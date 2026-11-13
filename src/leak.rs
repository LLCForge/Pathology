//! Route leak detection (RFC 7908) with the valley-free rule over a CAIDA
//! AS relationship file (`as-rel` / `as-rel2` format).
//!
//! Format, one link per line, `#` comments:
//! `<provider>|<customer>|-1` and `<peer>|<peer>|0` (as-rel2 adds `|<source>`).

use std::collections::HashSet;
use std::path::Path;

use anyhow::{bail, Context, Result};

/// Upper bound for the relationship file (the full CAIDA serial-2 set is ~15 MB).
pub const MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_LINKS: usize = 10_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Link {
    /// Customer to provider.
    Up,
    Peer,
    /// Provider to customer.
    Down,
}

#[derive(Debug, Default)]
pub struct AsRelationships {
    /// (provider, customer)
    p2c: HashSet<(u32, u32)>,
    /// (lower, higher)
    p2p: HashSet<(u32, u32)>,
}

/// A valley-free violation: `leaker` passed a route learned from a provider or
/// peer (`from`) on to another provider or peer (`to`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Leak {
    pub leaker: u32,
    pub from: u32,
    pub to: u32,
}

impl AsRelationships {
    pub fn load(path: &Path) -> Result<Self> {
        let size = std::fs::metadata(path)
            .with_context(|| format!("reading {}", path.display()))?
            .len();
        anyhow::ensure!(
            size <= MAX_FILE_BYTES,
            "{} is larger than {MAX_FILE_BYTES} bytes",
            path.display()
        );
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        Self::parse(&text).with_context(|| format!("parsing {}", path.display()))
    }

    pub fn parse(text: &str) -> Result<Self> {
        let mut r = Self::default();
        for (n, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut f = line.split('|');
            let (Some(a), Some(b), Some(rel)) = (f.next(), f.next(), f.next()) else {
                bail!("line {}: expected <as>|<as>|<-1|0>", n + 1);
            };
            let parse = |s: &str| {
                s.trim()
                    .parse::<u32>()
                    .with_context(|| format!("line {}: invalid ASN {s:?}", n + 1))
            };
            let (a, b) = (parse(a)?, parse(b)?);
            match rel.trim() {
                "-1" => r.p2c.insert((a, b)),
                "0" => r.p2p.insert((a.min(b), a.max(b))),
                other => bail!("line {}: unknown relationship {other:?}", n + 1),
            };
            anyhow::ensure!(r.len() <= MAX_LINKS, "more than {MAX_LINKS} links");
        }
        Ok(r)
    }

    pub fn len(&self) -> usize {
        self.p2c.len() + self.p2p.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Relationship of the link a route crosses from `from` to `to`.
    pub fn link(&self, from: u32, to: u32) -> Option<Link> {
        if self.p2c.contains(&(to, from)) {
            Some(Link::Up)
        } else if self.p2c.contains(&(from, to)) {
            Some(Link::Down)
        } else if self.p2p.contains(&(from.min(to), from.max(to))) {
            Some(Link::Peer)
        } else {
            None
        }
    }

    /// Checks `hops` (left = nearest to the collector, right = origin; prepends
    /// collapsed) against the valley-free rule: a route may go up any number of
    /// customer-to-provider links, cross at most one peer link, then only go
    /// down. Links with unknown relationships are skipped.
    pub fn valley_free_violation(&self, hops: &[u32]) -> Option<Leak> {
        let mut descending = false;
        let mut prev_link_from = None;
        for i in (1..hops.len()).rev() {
            let (from, to) = (hops[i], hops[i - 1]);
            let Some(link) = self.link(from, to) else {
                continue;
            };
            if descending && matches!(link, Link::Up | Link::Peer) {
                return Some(Leak {
                    leaker: from,
                    from: prev_link_from.unwrap_or(from),
                    to,
                });
            }
            if matches!(link, Link::Peer | Link::Down) {
                descending = true;
            }
            prev_link_from = Some(from);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REL: &str = "# CAIDA as-rel style test data\n\
        64500|64501|-1\n\
        64500|64502|-1\n\
        64510|64500|-1\n\
        64503|64500|0|bgp\n\
        64501|64496|-1\n";

    #[test]
    fn parses_and_classifies_links() {
        let r = AsRelationships::parse(REL).unwrap();
        assert_eq!(r.len(), 5);
        assert_eq!(r.link(64501, 64500), Some(Link::Up));
        assert_eq!(r.link(64500, 64501), Some(Link::Down));
        assert_eq!(r.link(64500, 64503), Some(Link::Peer));
        assert_eq!(r.link(64503, 64500), Some(Link::Peer));
        assert_eq!(r.link(1, 2), None);
        for bad in ["1|2", "1|x|0", "1|2|5"] {
            assert!(AsRelationships::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn valley_free() {
        let r = AsRelationships::parse(REL).unwrap();
        // 64502 (origin) -> provider 64500 -> provider 64510: all uphill.
        assert_eq!(r.valley_free_violation(&[64510, 64500, 64502]), None);
        // up, peer, down: fine.
        assert_eq!(r.valley_free_violation(&[64496, 64501, 64500, 64503]), None);
        // 64501 learns from its provider 64500 and gives it to its customer
        // 64496 (fine) ... but 64500 learning from provider 64510 and giving
        // to peer 64503 is a leak by 64500.
        let leak = r
            .valley_free_violation(&[64503, 64500, 64510])
            .expect("leak");
        assert_eq!(leak.leaker, 64500);
        assert_eq!(leak.to, 64503);
        assert_eq!(leak.from, 64510);
        // Unknown links are ignored.
        assert_eq!(r.valley_free_violation(&[1, 2, 3]), None);
        assert_eq!(r.valley_free_violation(&[]), None);
    }
}
