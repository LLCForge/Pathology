//! Bounds-checked big-endian reader shared by the BMP and BGP parsers.

/// The buffer ended before the named field could be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Truncated(pub &'static str);

pub struct Cursor<'a> {
    buf: &'a [u8],
}

impl<'a> Cursor<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8], Truncated> {
        if self.buf.len() < n {
            return Err(Truncated(what));
        }
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        Ok(head)
    }

    /// Everything that is left, without consuming it.
    pub fn peek_rest(&self) -> &'a [u8] {
        self.buf
    }

    pub fn peek_u8(&self) -> Option<u8> {
        self.buf.first().copied()
    }

    pub fn u8(&mut self, what: &'static str) -> Result<u8, Truncated> {
        Ok(self.take(1, what)?[0])
    }

    pub fn u16(&mut self, what: &'static str) -> Result<u16, Truncated> {
        let b = self.take(2, what)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    pub fn u32(&mut self, what: &'static str) -> Result<u32, Truncated> {
        let b = self.take(4, what)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Consumes and returns everything that is left.
    pub fn rest(&mut self) -> &'a [u8] {
        std::mem::take(&mut self.buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_and_reports_truncation() {
        let mut c = Cursor::new(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        assert_eq!(c.u8("a"), Ok(1));
        assert_eq!(c.u16("b"), Ok(0x0203));
        assert_eq!(c.u32("c"), Err(Truncated("c")));
        assert_eq!(c.rest(), &[0x04, 0x05, 0x06]);
        assert!(c.is_empty());
        assert_eq!(c.u8("d"), Err(Truncated("d")));
    }
}
