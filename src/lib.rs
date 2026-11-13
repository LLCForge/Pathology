//! Pathology: BGP route monitor for your own routers.
//!
//! BMP feeds ([`bmp`], [`collector`]) and passive BGP sessions
//! ([`bgp_listener`]) are parsed ([`bgp`]), compared against a learned
//! per-prefix [`baseline`] by the [`detector`], kept in a [`rib`] with a
//! route history served by the read-only [`api`], and findings are delivered
//! through llcforge-alert by [`alerts`].
#![forbid(unsafe_code)]

pub mod alerts;
pub mod api;
pub mod baseline;
pub mod bgp;
pub mod bgp_listener;
pub mod bmp;
pub mod collector;
pub mod config;
pub mod detector;
pub mod leak;
pub mod metrics;
pub mod mrt;
pub mod notary;
pub mod replay;
pub mod rib;
pub mod sessions;
mod wire;

#[cfg(test)]
mod testutil;
