// Security Center - Offline GeoIP lookup
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: MIT

//! Fully offline country lookup for remote IPs, backed by a MaxMind-format
//! database (e.g. DB-IP Lite Country, CC BY 4.0).
//!
//! No network calls are ever made — a security app must not leak the hosts a
//! user connects to by querying an online IP-geolocation service. If no local
//! database is present, lookups simply return `None` and the UI omits the flag.
//!
//! Database search order:
//!   1. `$SECURITY_CENTER_GEOIP_DB`
//!   2. common system paths (`/usr/share/GeoIP`, `/var/lib/GeoIP`, …)
//!      for `dbip-country-lite.mmdb`, `GeoLite2-Country.mmdb`, or `country.mmdb`.

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use maxminddb::{geoip2, Reader};

/// A loaded GeoIP database (or a no-op when none is available).
pub struct GeoIp {
    reader: Option<Reader<Vec<u8>>>,
}

impl GeoIp {
    /// Load the first database found in the standard locations.
    pub fn load() -> Self {
        Self {
            reader: find_database().and_then(|path| match Reader::open_readfile(&path) {
                Ok(r) => {
                    tracing::info!("Loaded GeoIP database: {}", path.display());
                    Some(r)
                }
                Err(e) => {
                    tracing::warn!("Failed to open GeoIP database {}: {}", path.display(), e);
                    None
                }
            }),
        }
    }

    /// Whether a database is loaded and lookups can return results.
    #[allow(dead_code)] // public API; used by tests and future UI hints
    pub fn is_available(&self) -> bool {
        self.reader.is_some()
    }

    /// Look up the ISO 3166-1 alpha-2 country code for an address.
    pub fn country_iso(&self, addr: IpAddr) -> Option<String> {
        let reader = self.reader.as_ref()?;
        // Private/loopback ranges are never in the DB — skip the lookup.
        if is_private(&addr) {
            return None;
        }
        let country: geoip2::Country = reader.lookup(addr).ok()?;
        country
            .country
            .and_then(|c| c.iso_code)
            .map(|s| s.to_uppercase())
    }

    /// Look up a display label: "🇩🇪 DE" when the database resolves a country,
    /// otherwise `None`.
    pub fn country_label(&self, addr: IpAddr) -> Option<String> {
        let iso = self.country_iso(addr)?;
        Some(format!("{} {}", flag_emoji(&iso), iso))
    }
}

/// Convert a 2-letter ISO country code into its Unicode flag emoji.
/// Returns an empty string for anything that is not two ASCII letters.
pub fn flag_emoji(iso: &str) -> String {
    let iso = iso.trim();
    if iso.len() != 2 || !iso.chars().all(|c| c.is_ascii_alphabetic()) {
        return String::new();
    }
    // Each letter maps to a Regional Indicator Symbol (U+1F1E6..U+1F1FF).
    iso.to_ascii_uppercase()
        .chars()
        .filter_map(|c| char::from_u32(0x1F1E6 + (c as u32 - 'A' as u32)))
        .collect()
}

/// Reserved / non-routable ranges that never have a GeoIP entry.
fn is_private(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified()
        }
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
    }
}

/// Find a MaxMind-format database in known locations.
fn find_database() -> Option<PathBuf> {
    if let Ok(explicit) = std::env::var("SECURITY_CENTER_GEOIP_DB") {
        let p = PathBuf::from(explicit);
        if p.is_file() {
            return Some(p);
        }
    }

    const DIRS: [&str; 4] = [
        "/usr/share/GeoIP",
        "/var/lib/GeoIP",
        "/usr/share/dbip",
        "/usr/local/share/GeoIP",
    ];
    const NAMES: [&str; 3] = [
        "dbip-country-lite.mmdb",
        "GeoLite2-Country.mmdb",
        "country.mmdb",
    ];

    for dir in DIRS {
        for name in NAMES {
            let candidate = Path::new(dir).join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_flag_emoji() {
        assert_eq!(flag_emoji("DE"), "🇩🇪");
        assert_eq!(flag_emoji("us"), "🇺🇸"); // case-insensitive
        assert_eq!(flag_emoji("GR"), "🇬🇷");
    }

    #[test]
    fn test_flag_emoji_invalid() {
        assert_eq!(flag_emoji(""), "");
        assert_eq!(flag_emoji("USA"), "");
        assert_eq!(flag_emoji("1A"), "");
        assert_eq!(flag_emoji("D"), "");
    }

    #[test]
    fn test_private_addresses_skipped() {
        // With no database loaded, lookups are always None and never panic.
        let geo = GeoIp { reader: None };
        assert_eq!(
            geo.country_iso(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            None
        );
        assert_eq!(geo.country_iso(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))), None);
        assert!(!geo.is_available());
    }

    #[test]
    fn test_is_private() {
        assert!(is_private(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(is_private(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(!is_private(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }
}
