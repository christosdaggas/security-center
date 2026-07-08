// Security Center - Offline GeoIP lookup
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: MIT

//! Fully offline country lookup for remote IPs, backed by a MaxMind-format
//! database (e.g. DB-IP Lite Country, CC BY 4.0).
//!
//! No network calls are ever made — a security app must not leak the hosts a
//! user connects to by querying an online IP-geolocation service. If no local
//! database is present, the app downloads the free DB-IP Lite Country database
//! once into the user's data directory, then all IP lookups stay offline.
//!
//! Database search order:
//!   1. `$SECURITY_CENTER_GEOIP_DB`
//!   2. user data directory (`~/.local/share/security-center/GeoIP`)
//!   3. common system paths (`/usr/share/GeoIP`, `/var/lib/GeoIP`, …)
//!      for `dbip-country-lite.mmdb`, `GeoLite2-Country.mmdb`, or `country.mmdb`.

use std::fs;
use std::io::{Read, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use maxminddb::{geoip2, Reader};

const DB_NAME: &str = "dbip-country-lite.mmdb";
const MAX_COMPRESSED_DB_SIZE: u64 = 64 * 1024 * 1024;
static DOWNLOAD_ATTEMPTED: AtomicBool = AtomicBool::new(false);

/// A loaded GeoIP database (or a no-op when none is available).
pub struct GeoIp {
    reader: Option<Reader<Vec<u8>>>,
}

impl GeoIp {
    /// Load the first database found, downloading DB-IP Lite on first use when
    /// no local database is already installed.
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
    #[allow(dead_code)] // public API; useful for tests and future filtering
    pub fn country_iso(&self, addr: IpAddr) -> Option<String> {
        self.country_details(addr).map(|(iso, _)| iso)
    }

    /// Look up a display label: "🇩🇪 Germany" when the database resolves a
    /// country, otherwise `None`.
    pub fn country_label(&self, addr: IpAddr) -> Option<String> {
        let (iso, name) = self.country_details(addr)?;
        Some(format!("{} {}", flag_emoji(&iso), name))
    }

    fn country_details(&self, addr: IpAddr) -> Option<(String, String)> {
        let reader = self.reader.as_ref()?;
        // Private/loopback ranges are never in the DB — skip the lookup.
        if is_private(&addr) {
            return None;
        }
        let country: geoip2::Country = reader.lookup(addr).ok()?.decode().ok()??;
        let iso = country.country.iso_code?.to_uppercase();
        let name = country
            .country
            .names
            .english
            .unwrap_or(iso.as_str())
            .to_string();
        Some((iso, name))
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

    if let Some(candidate) = user_database_path() {
        if candidate.is_file() {
            return Some(candidate);
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
    download_database_once()
}

fn user_database_path() -> Option<PathBuf> {
    dirs::data_dir().map(|base| base.join("security-center").join("GeoIP").join(DB_NAME))
}

fn download_database_once() -> Option<PathBuf> {
    if DOWNLOAD_ATTEMPTED.swap(true, Ordering::AcqRel) {
        return None;
    }

    match download_database() {
        Ok(path) => Some(path),
        Err(e) => {
            tracing::warn!("GeoIP database download failed: {}", e);
            None
        }
    }
}

fn download_database() -> Result<PathBuf, String> {
    let target =
        user_database_path().ok_or_else(|| "user data directory is unavailable".to_string())?;
    let parent = target
        .parent()
        .ok_or_else(|| "GeoIP database target has no parent directory".to_string())?;
    fs::create_dir_all(parent)
        .map_err(|e| format!("failed to create {}: {}", parent.display(), e))?;

    let year_month = chrono::Utc::now().format("%Y-%m");
    let url = format!("https://download.db-ip.com/free/dbip-country-lite-{year_month}.mmdb.gz");
    tracing::info!("Downloading GeoIP database: {}", url);

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent(format!("security-center/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| format!("failed to build HTTP client: {}", e))?;

    let response = client
        .get(&url)
        .send()
        .map_err(|e| format!("download request failed: {}", e))?;

    if !response.status().is_success() {
        return Err(format!("download returned HTTP {}", response.status()));
    }

    let mut compressed = Vec::new();
    response
        .take(MAX_COMPRESSED_DB_SIZE)
        .read_to_end(&mut compressed)
        .map_err(|e| format!("failed to read download: {}", e))?;
    if compressed.is_empty() {
        return Err("download was empty".to_string());
    }

    let mut decoder = flate2::read::GzDecoder::new(compressed.as_slice());
    let mut database = Vec::new();
    decoder
        .read_to_end(&mut database)
        .map_err(|e| format!("failed to decompress database: {}", e))?;
    if database.is_empty() {
        return Err("decompressed database was empty".to_string());
    }

    let tmp = target.with_file_name(format!("{DB_NAME}.tmp"));
    let mut file =
        fs::File::create(&tmp).map_err(|e| format!("failed to create {}: {}", tmp.display(), e))?;
    file.write_all(&database)
        .map_err(|e| format!("failed to write {}: {}", tmp.display(), e))?;
    file.sync_all()
        .map_err(|e| format!("failed to sync {}: {}", tmp.display(), e))?;

    Reader::open_readfile(&tmp)
        .map_err(|e| format!("downloaded database failed validation: {}", e))?;

    fs::rename(&tmp, &target).map_err(|e| {
        format!(
            "failed to move {} to {}: {}",
            tmp.display(),
            target.display(),
            e
        )
    })?;
    tracing::info!("Installed GeoIP database: {}", target.display());
    Ok(target)
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

    #[test]
    fn test_configured_database_resolves_public_ip() {
        if std::env::var("SECURITY_CENTER_GEOIP_DB").is_err() {
            return;
        }

        let geo = GeoIp::load();
        let label = geo.country_label(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(label
            .as_deref()
            .is_some_and(|l| l.contains("United States")));
    }
}
