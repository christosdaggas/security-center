// Security Center - Online IP intelligence
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: MIT

//! On-demand online lookup of rich details for a single remote IP address
//! (country, region, city, ISP, organisation, ASN, reverse hostname, and
//! proxy/hosting/mobile flags).
//!
//! Unlike the always-on offline [`crate::admin::GeoIp`] country lookup, this
//! module *does* make a network request — but only when the user explicitly
//! asks for it from the IP details window. Nothing here runs passively.
//!
//! Two free, key-less providers are tried in order, preferring the encrypted
//! one first so a security tool never sends the queried IP in the clear unless
//! the HTTPS provider is unavailable:
//!   1. `https://ipwho.is/{ip}`        — HTTPS, ISP/org/ASN/city (1000/day)
//!   2. `http://ip-api.com/json/{ip}`  — HTTP, adds reverse DNS + threat flags

use std::net::IpAddr;
use std::time::Duration;

use anyhow::{anyhow, Result};
use serde_json::Value;

/// Rich, best-effort details about a remote IP. Every field is optional: a
/// provider may not return it, and the two providers expose different subsets.
#[derive(Debug, Clone, Default)]
pub struct IpDetails {
    /// Which provider answered ("ipwho.is" or "ip-api.com").
    pub source: String,
    pub country: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub timezone: Option<String>,
    pub isp: Option<String>,
    pub org: Option<String>,
    /// Autonomous System number, formatted like "AS15169".
    pub asn: Option<String>,
    /// Organisation that owns the AS (may differ from the ISP).
    pub asn_org: Option<String>,
    /// Reverse-DNS hostname of the IP, when the provider resolves one.
    pub reverse_hostname: Option<String>,
    pub is_proxy: Option<bool>,
    pub is_hosting: Option<bool>,
    pub is_mobile: Option<bool>,
    pub flag_emoji: Option<String>,
}

/// Look up rich details for `ip` online, trying the HTTPS provider first and
/// falling back to the HTTP one. Blocking — call it from a worker thread.
///
/// Returns an error for private/reserved addresses (never in any GeoIP dataset)
/// and when both providers fail or are unreachable.
pub fn lookup_ip_online(ip: IpAddr) -> Result<IpDetails> {
    if crate::admin::is_local_ip(ip) || is_reserved(ip) {
        return Err(anyhow!("This is a private or reserved address"));
    }

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(8))
        .user_agent(format!("security-center/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| anyhow!("failed to build HTTP client: {}", e))?;

    // Prefer the encrypted provider; fall back to the richer HTTP one.
    match lookup_ipwhois(&client, ip) {
        Ok(details) => return Ok(details),
        Err(e) => tracing::debug!("ipwho.is lookup failed for {}: {}", ip, e),
    }
    lookup_ipapi(&client, ip).map_err(|e| {
        tracing::debug!("ip-api.com lookup failed for {}: {}", ip, e);
        anyhow!("online lookup failed: {}", e)
    })
}

/// Query `https://ipwho.is/{ip}` (HTTPS, ISP/org/ASN/city).
fn lookup_ipwhois(client: &reqwest::blocking::Client, ip: IpAddr) -> Result<IpDetails> {
    let url = format!("https://ipwho.is/{ip}");
    let json: Value = get_json(client, &url)?;

    // A failed lookup carries `success: false` plus a `message`.
    if json.get("success").and_then(Value::as_bool) == Some(false) {
        let msg = str_field(&json, "message").unwrap_or_else(|| "lookup failed".to_string());
        return Err(anyhow!("ipwho.is: {}", msg));
    }

    let connection = json.get("connection");
    let asn = connection
        .and_then(|c| c.get("asn"))
        .and_then(Value::as_u64)
        .map(|n| format!("AS{n}"));

    Ok(IpDetails {
        source: "ipwho.is".to_string(),
        country: str_field(&json, "country"),
        region: str_field(&json, "region"),
        city: str_field(&json, "city"),
        latitude: json.get("latitude").and_then(Value::as_f64),
        longitude: json.get("longitude").and_then(Value::as_f64),
        timezone: json
            .get("timezone")
            .and_then(|t| str_field(t, "id")),
        isp: connection.and_then(|c| str_field(c, "isp")),
        org: connection.and_then(|c| str_field(c, "org")),
        asn,
        asn_org: connection.and_then(|c| str_field(c, "org")),
        reverse_hostname: None,
        is_proxy: None,
        is_hosting: None,
        is_mobile: None,
        flag_emoji: json.get("flag").and_then(|f| str_field(f, "emoji")),
    })
}

/// Query `http://ip-api.com/json/{ip}` (HTTP, adds reverse DNS + threat flags).
fn lookup_ipapi(client: &reqwest::blocking::Client, ip: IpAddr) -> Result<IpDetails> {
    // Explicit field mask keeps the response small and stable.
    let url = format!(
        "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,\
         region,regionName,city,lat,lon,timezone,isp,org,as,asname,reverse,\
         mobile,proxy,hosting,query"
    );
    let json: Value = get_json(client, &url)?;

    if str_field(&json, "status").as_deref() != Some("success") {
        let msg = str_field(&json, "message").unwrap_or_else(|| "lookup failed".to_string());
        return Err(anyhow!("ip-api.com: {}", msg));
    }

    Ok(IpDetails {
        source: "ip-api.com".to_string(),
        country: str_field(&json, "country"),
        region: str_field(&json, "regionName"),
        city: str_field(&json, "city"),
        latitude: json.get("lat").and_then(Value::as_f64),
        longitude: json.get("lon").and_then(Value::as_f64),
        timezone: str_field(&json, "timezone"),
        isp: str_field(&json, "isp"),
        org: str_field(&json, "org"),
        asn: str_field(&json, "as"),
        asn_org: str_field(&json, "asname"),
        reverse_hostname: str_field(&json, "reverse"),
        is_proxy: json.get("proxy").and_then(Value::as_bool),
        is_hosting: json.get("hosting").and_then(Value::as_bool),
        is_mobile: json.get("mobile").and_then(Value::as_bool),
        flag_emoji: None,
    })
}

/// GET a URL and parse the body as JSON, mapping transport/HTTP errors.
fn get_json(client: &reqwest::blocking::Client, url: &str) -> Result<Value> {
    let response = client
        .get(url)
        .send()
        .map_err(|e| anyhow!("request failed: {}", e))?;
    if !response.status().is_success() {
        return Err(anyhow!("HTTP {}", response.status()));
    }
    response
        .json::<Value>()
        .map_err(|e| anyhow!("invalid JSON: {}", e))
}

/// Read an object field as a trimmed, non-empty string.
fn str_field(v: &Value, key: &str) -> Option<String> {
    v.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Reserved / non-routable ranges no geolocation provider can resolve.
///
/// The IPv6 unique-local and link-local checks are done by hand because
/// `Ipv6Addr::is_unique_local`/`is_unicast_link_local` are still unstable.
fn is_reserved(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.is_private() || v4.is_link_local() || v4.is_multicast(),
        IpAddr::V6(v6) => {
            if v6.is_multicast() {
                return true;
            }
            let first = v6.segments()[0];
            // fc00::/7 unique-local, or fe80::/10 link-local.
            (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipwhois_maps_fields() {
        let json: Value = serde_json::from_str(
            r#"{"ip":"8.8.8.8","success":true,"country":"United States",
                "country_code":"US","region":"California","city":"Mountain View",
                "latitude":37.386,"longitude":-122.083,
                "connection":{"asn":15169,"org":"Google LLC","isp":"Google LLC"},
                "timezone":{"id":"America/Los_Angeles"},"flag":{"emoji":"🇺🇸"}}"#,
        )
        .unwrap();
        // Exercise the mapping without hitting the network.
        let connection = json.get("connection");
        let asn = connection
            .and_then(|c| c.get("asn"))
            .and_then(Value::as_u64)
            .map(|n| format!("AS{n}"));
        assert_eq!(asn.as_deref(), Some("AS15169"));
        assert_eq!(str_field(&json, "city").as_deref(), Some("Mountain View"));
        assert_eq!(
            connection.and_then(|c| str_field(c, "isp")).as_deref(),
            Some("Google LLC")
        );
        assert_eq!(
            json.get("flag").and_then(|f| str_field(f, "emoji")).as_deref(),
            Some("🇺🇸")
        );
    }

    #[test]
    fn ipapi_failure_detected() {
        let json: Value =
            serde_json::from_str(r#"{"status":"fail","message":"private range"}"#).unwrap();
        assert_ne!(str_field(&json, "status").as_deref(), Some("success"));
    }

    #[test]
    fn reserved_ranges_rejected() {
        assert!(is_reserved("192.168.1.1".parse().unwrap()));
        assert!(!is_reserved("8.8.8.8".parse().unwrap()));
    }

    // Hits the real providers; excluded from the normal suite / CI.
    // Run with: cargo test live_lookup_public_ip -- --ignored --nocapture
    #[test]
    #[ignore = "requires network access"]
    fn live_lookup_public_ip() {
        let d = lookup_ip_online("8.8.8.8".parse().unwrap()).expect("lookup should succeed");
        eprintln!(
            "source={} country={:?} city={:?} isp={:?} org={:?} asn={:?}",
            d.source, d.country, d.city, d.isp, d.org, d.asn
        );
        assert!(d.country.is_some(), "expected a country");
        assert!(d.isp.is_some() || d.org.is_some(), "expected ISP or org");
    }
}
