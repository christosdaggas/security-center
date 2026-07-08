// Security Center - Input Validation
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: MIT

//! Centralized input validation for firewall-related strings and user input.

use anyhow::{anyhow, Result};

/// Validate a protocol string.
/// Returns `Some(&str)` for allowed protocols, `None` otherwise.
pub fn validate_protocol(s: &str) -> Option<&str> {
    match s {
        "tcp" | "udp" => Some(s),
        _ => None,
    }
}

/// Parse and validate a port specification: a single port ("8080") or an
/// inclusive range ("10-20"). Returns `(start, end)` where `end == start`
/// for a single port. Whitespace around the numbers is tolerated.
pub fn parse_port_spec(s: &str) -> Option<(u16, u16)> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some((start_str, end_str)) = trimmed.split_once('-') {
        let start: u16 = start_str.trim().parse().ok()?;
        let end: u16 = end_str.trim().parse().ok()?;
        if start >= 1 && end >= start {
            Some((start, end))
        } else {
            None
        }
    } else {
        let port: u16 = trimmed.parse().ok()?;
        if port >= 1 {
            Some((port, port))
        } else {
            None
        }
    }
}

/// Format a validated `(start, end)` pair as a firewalld port string
/// ("8080" or "10-20").
pub fn format_port_spec(start: u16, end: u16) -> String {
    if end > start {
        format!("{}-{}", start, end)
    } else {
        start.to_string()
    }
}

/// Validate and sanitize a user-provided port name.
/// Returns `Some(String)` if valid, `None` otherwise.
pub fn validate_port_name(name: &str) -> Option<String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Some(String::new());
    }
    if trimmed.len() > 64 {
        return None;
    }
    if trimmed
        .chars()
        .all(|c| c.is_alphanumeric() || c == ' ' || c == '-' || c == '_' || c == '.')
    {
        Some(trimmed.to_string())
    } else {
        None
    }
}

/// Validate a systemctl action.
pub fn validate_systemctl_action(action: &str) -> Result<()> {
    const ALLOWED: &[&str] = &[
        "start",
        "stop",
        "restart",
        "enable",
        "disable",
        "daemon-reload",
    ];
    if ALLOWED.contains(&action) {
        Ok(())
    } else {
        Err(anyhow!("Invalid systemctl action: {}", action))
    }
}

/// Validate a service/unit name for systemctl.
pub fn validate_service_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Ok(());
    }
    // Must end with a known unit suffix
    let has_valid_suffix = name.ends_with(".service")
        || name.ends_with(".socket")
        || name.ends_with(".target")
        || name.ends_with(".timer");
    if !has_valid_suffix {
        return Err(anyhow!(
            "Invalid service name (must end with .service, .socket, .target, or .timer): {}",
            name
        ));
    }
    // Only allow safe characters
    if !name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '.' || c == '-' || c == '_')
    {
        return Err(anyhow!(
            "Service name contains invalid characters: {}",
            name
        ));
    }
    Ok(())
}

/// Validate a firewalld zone name by its real rules rather than a fixed list,
/// so custom zones (FedoraWorkstation, libvirt, libvirt-routed, nm-shared, …)
/// are accepted while injection attempts are rejected.
///
/// firewalld zone names are non-empty, at most 17 characters, and contain only
/// ASCII letters, digits, `-` and `_`.
pub fn validate_zone_name(name: &str) -> Option<&str> {
    if name.is_empty() || name.len() > 17 {
        return None;
    }
    if name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        Some(name)
    } else {
        None
    }
}

/// Validate a theme string.
pub fn validate_theme(theme: &str) -> Option<&str> {
    match theme {
        "system" | "light" | "dark" => Some(theme),
        _ => None,
    }
}

/// Clamp a window dimension to reasonable bounds.
pub fn clamp_window_dimension(value: i32) -> i32 {
    value.clamp(100, 10000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_protocol_valid() {
        assert_eq!(validate_protocol("tcp"), Some("tcp"));
        assert_eq!(validate_protocol("udp"), Some("udp"));
    }

    #[test]
    fn test_validate_protocol_invalid() {
        assert_eq!(validate_protocol("tcp\" reject"), None);
        assert_eq!(validate_protocol("\"; rm -rf /"), None);
        assert_eq!(validate_protocol("TCP"), None);
        assert_eq!(validate_protocol("Udp"), None);
        assert_eq!(validate_protocol(""), None);
        assert_eq!(validate_protocol("icmp"), None);
    }

    #[test]
    fn test_parse_port_spec_single() {
        assert_eq!(parse_port_spec("80"), Some((80, 80)));
        assert_eq!(parse_port_spec(" 8080 "), Some((8080, 8080)));
        assert_eq!(parse_port_spec("65535"), Some((65535, 65535)));
        assert_eq!(parse_port_spec("1"), Some((1, 1)));
    }

    #[test]
    fn test_parse_port_spec_range() {
        assert_eq!(parse_port_spec("10-20"), Some((10, 20)));
        assert_eq!(parse_port_spec("10 - 20"), Some((10, 20)));
        assert_eq!(parse_port_spec("1025-65535"), Some((1025, 65535)));
        // A degenerate range collapses to a single port
        assert_eq!(parse_port_spec("42-42"), Some((42, 42)));
    }

    #[test]
    fn test_parse_port_spec_invalid() {
        assert_eq!(parse_port_spec(""), None);
        assert_eq!(parse_port_spec("0"), None);
        assert_eq!(parse_port_spec("20-10"), None);
        assert_eq!(parse_port_spec("0-20"), None);
        assert_eq!(parse_port_spec("65536"), None);
        assert_eq!(parse_port_spec("10-65536"), None);
        assert_eq!(parse_port_spec("abc"), None);
        assert_eq!(parse_port_spec("10-20-30"), None);
        assert_eq!(parse_port_spec("10-"), None);
        assert_eq!(parse_port_spec("-20"), None);
        assert_eq!(parse_port_spec("80; rm -rf /"), None);
    }

    #[test]
    fn test_format_port_spec() {
        assert_eq!(format_port_spec(80, 80), "80");
        assert_eq!(format_port_spec(10, 20), "10-20");
    }

    #[test]
    fn test_validate_port_name_valid() {
        assert_eq!(validate_port_name("HTTP"), Some("HTTP".to_string()));
        assert_eq!(
            validate_port_name("My Service"),
            Some("My Service".to_string())
        );
        assert_eq!(
            validate_port_name("web-server"),
            Some("web-server".to_string())
        );
        assert_eq!(validate_port_name("  spaced  "), Some("spaced".to_string()));
        assert_eq!(validate_port_name(""), Some("".to_string()));
    }

    #[test]
    fn test_validate_port_name_invalid() {
        assert_eq!(validate_port_name(&"a".repeat(65)), None);
        assert_eq!(validate_port_name("name\nwith\nnewlines"), None);
        assert_eq!(validate_port_name("name<script>"), None);
        assert_eq!(validate_port_name("../../etc/passwd"), None);
    }

    #[test]
    fn test_validate_systemctl_action_valid() {
        assert!(validate_systemctl_action("start").is_ok());
        assert!(validate_systemctl_action("stop").is_ok());
        assert!(validate_systemctl_action("restart").is_ok());
        assert!(validate_systemctl_action("enable").is_ok());
        assert!(validate_systemctl_action("disable").is_ok());
        assert!(validate_systemctl_action("daemon-reload").is_ok());
    }

    #[test]
    fn test_validate_systemctl_action_invalid() {
        assert!(validate_systemctl_action("; rm -rf /").is_err());
        assert!(validate_systemctl_action("../../bin/sh").is_err());
        assert!(validate_systemctl_action("").is_err());
        assert!(validate_systemctl_action("start; cat /etc/shadow").is_err());
    }

    #[test]
    fn test_validate_service_name_valid() {
        assert!(validate_service_name("nginx.service").is_ok());
        assert!(validate_service_name("dbus.socket").is_ok());
        assert!(validate_service_name("multi-user.target").is_ok());
        assert!(validate_service_name("").is_ok());
    }

    #[test]
    fn test_validate_service_name_invalid() {
        assert!(validate_service_name("nginx; cat /etc/shadow").is_err());
        assert!(validate_service_name("../../etc/cron.d/backdoor").is_err());
        assert!(validate_service_name("invalid").is_err());
    }

    #[test]
    fn test_validate_zone_name_valid() {
        assert_eq!(validate_zone_name("public"), Some("public"));
        assert_eq!(validate_zone_name("home"), Some("home"));
        // Custom / distro zones must be accepted
        assert_eq!(
            validate_zone_name("FedoraWorkstation"),
            Some("FedoraWorkstation")
        );
        assert_eq!(validate_zone_name("libvirt-routed"), Some("libvirt-routed"));
        assert_eq!(validate_zone_name("nm-shared"), Some("nm-shared"));
    }

    #[test]
    fn test_validate_zone_name_invalid() {
        assert_eq!(validate_zone_name("public\"); drop"), None);
        assert_eq!(validate_zone_name("../../etc"), None);
        assert_eq!(validate_zone_name(""), None);
        assert_eq!(validate_zone_name("zone with spaces"), None);
        // Over the 17-char firewalld limit
        assert_eq!(validate_zone_name("thisnameiswaytoolongforzone"), None);
    }

    #[test]
    fn test_validate_theme() {
        assert_eq!(validate_theme("system"), Some("system"));
        assert_eq!(validate_theme("light"), Some("light"));
        assert_eq!(validate_theme("dark"), Some("dark"));
        assert_eq!(validate_theme("hacked"), None);
    }

    #[test]
    fn test_clamp_window_dimension() {
        assert_eq!(clamp_window_dimension(50), 100);
        assert_eq!(clamp_window_dimension(500), 500);
        assert_eq!(clamp_window_dimension(20000), 10000);
    }
}
