// Security Center - Consolidated Port Model
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: MIT

//! A consolidated port groups the same port number across multiple zones and protocols.

use super::Port;
use crate::validation::format_port_spec;
use std::collections::HashMap;

/// A consolidated view of port rules, grouping the same port (or range)
/// across zones/protocols.
#[derive(Debug, Clone, Default)]
pub struct ConsolidatedPort {
    /// The port number (start of range for range rules).
    pub number: u16,
    /// End of the range (inclusive); `None` for a single port.
    pub end_number: Option<u16>,
    /// User-given name (if any).
    pub name: Option<String>,
    /// List of protocols (e.g., ["tcp"], ["udp"], or ["tcp", "udp"]).
    pub protocols: Vec<String>,
    /// List of zones this port rule applies to.
    pub zones: Vec<String>,
    /// Action: "accept" (open) or "deny"/"reject"/"drop" (blocked).
    pub action: String,
    /// Whether this is a permanent rule.
    pub is_permanent: bool,
    /// Exact rich-rule strings this consolidated entry was built from.
    /// Used to remove blocked rules by their real text rather than a guess.
    pub raw_rules: Vec<String>,
}

impl ConsolidatedPort {
    /// Create a new consolidated port from a single Port.
    pub fn from_port(port: &Port) -> Self {
        Self {
            number: port.number,
            end_number: port.end_number,
            name: port.name.clone(),
            protocols: vec![port.protocol.clone()],
            zones: port.zone.clone().map(|z| vec![z]).unwrap_or_default(),
            action: port.action.clone(),
            is_permanent: port.is_permanent,
            raw_rules: port.raw_rule.clone().into_iter().collect(),
        }
    }

    /// Whether this rule covers a range of ports.
    pub fn is_range(&self) -> bool {
        self.end_number.map_or(false, |end| end > self.number)
    }

    /// The firewalld port string: "8080" or "10-20".
    pub fn port_spec(&self) -> String {
        format_port_spec(self.number, self.end_number.unwrap_or(self.number))
    }

    /// Group a list of ports by port range and action, consolidating zones and protocols.
    pub fn consolidate(ports: &[Port]) -> Vec<ConsolidatedPort> {
        // Group by (port_range, action)
        // Key: (start, end, normalized_action)
        let mut map: HashMap<(u16, Option<u16>, String), ConsolidatedPort> = HashMap::new();

        for port in ports {
            // Normalize action: treat "reject", "drop", "deny" as blocked
            let normalized_action = if port.action == "reject" || port.action == "drop" || port.action == "deny" {
                "deny".to_string()
            } else {
                "accept".to_string()
            };

            let key = (port.number, port.end_number, normalized_action.clone());

            if let Some(existing) = map.get_mut(&key) {
                // Add protocol if not already present
                if !existing.protocols.contains(&port.protocol) {
                    existing.protocols.push(port.protocol.clone());
                }
                // Add zone if not already present
                if let Some(zone) = &port.zone {
                    if !existing.zones.contains(zone) {
                        existing.zones.push(zone.clone());
                    }
                }
                // Use name if we don't have one yet
                if existing.name.is_none() && port.name.is_some() {
                    existing.name = port.name.clone();
                }
                // Collect the exact rule text for later removal
                if let Some(rule) = &port.raw_rule {
                    if !existing.raw_rules.contains(rule) {
                        existing.raw_rules.push(rule.clone());
                    }
                }
            } else {
                // Create new consolidated entry
                let mut consolidated = ConsolidatedPort::from_port(port);
                consolidated.action = normalized_action;
                map.insert(key, consolidated);
            }
        }

        // Collect and sort by port number (ranges sort by their start)
        let mut result: Vec<ConsolidatedPort> = map.into_values().collect();
        result.sort_by_key(|p| (p.number, p.end_number));

        // Sort protocols and zones within each entry for consistent display
        for cp in &mut result {
            cp.protocols.sort();
            cp.zones.sort();
        }

        result
    }

    /// Get a display string for protocols (e.g., "TCP", "UDP", "TCP/UDP").
    pub fn protocol_display(&self) -> String {
        if self.protocols.len() == 2 {
            "TCP/UDP".to_string()
        } else if let Some(proto) = self.protocols.first() {
            proto.to_uppercase()
        } else {
            "?".to_string()
        }
    }

    /// Get display title (name, well-known service, or port number/range).
    pub fn display_title(&self) -> String {
        if let Some(name) = &self.name {
            format!("{} ({})", name, self.port_spec())
        } else if self.is_range() {
            format!("Ports {}", self.port_spec())
        } else if let Some(service) = self.well_known_service() {
            format!("{} ({})", service, self.number)
        } else {
            format!("Port {}", self.number)
        }
    }

    /// Check if this is a blocked (deny) rule.
    pub fn is_blocked(&self) -> bool {
        self.action == "deny" || self.action == "reject" || self.action == "drop"
    }

    /// Get well-known service name for common ports.
    pub fn well_known_service(&self) -> Option<&'static str> {
        // Ranges never map to a single well-known service
        if self.is_range() {
            return None;
        }
        // Only return for TCP or if both protocols
        let has_tcp = self.protocols.contains(&"tcp".to_string());
        match self.number {
            22 if has_tcp => Some("SSH"),
            80 if has_tcp => Some("HTTP"),
            443 if has_tcp => Some("HTTPS"),
            21 if has_tcp => Some("FTP"),
            25 if has_tcp => Some("SMTP"),
            53 => Some("DNS"),
            110 if has_tcp => Some("POP3"),
            143 if has_tcp => Some("IMAP"),
            445 if has_tcp => Some("SMB"),
            3306 if has_tcp => Some("MySQL"),
            5432 if has_tcp => Some("PostgreSQL"),
            6379 if has_tcp => Some("Redis"),
            8080 if has_tcp => Some("HTTP Alt"),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_consolidate_same_port_multiple_zones() {
        let ports = vec![
            Port::with_zone(80, "tcp", "public"),
            Port::with_zone(80, "tcp", "home"),
            Port::with_zone(80, "tcp", "work"),
        ];

        let consolidated = ConsolidatedPort::consolidate(&ports);
        assert_eq!(consolidated.len(), 1);
        assert_eq!(consolidated[0].number, 80);
        assert_eq!(consolidated[0].zones.len(), 3);
        assert_eq!(consolidated[0].protocols, vec!["tcp"]);
    }

    #[test]
    fn test_consolidate_tcp_and_udp() {
        let ports = vec![
            Port::with_zone(53, "tcp", "public"),
            Port::with_zone(53, "udp", "public"),
        ];

        let consolidated = ConsolidatedPort::consolidate(&ports);
        assert_eq!(consolidated.len(), 1);
        assert_eq!(consolidated[0].protocols.len(), 2);
        assert_eq!(consolidated[0].protocol_display(), "TCP/UDP");
    }

    #[test]
    fn test_consolidate_ranges() {
        let ports = vec![
            Port::range_with_zone(10, 20, "tcp", "public"),
            Port::range_with_zone(10, 20, "tcp", "home"),
            // Same start but a single port — must stay a separate entry
            Port::with_zone(10, "tcp", "public"),
        ];

        let consolidated = ConsolidatedPort::consolidate(&ports);
        assert_eq!(consolidated.len(), 2);

        let single = consolidated.iter().find(|p| !p.is_range()).unwrap();
        let range = consolidated.iter().find(|p| p.is_range()).unwrap();
        assert_eq!(single.port_spec(), "10");
        assert_eq!(range.port_spec(), "10-20");
        assert_eq!(range.zones.len(), 2);
        assert_eq!(range.display_title(), "Ports 10-20");
        // A well-known port number at the start of a range must not
        // be labeled as that service
        let ssh_range = ConsolidatedPort::from_port(&Port::range_with_zone(22, 30, "tcp", "public"));
        assert_eq!(ssh_range.well_known_service(), None);
    }

    #[test]
    fn test_separate_allowed_and_blocked() {
        let mut allow_port = Port::with_zone(80, "tcp", "public");
        allow_port.action = "accept".to_string();

        let mut deny_port = Port::with_zone(80, "tcp", "dmz");
        deny_port.action = "deny".to_string();

        let ports = vec![allow_port, deny_port];
        let consolidated = ConsolidatedPort::consolidate(&ports);

        // Should create 2 separate entries (one allowed, one denied)
        assert_eq!(consolidated.len(), 2);
    }
}
