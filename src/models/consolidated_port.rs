// Security Center - Consolidated Port Model
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: MIT

//! A consolidated port groups the same port number across multiple zones and protocols.

use super::Port;
use std::collections::HashMap;

/// A consolidated view of port rules, grouping the same port across zones/protocols.
#[derive(Debug, Clone, Default)]
pub struct ConsolidatedPort {
    /// The port number.
    pub number: u16,
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
}

impl ConsolidatedPort {
    /// Create a new consolidated port from a single Port.
    pub fn from_port(port: &Port) -> Self {
        Self {
            number: port.number,
            name: port.name.clone(),
            protocols: vec![port.protocol.clone()],
            zones: port.zone.clone().map(|z| vec![z]).unwrap_or_default(),
            action: port.action.clone(),
            is_permanent: port.is_permanent,
        }
    }

    /// Group a list of ports by port number and action, consolidating zones and protocols.
    pub fn consolidate(ports: &[Port]) -> Vec<ConsolidatedPort> {
        // Group by (port_number, action)
        // Key: (port_number, normalized_action)
        let mut map: HashMap<(u16, String), ConsolidatedPort> = HashMap::new();

        for port in ports {
            // Normalize action: treat "reject", "drop", "deny" as blocked
            let normalized_action = if port.action == "reject" || port.action == "drop" || port.action == "deny" {
                "deny".to_string()
            } else {
                "accept".to_string()
            };

            let key = (port.number, normalized_action.clone());

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
            } else {
                // Create new consolidated entry
                let mut consolidated = ConsolidatedPort::from_port(port);
                consolidated.action = normalized_action;
                map.insert(key, consolidated);
            }
        }

        // Collect and sort by port number
        let mut result: Vec<ConsolidatedPort> = map.into_values().collect();
        result.sort_by_key(|p| p.number);

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

    /// Get display title (name or port number).
    pub fn display_title(&self) -> String {
        if let Some(name) = &self.name {
            format!("{} ({})", name, self.number)
        } else {
            // Try well-known service
            if let Some(service) = self.well_known_service() {
                format!("{} ({})", service, self.number)
            } else {
                format!("Port {}", self.number)
            }
        }
    }

    /// Check if this is a blocked (deny) rule.
    pub fn is_blocked(&self) -> bool {
        self.action == "deny" || self.action == "reject" || self.action == "drop"
    }

    /// Get well-known service name for common ports.
    pub fn well_known_service(&self) -> Option<&'static str> {
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
