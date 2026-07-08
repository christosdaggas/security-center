// Security Center - Port Model
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: MIT

//! Firewall port model.

use crate::validation::{format_port_spec, parse_port_spec};

/// A firewall port rule covering a single port or an inclusive range.
#[derive(Debug, Clone, Default)]
pub struct Port {
    /// The port number (start of range for range rules).
    pub number: u16,
    /// End of the range (inclusive); `None` for a single port.
    pub end_number: Option<u16>,
    pub protocol: String,
    pub zone: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub direction: String,
    pub action: String,
    pub is_permanent: bool,
    /// The exact rich-rule string this port was parsed from, if any.
    /// Kept so blocked ports can be removed by their real rule text instead
    /// of a reconstructed guess (which may differ in family or verb).
    pub raw_rule: Option<String>,
}

impl Port {
    /// Create a new port.
    pub fn new(number: u16, protocol: &str) -> Self {
        Self {
            number,
            protocol: protocol.to_string(),
            direction: "in".to_string(),
            action: "accept".to_string(),
            ..Default::default()
        }
    }

    /// Create a port with zone info.
    pub fn with_zone(number: u16, protocol: &str, zone: &str) -> Self {
        Self {
            number,
            protocol: protocol.to_string(),
            zone: Some(zone.to_string()),
            direction: "in".to_string(),
            action: "accept".to_string(),
            ..Default::default()
        }
    }

    /// Create a port range with zone info. A degenerate range (end <= start)
    /// collapses to a single port.
    pub fn range_with_zone(start: u16, end: u16, protocol: &str, zone: &str) -> Self {
        let mut port = Self::with_zone(start, protocol, zone);
        if end > start {
            port.end_number = Some(end);
        }
        port
    }

    /// Whether this rule covers a range of ports.
    pub fn is_range(&self) -> bool {
        self.end_number.is_some_and(|end| end > self.number)
    }

    /// The firewalld port string: "8080" or "10-20".
    pub fn port_spec(&self) -> String {
        format_port_spec(self.number, self.end_number.unwrap_or(self.number))
    }

    /// Get the display string for the port.
    pub fn display_string(&self) -> String {
        if let Some(name) = &self.name {
            format!("{} ({}/{})", name, self.port_spec(), self.protocol)
        } else {
            format!("{}/{}", self.port_spec(), self.protocol)
        }
    }

    /// Get the well-known service name for this port.
    pub fn well_known_service(&self) -> Option<&'static str> {
        match (self.number, self.protocol.as_str()) {
            (22, "tcp") => Some("SSH"),
            (80, "tcp") => Some("HTTP"),
            (443, "tcp") => Some("HTTPS"),
            (21, "tcp") => Some("FTP"),
            (25, "tcp") => Some("SMTP"),
            (53, "tcp" | "udp") => Some("DNS"),
            (67 | 68, "udp") => Some("DHCP"),
            (110, "tcp") => Some("POP3"),
            (143, "tcp") => Some("IMAP"),
            (445, "tcp") => Some("SMB"),
            (3306, "tcp") => Some("MySQL"),
            (5432, "tcp") => Some("PostgreSQL"),
            (6379, "tcp") => Some("Redis"),
            (8080, "tcp") => Some("HTTP Alt"),
            _ => None,
        }
    }

    /// Parse a port string like "8080/tcp" or "10-20/tcp".
    pub fn parse(s: &str) -> Option<Self> {
        let (port_part, proto) = s.split_once('/')?;
        let (start, end) = parse_port_spec(port_part)?;
        let mut port = Self::new(start, proto);
        if end > start {
            port.end_number = Some(end);
        }
        Some(port)
    }

    /// Parse a port string with zone like "8080/tcp" or "10-20/tcp"
    /// from zone "public". Ranges are preserved as ranges.
    pub fn parse_with_zone(s: &str, zone: &str) -> Option<Self> {
        let (port_part, proto) = s.split_once('/')?;
        let (start, end) = parse_port_spec(port_part)?;
        Some(Self::range_with_zone(start, end, proto, zone))
    }

    /// Parse a blocked port from a rich rule string.
    /// Example: `rule family="ipv4" port port="80" protocol="tcp" reject`
    /// Port ranges like port="10-20" are also supported.
    /// Returns Some(Port) if this is a port reject/drop rule, None otherwise.
    pub fn parse_from_rich_rule(rule: &str, zone: &str) -> Option<Self> {
        // Check if this is a port reject or drop rule
        if !rule.contains("port port=") || (!rule.contains("reject") && !rule.contains("drop")) {
            return None;
        }

        // Extract port spec: port="80" or port="10-20"
        let port_start = rule.find("port port=\"")?;
        let port_value_start = port_start + 11; // length of 'port port="'
        let remaining = &rule[port_value_start..];
        let port_end = remaining.find('"')?;
        let port_str = &remaining[..port_end];
        let (range_start, range_end) = parse_port_spec(port_str)?;

        // Extract protocol: protocol="tcp" or protocol="udp"
        let proto_start = rule.find("protocol=\"")?;
        let proto_value_start = proto_start + 10; // length of 'protocol="'
        let remaining = &rule[proto_value_start..];
        let proto_end = remaining.find('"')?;
        let protocol = &remaining[..proto_end];

        // Determine the action (reject or drop)
        let action = if rule.contains("reject") {
            "reject"
        } else {
            "drop"
        };

        Some(Self {
            number: range_start,
            end_number: (range_end > range_start).then_some(range_end),
            protocol: protocol.to_string(),
            zone: Some(zone.to_string()),
            name: None,
            description: Some(format!("Blocked via rich rule ({})", action)),
            direction: "in".to_string(),
            action: action.to_string(),
            is_permanent: true,
            raw_rule: Some(rule.to_string()),
        })
    }
}
