// GNOME Firewall - Port Model
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: GPL-3.0-or-later

//! Firewall port model.

/// A firewall port rule.
#[derive(Debug, Clone, Default)]
pub struct Port {
    pub number: u16,
    pub protocol: String,
    pub zone: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub direction: String,
    pub action: String,
    pub is_permanent: bool,
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

    /// Get the display string for the port.
    pub fn display_string(&self) -> String {
        if let Some(name) = &self.name {
            format!("{} ({}/{})", name, self.number, self.protocol)
        } else {
            format!("{}/{}", self.number, self.protocol)
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

    /// Parse a port string like "8080/tcp".
    pub fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split('/').collect();
        if parts.len() == 2 {
            if let Ok(number) = parts[0].parse() {
                return Some(Self::new(number, parts[1]));
            }
        }
        None
    }

    /// Parse a port string with zone like "8080/tcp" from zone "public".
    /// Also handles port ranges like "1025-65535/tcp" by taking the start of range.
    pub fn parse_with_zone(s: &str, zone: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split('/').collect();
        if parts.len() == 2 {
            let port_part = parts[0];
            let proto = parts[1];
            
            // Check if it's a range like "1025-65535"
            if port_part.contains('-') {
                // It's a range - skip it for now (system default ports)
                // Or take the start of the range
                let range_parts: Vec<&str> = port_part.split('-').collect();
                if range_parts.len() == 2 {
                    // Skip large ranges (system defaults like 1025-65535)
                    if let (Ok(start), Ok(end)) = (range_parts[0].parse::<u16>(), range_parts[1].parse::<u16>()) {
                        if end - start > 100 {
                            // Skip large ranges
                            return None;
                        }
                        // For small ranges, create entry for start port
                        return Some(Self::with_zone(start, proto, zone));
                    }
                }
                return None;
            }
            
            if let Ok(number) = port_part.parse() {
                return Some(Self::with_zone(number, proto, zone));
            }
        }
        None
    }

    /// Parse a blocked port from a rich rule string.
    /// Example: `rule family="ipv4" port port="80" protocol="tcp" reject`
    /// Returns Some(Port) if this is a port reject/drop rule, None otherwise.
    pub fn parse_from_rich_rule(rule: &str, zone: &str) -> Option<Self> {
        // Check if this is a port reject or drop rule
        if !rule.contains("port port=") || (!rule.contains("reject") && !rule.contains("drop")) {
            return None;
        }

        // Extract port number: port="80" or port="443"
        let port_start = rule.find("port port=\"")?;
        let port_value_start = port_start + 11; // length of 'port port="'
        let remaining = &rule[port_value_start..];
        let port_end = remaining.find('"')?;
        let port_str = &remaining[..port_end];
        let port_number: u16 = port_str.parse().ok()?;

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
            number: port_number,
            protocol: protocol.to_string(),
            zone: Some(zone.to_string()),
            name: None,
            description: Some(format!("Blocked via rich rule ({})", action)),
            direction: "in".to_string(),
            action: action.to_string(),
            is_permanent: true,
        })
    }
}
