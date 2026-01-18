// Security Center - Zone Model
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: MIT

//! Firewall zone model.

/// A firewall zone.
#[derive(Debug, Clone, Default)]
pub struct Zone {
    pub name: String,
    pub description: String,
    pub target: String,
    pub is_active: bool,
    pub is_default: bool,
    pub services: Vec<String>,
    pub ports: Vec<String>,
    pub interfaces: Vec<String>,
    pub sources: Vec<String>,
    pub rich_rules: Vec<String>,
    pub masquerade: bool,
    pub forward: bool,
}

impl Zone {
    /// Create a new zone.
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            ..Default::default()
        }
    }

    /// Get the trust level of the zone (for sorting/display).
    pub fn trust_level(&self) -> i32 {
        match self.name.as_str() {
            "drop" => 0,
            "block" => 1,
            "public" => 2,
            "external" => 3,
            "dmz" => 4,
            "work" => 5,
            "home" => 6,
            "internal" => 7,
            "trusted" => 8,
            _ => 5,
        }
    }

    /// Get a human-readable description of the zone's purpose.
    pub fn purpose(&self) -> &'static str {
        match self.name.as_str() {
            "drop" => "Drops all incoming connections silently",
            "block" => "Rejects incoming connections with ICMP messages",
            "public" => "For use in public areas, only selected services allowed",
            "external" => "For external networks with masquerading",
            "dmz" => "Demilitarized zone for publicly accessible services",
            "work" => "For work environment, trusts most computers",
            "home" => "For home use, trusts other computers",
            "internal" => "For internal networks, high trust level",
            "trusted" => "All connections are accepted",
            _ => "Custom zone",
        }
    }
}
