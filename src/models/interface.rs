// GNOME Firewall - Interface Model
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: GPL-3.0-or-later

//! Network interface model.

/// A network interface.
#[derive(Debug, Clone, Default)]
pub struct Interface {
    pub name: String,
    pub zone: String,
    pub is_active: bool,
}

impl Interface {
    /// Create a new interface.
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            ..Default::default()
        }
    }

    /// Get a human-readable type for the interface.
    pub fn interface_type(&self) -> &'static str {
        if self.name.starts_with("eth") || self.name.starts_with("en") {
            "Ethernet"
        } else if self.name.starts_with("wl") || self.name.starts_with("wlan") {
            "Wireless"
        } else if self.name.starts_with("br") {
            "Bridge"
        } else if self.name.starts_with("veth") || self.name.starts_with("docker") {
            "Virtual (Container)"
        } else if self.name.starts_with("virbr") {
            "Virtual (Libvirt)"
        } else if self.name.starts_with("tun") || self.name.starts_with("tap") {
            "Tunnel"
        } else if self.name == "lo" {
            "Loopback"
        } else {
            "Unknown"
        }
    }
}
