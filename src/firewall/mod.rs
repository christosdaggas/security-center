// Security Center - Firewall Module
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: MIT

//! Firewalld D-Bus client and related utilities.

mod client;

pub use client::FirewallClient;

// Keep FirewallEvent for future use (event-based architecture)
#[allow(unused_imports)]
pub use client::FirewallEvent;

/// D-Bus bus name for firewalld.
pub const BUS_NAME: &str = "org.fedoraproject.FirewallD1";

/// D-Bus object paths.
pub mod paths {
    pub const ROOT: &str = "/org/fedoraproject/FirewallD1";
    pub const CONFIG: &str = "/org/fedoraproject/FirewallD1/config";
}

/// D-Bus interface names.
#[allow(dead_code)]
pub mod interfaces {
    /// Main firewalld interface (for getDefaultZone, setDefaultZone, reload, etc.)
    pub const MAIN: &str = "org.fedoraproject.FirewallD1";
    /// Zone interface (for zone-specific operations)
    pub const ZONE: &str = "org.fedoraproject.FirewallD1.zone";
    pub const CONFIG: &str = "org.fedoraproject.FirewallD1.config";
    pub const CONFIG_ZONE: &str = "org.fedoraproject.FirewallD1.config.zone";
    pub const PROPERTIES: &str = "org.freedesktop.DBus.Properties";
}

/// Get a description for a zone name.
pub fn zone_description(name: &str) -> &'static str {
    match name {
        "drop" => "Drops all incoming network packets with no reply. Only outgoing connections are possible.",
        "block" => "Incoming connections are rejected with an icmp-host-prohibited message. Only outgoing connections are possible.",
        "public" => "For use in public areas. You do not trust other computers. Only selected connections are accepted.",
        "external" => "For use on external networks with masquerading enabled. Only selected connections are accepted.",
        "dmz" => "For computers in your demilitarized zone that are publicly accessible. Only selected connections are accepted.",
        "work" => "For use in work areas. You mostly trust other computers. Only selected connections are accepted.",
        "home" => "For use at home. You mostly trust other computers. Only selected connections are accepted.",
        "internal" => "For use on internal networks. You mostly trust other computers. Only selected connections are accepted.",
        "trusted" => "All network connections are accepted.",
        _ => "Custom zone",
    }
}
