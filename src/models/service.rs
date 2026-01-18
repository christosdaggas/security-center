// Security Center - Service Model
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: MIT

//! Firewall service model.

/// A firewall service definition.
#[derive(Debug, Clone, Default)]
pub struct Service {
    pub name: String,
    pub description: String,
    pub ports: Vec<(String, String)>,  // (port, protocol)
    pub is_enabled: bool,
}

impl Service {
    /// Create a new service.
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            ..Default::default()
        }
    }

    /// Get the risk level of the service.
    pub fn risk_level(&self) -> &'static str {
        match self.name.as_str() {
            "ssh" | "cockpit" | "vnc-server" => "medium",
            "ftp" | "telnet" | "rsh" | "rlogin" => "high",
            "http" | "https" | "dns" => "low",
            _ => "low",
        }
    }

    /// Get a human-readable description.
    pub fn human_description(&self) -> &str {
        if !self.description.is_empty() {
            &self.description
        } else {
            match self.name.as_str() {
                "ssh" => "Secure Shell remote access",
                "http" => "Web server (unencrypted)",
                "https" => "Web server (encrypted)",
                "dns" => "Domain Name System",
                "dhcp" => "Dynamic Host Configuration Protocol",
                "ftp" => "File Transfer Protocol",
                "smtp" => "Email sending",
                "imap" | "imaps" => "Email retrieval",
                "samba" => "Windows file sharing",
                "nfs" => "Network File System",
                "cockpit" => "Web-based server management",
                _ => "Network service",
            }
        }
    }

    /// Get a summary of the ports used by this service.
    pub fn ports_summary(&self) -> String {
        if self.ports.is_empty() {
            return String::new();
        }
        
        let port_strs: Vec<String> = self.ports.iter()
            .take(3)
            .map(|(port, proto)| format!("{}/{}", port, proto))
            .collect();
        
        if self.ports.len() > 3 {
            format!("{} +{}", port_strs.join(", "), self.ports.len() - 3)
        } else {
            port_strs.join(", ")
        }
    }
}
