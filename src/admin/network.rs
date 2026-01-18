// Security Center - Network Introspection
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: MIT

//! Network exposure introspection via procfs.
//!
//! This module reads network listening endpoints from the kernel's procfs
//! interface without using any shell commands or external tools.
//!
//! # Data Sources
//!
//! - `/proc/net/tcp` - IPv4 TCP connections
//! - `/proc/net/tcp6` - IPv6 TCP connections
//! - `/proc/net/udp` - IPv4 UDP connections
//! - `/proc/net/udp6` - IPv6 UDP connections
//! - `/proc/{pid}/cmdline` - Process command line
//! - `/proc/{pid}/fd/` - File descriptors to correlate sockets
//!
//! # Architecture
//!
//! The module correlates:
//! ```text
//! Listening Socket → Process (via inode) → Firewall Rule → Zone
//! ```

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use anyhow::{Context, Result};

use crate::firewall::FirewallClient;

/// Protocol type for a listening endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
        }
    }
}

/// Firewall status for a port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirewallStatus {
    /// Port is allowed in the specified zone
    Allowed { zone: String },
    /// Port is blocked (not in any zone's allowed list)
    Blocked,
    /// Firewall status unknown (firewalld not available)
    Unknown,
}

impl FirewallStatus {
    pub fn icon(&self) -> &'static str {
        match self {
            Self::Allowed { .. } => "security-low-symbolic",
            Self::Blocked => "security-high-symbolic",
            Self::Unknown => "security-medium-symbolic",
        }
    }

    pub fn label(&self) -> String {
        match self {
            Self::Allowed { zone } => format!("Allowed ({})", zone),
            Self::Blocked => "Blocked".to_string(),
            Self::Unknown => "Not Checked".to_string(),
        }
    }
}

/// A network endpoint that is listening for connections.
#[derive(Debug, Clone)]
pub struct ListeningEndpoint {
    /// Local IP address (0.0.0.0 means all interfaces)
    pub local_addr: IpAddr,
    /// Local port number
    pub port: u16,
    /// Protocol (TCP/UDP)
    pub protocol: Protocol,
    /// Socket inode for correlation
    pub inode: u64,
    /// Process ID (if found)
    pub pid: Option<u32>,
    /// Process name (if found)
    pub process_name: Option<String>,
    /// Process command line (if found)
    pub cmdline: Option<String>,
    /// Firewall status
    pub firewall_status: FirewallStatus,
}

impl ListeningEndpoint {
    /// Check if listening on all interfaces (potentially exposed).
    pub fn is_exposed(&self) -> bool {
        match self.local_addr {
            IpAddr::V4(addr) => addr == Ipv4Addr::UNSPECIFIED,
            IpAddr::V6(addr) => addr == Ipv6Addr::UNSPECIFIED,
        }
    }

    /// Get a warning message if this endpoint is risky.
    pub fn warning(&self) -> Option<&'static str> {
        if self.is_exposed() {
            match &self.firewall_status {
                FirewallStatus::Allowed { zone } if zone == "public" || zone == "external" => {
                    Some("Exposed to public network")
                }
                FirewallStatus::Allowed { .. } => {
                    Some("Listening on all interfaces")
                }
                _ => None,
            }
        } else {
            None
        }
    }

    /// Get a display name for the endpoint.
    pub fn display_name(&self) -> String {
        if let Some(name) = &self.process_name {
            format!("{} ({})", name, self.port)
        } else {
            format!("Port {}", self.port)
        }
    }
}

/// Network exposure analyzer.
///
/// This struct reads network state from procfs and correlates it with
/// firewall rules to provide a comprehensive view of network exposure.
pub struct NetworkExposure {
    /// Mapping from socket inode to PID
    inode_to_pid: HashMap<u64, u32>,
    /// Mapping from PID to process info
    pid_info: HashMap<u32, (String, String)>, // (name, cmdline)
}

impl Default for NetworkExposure {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkExposure {
    pub fn new() -> Self {
        Self {
            inode_to_pid: HashMap::new(),
            pid_info: HashMap::new(),
        }
    }

    /// Scan the system for listening endpoints.
    pub fn scan(&mut self) -> Result<Vec<ListeningEndpoint>> {
        // Build inode -> PID mapping first
        self.build_inode_map()?;
        
        // Read all listening sockets
        let mut endpoints = Vec::new();
        
        // TCP IPv4
        if let Ok(tcp4) = self.read_proc_net("/proc/net/tcp", Protocol::Tcp, false) {
            endpoints.extend(tcp4);
        }
        
        // TCP IPv6
        if let Ok(tcp6) = self.read_proc_net("/proc/net/tcp6", Protocol::Tcp, true) {
            endpoints.extend(tcp6);
        }
        
        // UDP IPv4
        if let Ok(udp4) = self.read_proc_net("/proc/net/udp", Protocol::Udp, false) {
            endpoints.extend(udp4);
        }
        
        // UDP IPv6
        if let Ok(udp6) = self.read_proc_net("/proc/net/udp6", Protocol::Udp, true) {
            endpoints.extend(udp6);
        }

        // Enrich with process info
        for endpoint in &mut endpoints {
            if let Some(&pid) = self.inode_to_pid.get(&endpoint.inode) {
                endpoint.pid = Some(pid);
                if let Some((name, cmdline)) = self.pid_info.get(&pid) {
                    endpoint.process_name = Some(name.clone());
                    endpoint.cmdline = Some(cmdline.clone());
                }
            }
        }

        // Sort by port
        endpoints.sort_by_key(|e| (e.port, e.protocol as u8));
        
        // Remove duplicates (same port/protocol)
        endpoints.dedup_by(|a, b| a.port == b.port && a.protocol == b.protocol);

        // Check firewall status for each endpoint
        self.update_firewall_status(&mut endpoints);

        Ok(endpoints)
    }

    /// Update firewall status for all endpoints by checking firewalld rules.
    fn update_firewall_status(&self, endpoints: &mut [ListeningEndpoint]) {
        // Try to connect to firewalld and get blocked ports
        let mut client = FirewallClient::new();
        if client.connect().is_err() {
            // Firewalld not available, leave status as Unknown
            return;
        }

        // Get zones and their rich rules
        let zones = match client.get_zones() {
            Ok(zones) => zones,
            Err(_) => return,
        };

        // Build a set of blocked ports (port, protocol) from rich rules
        let mut blocked_ports: HashSet<(u16, String)> = HashSet::new();
        let mut allowed_ports: HashMap<(u16, String), String> = HashMap::new(); // (port, protocol) -> zone

        for zone in &zones {
            // Check rich rules for reject/drop rules
            for rule in &zone.rich_rules {
                if let Some(port_info) = parse_rich_rule_port(rule) {
                    if rule.contains("reject") || rule.contains("drop") {
                        blocked_ports.insert(port_info);
                    }
                }
            }

            // Check allowed ports in the zone
            for port_str in &zone.ports {
                if let Some((port, protocol)) = parse_port_string(port_str) {
                    allowed_ports.insert((port, protocol), zone.name.clone());
                }
            }
        }

        // Update each endpoint's firewall status
        for endpoint in endpoints.iter_mut() {
            let protocol = endpoint.protocol.as_str().to_lowercase();
            let key = (endpoint.port, protocol.clone());

            if blocked_ports.contains(&key) {
                endpoint.firewall_status = FirewallStatus::Blocked;
            } else if let Some(zone) = allowed_ports.get(&key) {
                endpoint.firewall_status = FirewallStatus::Allowed { zone: zone.clone() };
            }
            // Otherwise, keep as Unknown (default)
        }
    }

    /// Build a mapping from socket inodes to PIDs.
    fn build_inode_map(&mut self) -> Result<()> {
        self.inode_to_pid.clear();
        self.pid_info.clear();

        let proc = Path::new("/proc");
        
        for entry in fs::read_dir(proc).context("Failed to read /proc")? {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };

            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            
            // Only process numeric directories (PIDs)
            let pid: u32 = match name_str.parse() {
                Ok(p) => p,
                Err(_) => continue,
            };

            // Read process info
            let cmdline = self.read_cmdline(pid).unwrap_or_default();
            let comm = self.read_comm(pid).unwrap_or_else(|| "unknown".to_string());
            self.pid_info.insert(pid, (comm, cmdline));

            // Read file descriptors to find sockets
            let fd_path = proc.join(name_str.as_ref()).join("fd");
            if let Ok(fds) = fs::read_dir(&fd_path) {
                for fd_entry in fds.flatten() {
                    if let Ok(link) = fs::read_link(fd_entry.path()) {
                        let link_str = link.to_string_lossy();
                        if link_str.starts_with("socket:[") {
                            // Extract inode from "socket:[12345]"
                            if let Some(inode_str) = link_str
                                .strip_prefix("socket:[")
                                .and_then(|s| s.strip_suffix(']'))
                            {
                                if let Ok(inode) = inode_str.parse::<u64>() {
                                    self.inode_to_pid.insert(inode, pid);
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Read a process's command name.
    fn read_comm(&self, pid: u32) -> Option<String> {
        fs::read_to_string(format!("/proc/{}/comm", pid))
            .ok()
            .map(|s| s.trim().to_string())
    }

    /// Read a process's command line.
    fn read_cmdline(&self, pid: u32) -> Option<String> {
        fs::read_to_string(format!("/proc/{}/cmdline", pid))
            .ok()
            .map(|s| s.replace('\0', " ").trim().to_string())
    }

    /// Read listening sockets from a /proc/net/* file.
    fn read_proc_net(&self, path: &str, protocol: Protocol, ipv6: bool) -> Result<Vec<ListeningEndpoint>> {
        let file = fs::File::open(path)
            .with_context(|| format!("Failed to open {}", path))?;
        
        let reader = BufReader::new(file);
        let mut endpoints = Vec::new();

        for (idx, line) in reader.lines().enumerate() {
            // Skip header line
            if idx == 0 {
                continue;
            }

            let line = match line {
                Ok(l) => l,
                Err(_) => continue,
            };

            if let Some(endpoint) = self.parse_proc_net_line(&line, protocol, ipv6) {
                endpoints.push(endpoint);
            }
        }

        Ok(endpoints)
    }

    /// Parse a line from /proc/net/tcp or similar.
    ///
    /// Format: sl local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt uid timeout inode
    fn parse_proc_net_line(&self, line: &str, protocol: Protocol, ipv6: bool) -> Option<ListeningEndpoint> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            return None;
        }

        // State: 0A = LISTEN for TCP, or just check for UDP
        let state = u8::from_str_radix(parts[3], 16).ok()?;
        
        // For TCP, only show LISTEN (0x0A)
        // For UDP, show all (UDP is connectionless, so "listening" means bound)
        if protocol == Protocol::Tcp && state != 0x0A {
            return None;
        }

        // Parse local address
        let local_parts: Vec<&str> = parts[1].split(':').collect();
        if local_parts.len() != 2 {
            return None;
        }

        let local_addr = if ipv6 {
            parse_ipv6_hex(local_parts[0])?
        } else {
            IpAddr::V4(parse_ipv4_hex(local_parts[0])?)
        };

        let port = u16::from_str_radix(local_parts[1], 16).ok()?;
        
        // Skip ports 0 (not actually listening)
        if port == 0 {
            return None;
        }

        let inode = parts[9].parse::<u64>().ok()?;

        Some(ListeningEndpoint {
            local_addr,
            port,
            protocol,
            inode,
            pid: None,
            process_name: None,
            cmdline: None,
            firewall_status: FirewallStatus::Unknown,
        })
    }
}

/// Parse an IPv4 address from hex format (little-endian).
fn parse_ipv4_hex(hex: &str) -> Option<Ipv4Addr> {
    if hex.len() != 8 {
        return None;
    }
    
    let bytes = u32::from_str_radix(hex, 16).ok()?;
    Some(Ipv4Addr::from(bytes.to_be()))
}

/// Parse an IPv6 address from hex format.
fn parse_ipv6_hex(hex: &str) -> Option<IpAddr> {
    if hex.len() != 32 {
        return None;
    }

    // IPv6 in /proc is stored as 4 groups of 8 hex chars, each in little-endian
    let mut bytes = [0u8; 16];
    for i in 0..4 {
        let group = &hex[i * 8..(i + 1) * 8];
        let val = u32::from_str_radix(group, 16).ok()?;
        let be_bytes = val.to_be_bytes();
        bytes[i * 4] = be_bytes[3];
        bytes[i * 4 + 1] = be_bytes[2];
        bytes[i * 4 + 2] = be_bytes[1];
        bytes[i * 4 + 3] = be_bytes[0];
    }

    Some(IpAddr::V6(Ipv6Addr::from(bytes)))
}

/// Common well-known ports and their service names.
pub fn get_service_name(port: u16) -> Option<&'static str> {
    match port {
        22 => Some("SSH"),
        23 => Some("Telnet"),
        25 => Some("SMTP"),
        53 => Some("DNS"),
        80 => Some("HTTP"),
        110 => Some("POP3"),
        143 => Some("IMAP"),
        443 => Some("HTTPS"),
        465 => Some("SMTPS"),
        587 => Some("Submission"),
        993 => Some("IMAPS"),
        995 => Some("POP3S"),
        3306 => Some("MySQL"),
        5432 => Some("PostgreSQL"),
        6379 => Some("Redis"),
        8080 => Some("HTTP Alt"),
        8443 => Some("HTTPS Alt"),
        27017 => Some("MongoDB"),
        _ => None,
    }
}

/// Parse a port and protocol from a rich rule string.
/// Example: `rule family="ipv4" port port="80" protocol="tcp" reject`
/// Returns Some((port, protocol)) if found.
fn parse_rich_rule_port(rule: &str) -> Option<(u16, String)> {
    // Check if this is a port rule
    if !rule.contains("port port=") {
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
    let protocol = remaining[..proto_end].to_lowercase();

    Some((port_number, protocol))
}

/// Parse a port string like "80/tcp" into (port, protocol).
fn parse_port_string(port_str: &str) -> Option<(u16, String)> {
    let parts: Vec<&str> = port_str.split('/').collect();
    if parts.len() != 2 {
        return None;
    }
    
    let port: u16 = parts[0].parse().ok()?;
    let protocol = parts[1].to_lowercase();
    
    Some((port, protocol))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ipv4() {
        // 0.0.0.0 in little-endian hex
        assert_eq!(parse_ipv4_hex("00000000"), Some(Ipv4Addr::new(0, 0, 0, 0)));
        // 127.0.0.1 in little-endian hex
        assert_eq!(parse_ipv4_hex("0100007F"), Some(Ipv4Addr::new(127, 0, 0, 1)));
    }
}
