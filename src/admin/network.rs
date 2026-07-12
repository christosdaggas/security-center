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

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use crate::firewall::FirewallClient;
use crate::validation::parse_port_spec;

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
                FirewallStatus::Allowed { .. } => Some("Listening on all interfaces"),
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

/// An established network connection to or from a remote host.
#[derive(Debug, Clone)]
pub struct ActiveConnection {
    // Parsed from the socket table; not shown in the grouped UI but kept as
    // part of the connection model for detail views and tests.
    #[allow(dead_code)]
    pub local_addr: IpAddr,
    #[allow(dead_code)]
    pub local_port: u16,
    pub remote_addr: IpAddr,
    pub remote_port: u16,
    pub protocol: Protocol,
    pub inode: u64,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
}

impl ActiveConnection {
    /// True if the remote peer is outside the local machine (not loopback).
    pub fn is_remote(&self) -> bool {
        !is_local_ip(self.remote_addr)
    }

    /// Process label, falling back to the PID or "unknown".
    pub fn process_label(&self) -> String {
        match (&self.process_name, self.pid) {
            (Some(name), _) => name.clone(),
            (None, Some(pid)) => format!("pid {}", pid),
            _ => "unknown".to_string(),
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

        // Collect blocked and allowed port ranges (single ports are
        // degenerate ranges) so range rules like "10-20/tcp" match too
        let mut blocked_ranges: Vec<(u16, u16, String)> = Vec::new(); // (start, end, protocol)
        let mut allowed_ranges: Vec<(u16, u16, String, String)> = Vec::new(); // (start, end, protocol, zone)

        for zone in &zones {
            // Check rich rules for reject/drop rules
            for rule in &zone.rich_rules {
                if let Some(((start, end), protocol)) = parse_rich_rule_port(rule) {
                    if rule.contains("reject") || rule.contains("drop") {
                        blocked_ranges.push((start, end, protocol));
                    }
                }
            }

            // Check allowed ports in the zone
            for port_str in &zone.ports {
                if let Some(((start, end), protocol)) = parse_port_string(port_str) {
                    allowed_ranges.push((start, end, protocol, zone.name.clone()));
                }
            }
        }

        // Update each endpoint's firewall status
        for endpoint in endpoints.iter_mut() {
            let protocol = endpoint.protocol.as_str().to_lowercase();
            let port = endpoint.port;

            if blocked_ranges
                .iter()
                .any(|(start, end, p)| *p == protocol && (*start..=*end).contains(&port))
            {
                endpoint.firewall_status = FirewallStatus::Blocked;
            } else if let Some((_, _, _, zone)) = allowed_ranges
                .iter()
                .find(|(start, end, p, _)| *p == protocol && (*start..=*end).contains(&port))
            {
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

    /// Scan established (ESTABLISHED) TCP connections and their remote peers.
    ///
    /// Returns connections to remote hosts (loopback peers are filtered out),
    /// sorted by remote address then port. Uses the same inode→PID map as the
    /// listening-socket scan — no privileges or new dependencies required.
    pub fn scan_connections(&mut self) -> Result<Vec<ActiveConnection>> {
        self.build_inode_map()?;

        let mut connections = Vec::new();
        for (path, ipv6) in [("/proc/net/tcp", false), ("/proc/net/tcp6", true)] {
            if let Ok(file) = fs::File::open(path) {
                for (idx, line) in BufReader::new(file).lines().enumerate() {
                    if idx == 0 {
                        continue; // header
                    }
                    let line = match line {
                        Ok(l) => l,
                        Err(_) => continue,
                    };
                    if let Some(conn) = self.parse_connection_line(&line, ipv6) {
                        if conn.is_remote() {
                            connections.push(conn);
                        }
                    }
                }
            }
        }

        // Enrich with process info
        for conn in &mut connections {
            if let Some(&pid) = self.inode_to_pid.get(&conn.inode) {
                conn.pid = Some(pid);
                if let Some((name, _)) = self.pid_info.get(&pid) {
                    conn.process_name = Some(name.clone());
                }
            }
        }

        connections.sort_by_key(|c| (c.remote_addr, c.remote_port));
        Ok(connections)
    }

    /// Parse an ESTABLISHED TCP row, extracting both local and remote peers.
    fn parse_connection_line(&self, line: &str, ipv6: bool) -> Option<ActiveConnection> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            return None;
        }

        // Only ESTABLISHED (0x01) connections
        let state = u8::from_str_radix(parts[3], 16).ok()?;
        if state != 0x01 {
            return None;
        }

        let (local_addr, local_port) = parse_addr_port(parts[1], ipv6)?;
        let (remote_addr, remote_port) = parse_addr_port(parts[2], ipv6)?;
        let inode = parts[9].parse::<u64>().ok()?;

        Some(ActiveConnection {
            local_addr,
            local_port,
            remote_addr,
            remote_port,
            protocol: Protocol::Tcp,
            inode,
            pid: None,
            process_name: None,
        })
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
    fn read_proc_net(
        &self,
        path: &str,
        protocol: Protocol,
        ipv6: bool,
    ) -> Result<Vec<ListeningEndpoint>> {
        let file = fs::File::open(path).with_context(|| format!("Failed to open {}", path))?;

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
    fn parse_proc_net_line(
        &self,
        line: &str,
        protocol: Protocol,
        ipv6: bool,
    ) -> Option<ListeningEndpoint> {
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

/// True for loopback / unspecified peers, including IPv4-mapped IPv6 forms
/// like `::ffff:127.0.0.1` that `IpAddr::is_loopback` alone misses.
pub fn is_local_ip(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_unspecified(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.is_loopback() || v4.is_unspecified(),
            None => v6.is_loopback() || v6.is_unspecified(),
        },
    }
}

/// Parse a "HEXADDR:HEXPORT" field from /proc/net/tcp into (IpAddr, port).
fn parse_addr_port(field: &str, ipv6: bool) -> Option<(IpAddr, u16)> {
    let (addr_hex, port_hex) = field.split_once(':')?;
    let addr = if ipv6 {
        parse_ipv6_hex(addr_hex)?
    } else {
        IpAddr::V4(parse_ipv4_hex(addr_hex)?)
    };
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    Some((addr, port))
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

/// Parse a port (or range) and protocol from a rich rule string.
/// Example: `rule family="ipv4" port port="80" protocol="tcp" reject`
/// Ranges like port="10-20" are also supported.
/// Returns Some(((start, end), protocol)) if found; end == start for a single port.
fn parse_rich_rule_port(rule: &str) -> Option<((u16, u16), String)> {
    // Check if this is a port rule
    if !rule.contains("port port=") {
        return None;
    }

    // Extract port spec: port="80" or port="10-20"
    let port_start = rule.find("port port=\"")?;
    let port_value_start = port_start + 11; // length of 'port port="'
    let remaining = &rule[port_value_start..];
    let port_end = remaining.find('"')?;
    let range = parse_port_spec(&remaining[..port_end])?;

    // Extract protocol: protocol="tcp" or protocol="udp"
    let proto_start = rule.find("protocol=\"")?;
    let proto_value_start = proto_start + 10; // length of 'protocol="'
    let remaining = &rule[proto_value_start..];
    let proto_end = remaining.find('"')?;
    let protocol = remaining[..proto_end].to_lowercase();

    Some((range, protocol))
}

/// Parse a port string like "80/tcp" or "10-20/tcp" into ((start, end), protocol).
/// end == start for a single port.
fn parse_port_string(port_str: &str) -> Option<((u16, u16), String)> {
    let (port_part, proto_part) = port_str.split_once('/')?;
    if proto_part.contains('/') {
        return None;
    }

    let range = parse_port_spec(port_part)?;
    let protocol = proto_part.to_lowercase();

    Some((range, protocol))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ipv4() {
        // 0.0.0.0 in little-endian hex
        assert_eq!(parse_ipv4_hex("00000000"), Some(Ipv4Addr::new(0, 0, 0, 0)));
        // 127.0.0.1 in little-endian hex
        assert_eq!(
            parse_ipv4_hex("0100007F"),
            Some(Ipv4Addr::new(127, 0, 0, 1))
        );
    }

    #[test]
    fn test_parse_addr_port() {
        // 192.168.1.10:443 — little-endian addr, big-endian port hex
        let (addr, port) = parse_addr_port("0A01A8C0:01BB", false).unwrap();
        assert_eq!(addr, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)));
        assert_eq!(port, 443);
        assert_eq!(parse_addr_port("nocolon", false), None);
    }

    #[test]
    fn test_parse_connection_line() {
        let scanner = NetworkExposure::new();
        // ESTABLISHED (state 01), remote 192.168.1.10:443
        let line = "   0: 0100007F:8080 0A01A8C0:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 987654 1 0000000000000000";
        let conn = scanner
            .parse_connection_line(line, false)
            .expect("should parse");
        assert_eq!(conn.remote_addr, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)));
        assert_eq!(conn.remote_port, 443);
        assert_eq!(conn.local_port, 0x8080);
        assert_eq!(conn.inode, 987654);
        assert!(conn.is_remote());

        // LISTEN (state 0A) must be rejected — not an active connection
        let listen = "   0: 0100007F:8080 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 111 1 0000000000000000";
        assert!(scanner.parse_connection_line(listen, false).is_none());
    }

    #[test]
    fn test_parse_ipv4_invalid() {
        assert_eq!(parse_ipv4_hex(""), None);
        assert_eq!(parse_ipv4_hex("000000"), None);
        assert_eq!(parse_ipv4_hex("000000000"), None);
        assert_eq!(parse_ipv4_hex("notahex"), None);
    }

    #[test]
    fn test_parse_ipv6() {
        assert_eq!(
            parse_ipv6_hex("00000000000000000000000000000000"),
            Some(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)))
        );
    }

    #[test]
    fn test_parse_ipv6_invalid() {
        assert_eq!(parse_ipv6_hex(""), None);
        assert_eq!(parse_ipv6_hex("000000000000000000000000000000"), None);
        assert_eq!(parse_ipv6_hex("000000000000000000000000000000000"), None);
    }

    #[test]
    fn test_parse_port_string() {
        assert_eq!(
            parse_port_string("80/tcp"),
            Some(((80, 80), "tcp".to_string()))
        );
        assert_eq!(
            parse_port_string("53/udp"),
            Some(((53, 53), "udp".to_string()))
        );
        assert_eq!(
            parse_port_string("10-20/tcp"),
            Some(((10, 20), "tcp".to_string()))
        );
        assert_eq!(parse_port_string("invalid"), None);
        assert_eq!(parse_port_string("80/tcp/udp"), None);
    }

    #[test]
    fn test_parse_rich_rule_port() {
        assert_eq!(
            parse_rich_rule_port("rule family=\"ipv4\" port port=\"80\" protocol=\"tcp\" reject"),
            Some(((80, 80), "tcp".to_string()))
        );
        assert_eq!(
            parse_rich_rule_port("rule family=\"ipv4\" port port=\"53\" protocol=\"udp\" drop"),
            Some(((53, 53), "udp".to_string()))
        );
        assert_eq!(
            parse_rich_rule_port(
                "rule family=\"ipv4\" port port=\"8000-9000\" protocol=\"tcp\" reject"
            ),
            Some(((8000, 9000), "tcp".to_string()))
        );
        assert_eq!(parse_rich_rule_port("not a port rule"), None);
    }

    #[test]
    fn test_get_service_name() {
        assert_eq!(get_service_name(22), Some("SSH"));
        assert_eq!(get_service_name(80), Some("HTTP"));
        assert_eq!(get_service_name(443), Some("HTTPS"));
        assert_eq!(get_service_name(9999), None);
    }
}
