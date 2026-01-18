// Security Center - Statistics Collectors
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: MIT

//! Data collectors for firewall statistics.

use std::collections::VecDeque;
use std::fs;
use std::time::Instant;

use super::models::{ConnectionStats, TrafficCounters, TrafficRatioSnapshot};

/// Internal time series for connection history.
#[derive(Debug)]
pub struct InternalTimeSeries {
    pub tcp: VecDeque<u32>,
    pub udp: VecDeque<u32>,
    pub icmp: VecDeque<u32>,
    max_samples: usize,
}

impl Default for InternalTimeSeries {
    fn default() -> Self {
        Self {
            tcp: VecDeque::with_capacity(60),
            udp: VecDeque::with_capacity(60),
            icmp: VecDeque::with_capacity(60),
            max_samples: 60,
        }
    }
}

impl InternalTimeSeries {
    fn push(&mut self, stats: &ConnectionStats) {
        if self.tcp.len() >= self.max_samples {
            self.tcp.pop_front();
            self.udp.pop_front();
            self.icmp.pop_front();
        }
        self.tcp.push_back(stats.tcp);
        self.udp.push_back(stats.udp);
        self.icmp.push_back(stats.icmp);
    }
}

/// Collector for traffic counters from nftables/proc.
#[derive(Debug, Default)]
pub struct TrafficCollector {
    /// Last collected counters for delta computation.
    last_counters: Option<TrafficCounters>,
    /// Accumulated totals.
    total_accepted: u64,
    total_blocked: u64,
}

impl TrafficCollector {
    /// Create a new traffic collector.
    pub fn new() -> Self {
        Self::default()
    }

    /// Update totals from external async collection.
    pub fn update_totals(&mut self, accepted: u64, blocked: u64) {
        self.total_accepted = accepted;
        self.total_blocked = blocked;
    }

    /// Collect current traffic counters.
    pub fn collect(&mut self) {
        let mut counters = TrafficCounters::new();

        // Try to read from /proc/net/snmp for basic IP stats
        if let Ok(content) = fs::read_to_string("/proc/net/snmp") {
            for line in content.lines() {
                if line.starts_with("Ip:") && !line.contains("Forwarding") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() > 10 {
                        if let Ok(in_pkts) = parts.get(3).unwrap_or(&"0").parse::<u64>() {
                            counters.accepted_packets = in_pkts;
                        }
                    }
                }
            }
        }

        // Try to read conntrack count
        if let Ok(content) = fs::read_to_string("/proc/sys/net/netfilter/nf_conntrack_count") {
            if let Ok(count) = content.trim().parse::<u64>() {
                counters.accepted_packets = counters.accepted_packets.max(count);
            }
        }

        // Calculate delta from last collection
        if let Some(ref last) = self.last_counters {
            let delta = counters.accepted_packets.saturating_sub(last.accepted_packets);
            self.total_accepted += delta;
        } else {
            // First collection - use current value as baseline
            self.total_accepted = counters.accepted_packets;
        }

        counters.dropped_packets = self.estimate_dropped_packets();
        counters.timestamp = Some(Instant::now());
        self.last_counters = Some(counters);
    }

    /// Get a snapshot of the traffic ratio for the UI.
    pub fn snapshot(&self) -> TrafficRatioSnapshot {
        let total = self.total_accepted + self.total_blocked;
        if total == 0 {
            TrafficRatioSnapshot::default_safe()
        } else {
            TrafficRatioSnapshot {
                accepted_ratio: self.total_accepted as f64 / total as f64,
                dropped_ratio: self.total_blocked as f64 / total as f64,
                total_packets: total,
                timestamp: Some(Instant::now()),
                // Additional fields needed by overview page
                accepted: self.total_accepted,
                blocked: self.total_blocked,
            }
        }
    }

    /// Estimate dropped packets from iptables counters.
    fn estimate_dropped_packets(&self) -> u64 {
        // Try to read from /proc/net/stat/nf_conntrack for drops
        if let Ok(content) = fs::read_to_string("/proc/net/stat/nf_conntrack") {
            for line in content.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() > 4 {
                    // Column 5 is typically the drop count
                    if let Ok(drops) = u64::from_str_radix(parts.get(4).unwrap_or(&"0"), 16) {
                        return drops;
                    }
                }
            }
        }
        0
    }
}

/// Collector for connection tracking statistics.
#[derive(Debug, Default)]
pub struct ConnectionCollector {
    /// Current connection stats.
    current: ConnectionStats,
    /// Time series history.
    history: InternalTimeSeries,
}

impl ConnectionCollector {
    /// Create a new connection collector.
    pub fn new() -> Self {
        Self::default()
    }

    /// Push stats from external async collection.
    pub fn push_stats(&mut self, stats: ConnectionStats) {
        self.history.push(&stats);
        self.current = stats;
    }

    /// Collect current connection statistics.
    pub fn collect(&mut self) {
        let mut stats = ConnectionStats::new();

        // Read from /proc/net/nf_conntrack if available
        if let Ok(content) = fs::read_to_string("/proc/net/nf_conntrack") {
            for line in content.lines() {
                if line.contains("tcp") {
                    stats.tcp += 1;
                } else if line.contains("udp") {
                    stats.udp += 1;
                } else if line.contains("icmp") {
                    stats.icmp += 1;
                } else {
                    stats.other += 1;
                }
            }
        } else {
            // Fallback: read from /proc/net/tcp, /proc/net/udp
            stats.tcp = Self::count_connections("/proc/net/tcp")
                + Self::count_connections("/proc/net/tcp6");
            stats.udp = Self::count_connections("/proc/net/udp")
                + Self::count_connections("/proc/net/udp6");
        }

        self.history.push(&stats);
        self.current = stats;
    }

    /// Get the current connection stats.
    pub fn stats(&self) -> &ConnectionStats {
        &self.current
    }

    /// Get the time series data for charting.
    pub fn timeseries(&self) -> &InternalTimeSeries {
        &self.history
    }

    /// Count connections from a /proc/net file.
    fn count_connections(path: &str) -> u32 {
        fs::read_to_string(path)
            .map(|content| content.lines().count().saturating_sub(1) as u32)
            .unwrap_or(0)
    }
}
