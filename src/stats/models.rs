// Security Center - Statistics Models
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: MIT

//! Data structures for firewall statistics.

use std::time::Instant;

/// Timestamp type for statistics.
pub type Timestamp = Instant;

/// Raw traffic counters from nftables/iptables.
#[derive(Debug, Clone, Default)]
pub struct TrafficCounters {
    pub accepted_packets: u64,
    pub dropped_packets: u64,
    pub timestamp: Option<Timestamp>,
}

impl TrafficCounters {
    /// Create new traffic counters with current timestamp.
    pub fn new() -> Self {
        Self {
            timestamp: Some(Instant::now()),
            ..Default::default()
        }
    }
}

/// UI-ready traffic ratio snapshot.
#[derive(Debug, Clone, Default)]
pub struct TrafficRatioSnapshot {
    /// Ratio of accepted packets (0.0 to 1.0).
    pub accepted_ratio: f64,
    /// Ratio of dropped packets (0.0 to 1.0).
    pub dropped_ratio: f64,
    /// Total packets in this sampling period.
    pub total_packets: u64,
    /// Absolute count of accepted packets.
    pub accepted: u64,
    /// Absolute count of blocked packets.
    pub blocked: u64,
    /// When this snapshot was created.
    pub timestamp: Option<Timestamp>,
}

impl TrafficRatioSnapshot {
    /// Create a snapshot showing 100% accepted (default safe state).
    pub fn default_safe() -> Self {
        Self {
            accepted_ratio: 1.0,
            dropped_ratio: 0.0,
            total_packets: 0,
            accepted: 0,
            blocked: 0,
            timestamp: Some(Instant::now()),
        }
    }
}

/// Connection statistics by protocol.
#[derive(Debug, Clone, Default)]
pub struct ConnectionStats {
    pub tcp: u32,
    pub udp: u32,
    pub icmp: u32,
    pub other: u32,
    pub timestamp: Option<Timestamp>,
}

impl ConnectionStats {
    /// Create new connection stats with current timestamp.
    pub fn new() -> Self {
        Self {
            timestamp: Some(Instant::now()),
            ..Default::default()
        }
    }

    /// Get total connections.
    pub fn total(&self) -> u32 {
        self.tcp + self.udp + self.icmp + self.other
    }
}