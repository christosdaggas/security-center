// Security Center - Statistics Cache
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: MIT

//! Caching for statistics to avoid slow startup.

use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use tracing::warn;

/// Cached statistics data.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CachedStats {
    /// Timestamp when cached.
    pub timestamp: u64,
    /// Last known traffic ratio.
    pub traffic_ratio: CachedTrafficRatio,
    /// Last known connection stats.
    pub connections: CachedConnectionStats,
    /// Last known blocked ports.
    pub blocked_ports: Vec<(String, u64)>,
}

/// Cached traffic ratio (serializable).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CachedTrafficRatio {
    pub accepted: u64,
    pub blocked: u64,
}

/// Cached connection time series (serializable).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CachedConnectionStats {
    pub tcp_series: Vec<f64>,
    pub udp_series: Vec<f64>,
    pub icmp_series: Vec<f64>,
}

/// Statistics cache manager.
#[derive(Debug)]
pub struct StatsCache {
    path: PathBuf,
    /// Maximum age before cache is considered stale.
    max_age: Duration,
}

impl Default for StatsCache {
    fn default() -> Self {
        Self::new()
    }
}

impl StatsCache {
    /// Create a new cache manager.
    pub fn new() -> Self {
        let path = dirs::cache_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("gnome-security-center")
            .join("stats_cache.json");

        Self {
            path,
            max_age: Duration::from_secs(3600), // 1 hour
        }
    }

    /// Load cached statistics.
    pub fn load(&self) -> Option<CachedStats> {
        let content = fs::read_to_string(&self.path).ok()?;
        let cached: CachedStats = serde_json::from_str(&content).ok()?;

        // Check if cache is fresh
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let age = Duration::from_secs(now.saturating_sub(cached.timestamp));
        if age > self.max_age {
            return None;
        }

        Some(cached)
    }

    /// Save statistics to cache.
    pub fn save(&self, stats: &CachedStats) {
        if let Some(parent) = self.path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        match serde_json::to_string_pretty(stats) {
            Ok(content) => {
                if let Err(e) = fs::write(&self.path, content) {
                    warn!("Failed to save stats cache: {}", e);
                }
            }
            Err(e) => {
                warn!("Failed to serialize stats cache: {}", e);
            }
        }
    }
}
