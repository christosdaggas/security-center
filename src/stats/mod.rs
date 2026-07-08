// Security Center - Statistics Module
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: MIT

//! Traffic statistics collection and aggregation.
//!
//! Retained for reuse: the overview dashboard now drives its live view from
//! netlink/procfs directly rather than these cached collectors, so nothing
//! constructs them at the moment.
#![allow(dead_code, unused_imports)]

mod cache;
mod collectors;
pub mod models;

pub use cache::{CachedConnectionStats, CachedStats, CachedTrafficRatio, StatsCache};
pub use collectors::{ConnectionCollector, TrafficCollector};
