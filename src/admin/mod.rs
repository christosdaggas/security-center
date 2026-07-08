// Security Center - Admin Module
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: MIT

//! Admin module providing D-Bus interfaces for system administration.
//!
//! This module contains pure Rust implementations for:
//! - systemd service management via D-Bus
//! - Network exposure introspection via procfs
//! - Coordinated admin actions
//!
//! # Architecture
//!
//! All system interactions use D-Bus APIs exclusively.
//! Privileged operations are authorized via Polkit (handled by the D-Bus services).
//!
//! ```text
//! UI Layer → Admin Module → D-Bus → systemd/firewalld → Polkit
//! ```

mod network;
mod actions;
mod sock_diag;
mod geoip;

pub use network::{ActiveConnection, ListeningEndpoint, NetworkExposure, FirewallStatus, get_service_name};
pub use sock_diag::{collect_socket_bytes, collect_top_talkers, TalkerBytes};
pub use geoip::GeoIp;
pub use actions::{AdminAction, AdminActionResult, QuickActionsManager, ActionCategory, QUICK_ACTIONS};
