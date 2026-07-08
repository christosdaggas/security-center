// Security Center - Models
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: MIT

//! Data models for firewall entities.

mod interface;
mod port;
mod service;
mod zone;

pub use consolidated_port::ConsolidatedPort;
pub use interface::Interface;
pub use port::Port;
pub use service::Service;
pub use zone::Zone;

mod consolidated_port;
