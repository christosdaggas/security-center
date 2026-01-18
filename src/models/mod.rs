// Security Center - Models
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: MIT

//! Data models for firewall entities.

mod zone;
mod service;
mod port;
mod interface;

pub use zone::Zone;
pub use service::Service;
pub use port::Port;
pub use interface::Interface;
