// GNOME Firewall - Models
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: GPL-3.0-or-later

//! Data models for firewall entities.

mod zone;
mod service;
mod port;
mod interface;

pub use zone::Zone;
pub use service::Service;
pub use port::Port;
pub use interface::Interface;
