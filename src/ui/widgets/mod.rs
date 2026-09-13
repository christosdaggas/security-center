// Security Center - Widgets Module
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: MIT

//! Custom UI widgets.

mod bar_chart;
// NOTE: donut_chart intentionally not registered (unused); the file stays
// on disk with its prior history.
mod line_chart;
mod meter_bar;
mod network_activity_chart;
mod sparkline;
mod world_map;

pub use bar_chart::BarChart;
#[allow(unused_imports)] // retained for reuse
pub use line_chart::LineChart;
pub use meter_bar::MeterBar;
pub use network_activity_chart::{list_interfaces, NetworkActivityChart};
#[allow(unused_imports)] // retained for reuse
pub use sparkline::Sparkline;
pub use world_map::{country_name, WorldMap};
