// Security Center - Widgets Module
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: MIT

//! Custom UI widgets.

mod bar_chart;
mod donut_chart;
mod line_chart;
mod meter_bar;
mod network_activity_chart;
mod sparkline;

pub use bar_chart::BarChart;
pub use donut_chart::DonutChart;
#[allow(unused_imports)] // retained for reuse
pub use line_chart::LineChart;
pub use meter_bar::MeterBar;
pub use network_activity_chart::{list_interfaces, NetworkActivityChart};
pub use sparkline::Sparkline;
