// Security Center - Widgets Module
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: MIT

//! Custom UI widgets.

mod donut_chart;
mod line_chart;
mod bar_chart;
mod network_activity_chart;

pub use donut_chart::DonutChart;
pub use line_chart::LineChart;
pub use bar_chart::BarChart;
#[allow(unused)]
pub use network_activity_chart::NetworkActivityChart;
