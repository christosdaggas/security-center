// GNOME Firewall - Line Chart Widget
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: GPL-3.0-or-later

//! Animated line chart for time series data.

use std::cell::RefCell;

use gtk4::prelude::*;
use gtk4::subclass::prelude::*;
use gtk4::{gdk, glib, graphene};

/// A data series for the line chart.
#[derive(Debug, Clone)]
pub struct DataSeries {
    pub values: Vec<f64>,
    pub color: gdk::RGBA,
    pub label: String,
}

impl DataSeries {
    /// Create a new data series.
    pub fn new(label: &str, color: gdk::RGBA) -> Self {
        Self {
            values: Vec::new(),
            color,
            label: label.to_string(),
        }
    }

    /// Set the values.
    pub fn set_values(&mut self, values: Vec<f64>) {
        self.values = values;
    }
}

glib::wrapper! {
    /// A line chart widget showing time series data.
    pub struct LineChart(ObjectSubclass<imp::LineChart>)
        @extends gtk4::Widget;
}

impl LineChart {
    /// Create a new line chart.
    pub fn new() -> Self {
        glib::Object::new()
    }

    /// Set the data for TCP, UDP, and ICMP series.
    pub fn set_data(&self, tcp: &[f64], udp: &[f64], icmp: &[f64]) {
        let tcp_color = gdk::RGBA::new(0.3, 0.6, 0.9, 1.0); // Blue
        let udp_color = gdk::RGBA::new(0.9, 0.5, 0.2, 1.0); // Orange
        let icmp_color = gdk::RGBA::new(0.4, 0.8, 0.4, 1.0); // Green
        
        let mut tcp_series = DataSeries::new("TCP", tcp_color);
        tcp_series.set_values(tcp.to_vec());
        
        let mut udp_series = DataSeries::new("UDP", udp_color);
        udp_series.set_values(udp.to_vec());
        
        let mut icmp_series = DataSeries::new("ICMP", icmp_color);
        icmp_series.set_values(icmp.to_vec());
        
        self.set_series(vec![tcp_series, udp_series, icmp_series]);
    }

    /// Set the data series to display.
    pub fn set_series(&self, series: Vec<DataSeries>) {
        self.imp().series.replace(series);
        self.queue_draw();
    }

    /// Add a single value to each series (for live updates).
    pub fn push_values(&self, values: &[f64]) {
        let imp = self.imp();
        let mut series = imp.series.borrow_mut();
        let max_points = imp.max_points.get();
        
        for (i, value) in values.iter().enumerate() {
            if let Some(s) = series.get_mut(i) {
                s.values.push(*value);
                while s.values.len() > max_points {
                    s.values.remove(0);
                }
            }
        }
        drop(series);
        self.queue_draw();
    }

    /// Set the maximum number of data points to display.
    pub fn set_max_points(&self, max: usize) {
        self.imp().max_points.set(max);
    }

    /// Set whether to show the legend.
    pub fn set_show_legend(&self, show: bool) {
        self.imp().show_legend.set(show);
        self.queue_draw();
    }
}

impl Default for LineChart {
    fn default() -> Self {
        Self::new()
    }
}

mod imp {
    use super::*;
    use std::cell::Cell;

    #[derive(Default)]
    pub struct LineChart {
        pub series: RefCell<Vec<DataSeries>>,
        pub max_points: Cell<usize>,
        pub show_legend: Cell<bool>,
    }

    #[glib::object_subclass]
    impl ObjectSubclass for LineChart {
        const NAME: &'static str = "GnomeFirewallLineChart";
        type Type = super::LineChart;
        type ParentType = gtk4::Widget;
    }

    impl ObjectImpl for LineChart {
        fn constructed(&self) {
            self.parent_constructed();
            
            let obj = self.obj();
            obj.set_width_request(300);
            obj.set_height_request(120);
            
            self.max_points.set(60);
            self.show_legend.set(true);
        }
    }

    impl WidgetImpl for LineChart {
        fn snapshot(&self, snapshot: &gtk4::Snapshot) {
            let widget = self.obj();
            let width = widget.width() as f64;
            let height = widget.height() as f64;
            
            let series = self.series.borrow();
            
            // Margins
            let margin_left = 10.0;
            let margin_right = 10.0;
            let margin_top = 10.0;
            let margin_bottom = if self.show_legend.get() { 30.0 } else { 10.0 };
            
            let chart_width = width - margin_left - margin_right;
            let chart_height = height - margin_top - margin_bottom;
            
            // Find max value across all series
            let max_value = series
                .iter()
                .flat_map(|s| s.values.iter())
                .copied()
                .fold(1.0_f64, f64::max);
            
            // Get colors - use widget color() method (GTK 4.10+) with fallbacks
            let dim_color = gdk::RGBA::new(0.5, 0.5, 0.5, 0.2);
            let text_color = widget.color();
            
            let bounds = graphene::Rect::new(0.0, 0.0, width as f32, height as f32);
            let cr = snapshot.append_cairo(&bounds);
            
            // Draw subtle grid lines
            cr.set_source_rgba(
                dim_color.red() as f64,
                dim_color.green() as f64,
                dim_color.blue() as f64,
                dim_color.alpha() as f64,
            );
            cr.set_line_width(0.5);
            
            for i in 0..=4 {
                let y = margin_top + (chart_height * i as f64 / 4.0);
                cr.move_to(margin_left, y);
                cr.line_to(width - margin_right, y);
                let _ = cr.stroke();
            }
            
            // Draw each series
            for series in series.iter() {
                if series.values.is_empty() {
                    continue;
                }
                
                let points_count = series.values.len();
                let x_step = if points_count > 1 {
                    chart_width / (points_count - 1) as f64
                } else {
                    chart_width
                };
                
                cr.set_source_rgba(
                    series.color.red() as f64,
                    series.color.green() as f64,
                    series.color.blue() as f64,
                    series.color.alpha() as f64,
                );
                cr.set_line_width(2.0);
                cr.set_line_join(gtk4::cairo::LineJoin::Round);
                cr.set_line_cap(gtk4::cairo::LineCap::Round);
                
                for (i, value) in series.values.iter().enumerate() {
                    let x = margin_left + (i as f64 * x_step);
                    let y = margin_top + chart_height - (value / max_value * chart_height);
                    
                    if i == 0 {
                        cr.move_to(x, y);
                    } else {
                        cr.line_to(x, y);
                    }
                }
                let _ = cr.stroke();
                
                // Draw area fill with transparency
                cr.set_source_rgba(
                    series.color.red() as f64,
                    series.color.green() as f64,
                    series.color.blue() as f64,
                    0.1,
                );
                
                for (i, value) in series.values.iter().enumerate() {
                    let x = margin_left + (i as f64 * x_step);
                    let y = margin_top + chart_height - (value / max_value * chart_height);
                    
                    if i == 0 {
                        cr.move_to(x, margin_top + chart_height);
                        cr.line_to(x, y);
                    } else {
                        cr.line_to(x, y);
                    }
                }
                
                // Close the path
                let last_x = margin_left + ((series.values.len() - 1) as f64 * x_step);
                cr.line_to(last_x, margin_top + chart_height);
                cr.close_path();
                let _ = cr.fill();
            }
            
            // Draw legend
            if self.show_legend.get() && !series.is_empty() {
                let legend_y = height - 15.0;
                let mut legend_x = margin_left;
                
                cr.set_font_size(10.0);
                
                for s in series.iter() {
                    // Color dot
                    cr.set_source_rgba(
                        s.color.red() as f64,
                        s.color.green() as f64,
                        s.color.blue() as f64,
                        s.color.alpha() as f64,
                    );
                    cr.arc(legend_x + 4.0, legend_y, 4.0, 0.0, 2.0 * std::f64::consts::PI);
                    let _ = cr.fill();
                    
                    // Label
                    cr.set_source_rgba(
                        text_color.red() as f64,
                        text_color.green() as f64,
                        text_color.blue() as f64,
                        0.7,
                    );
                    cr.move_to(legend_x + 12.0, legend_y + 3.0);
                    let _ = cr.show_text(&s.label);
                    
                    legend_x += 60.0;
                }
            }
        }
    }
}
