// Security Center - Network Activity Chart Widget
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: MIT

//! Live network activity chart with spike visualization.
//! Styled to match Network Manager's network activity graph.

use std::cell::RefCell;
use std::rc::Rc;

use gtk4::prelude::*;
use gtk4::subclass::prelude::*;
use gtk4::{glib, graphene};
use libadwaita as adw;

glib::wrapper! {
    /// A network activity chart showing connection data with spike visualization.
    pub struct NetworkActivityChart(ObjectSubclass<imp::NetworkActivityChart>)
        @extends gtk4::Widget;
}

impl NetworkActivityChart {
    /// Create a new network activity chart.
    pub fn new() -> Self {
        glib::Object::new()
    }

    /// Set the data for the chart (inbound and outbound).
    pub fn set_data(&self, inbound: &[f64], outbound: &[f64]) {
        let imp = self.imp();
        *imp.inbound_data.borrow_mut() = inbound.to_vec();
        *imp.outbound_data.borrow_mut() = outbound.to_vec();
        self.queue_draw();
    }

    /// Push new data points (for live updates).
    pub fn push_values(&self, inbound: f64, outbound: f64) {
        let imp = self.imp();
        let max_points = imp.max_points.get();
        
        {
            let mut data = imp.inbound_data.borrow_mut();
            data.push(inbound);
            while data.len() > max_points {
                data.remove(0);
            }
        }
        
        {
            let mut data = imp.outbound_data.borrow_mut();
            data.push(outbound);
            while data.len() > max_points {
                data.remove(0);
            }
        }
        
        self.queue_draw();
    }

    /// Get the current inbound value.
    pub fn current_inbound(&self) -> f64 {
        self.imp().inbound_data.borrow().last().copied().unwrap_or(0.0)
    }

    /// Get the current outbound value.
    pub fn current_outbound(&self) -> f64 {
        self.imp().outbound_data.borrow().last().copied().unwrap_or(0.0)
    }

    /// Start live data collection.
    pub fn start_live_collection(&self) {
        let chart = self.clone();
        let prev_stats: Rc<RefCell<Option<(u64, u64)>>> = Rc::new(RefCell::new(None));
        
        glib::timeout_add_local(std::time::Duration::from_millis(1000), move || {
            // Read real network stats from /proc/net/dev
            let (rx_bytes, tx_bytes) = read_network_stats();
            
            let mut prev = prev_stats.borrow_mut();
            let (in_rate, out_rate) = if let Some((prev_rx, prev_tx)) = *prev {
                let in_bytes = rx_bytes.saturating_sub(prev_rx) as f64;
                let out_bytes = tx_bytes.saturating_sub(prev_tx) as f64;
                (in_bytes / 1024.0, out_bytes / 1024.0) // KB/s
            } else {
                (0.0, 0.0)
            };
            *prev = Some((rx_bytes, tx_bytes));
            drop(prev);
            
            chart.push_values(in_rate, out_rate);
            
            glib::ControlFlow::Continue
        });
    }
}

impl Default for NetworkActivityChart {
    fn default() -> Self {
        Self::new()
    }
}

/// Read network stats from /proc/net/dev.
fn read_network_stats() -> (u64, u64) {
    let mut rx_total: u64 = 0;
    let mut tx_total: u64 = 0;
    
    if let Ok(content) = std::fs::read_to_string("/proc/net/dev") {
        for line in content.lines().skip(2) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 10 {
                let iface = parts[0].trim_end_matches(':');
                // Skip loopback interface
                if iface == "lo" {
                    continue;
                }
                // Parse receive bytes (column 1) and transmit bytes (column 9)
                if let (Ok(rx), Ok(tx)) = (
                    parts[1].parse::<u64>(),
                    parts[9].parse::<u64>(),
                ) {
                    rx_total += rx;
                    tx_total += tx;
                }
            }
        }
    }
    
    (rx_total, tx_total)
}

mod imp {
    use super::*;
    use std::cell::Cell;

    #[derive(Default)]
    pub struct NetworkActivityChart {
        pub inbound_data: RefCell<Vec<f64>>,
        pub outbound_data: RefCell<Vec<f64>>,
        pub max_points: Cell<usize>,
    }

    #[glib::object_subclass]
    impl ObjectSubclass for NetworkActivityChart {
        const NAME: &'static str = "SecurityCenterNetworkActivityChart";
        type Type = super::NetworkActivityChart;
        type ParentType = gtk4::Widget;
    }

    impl ObjectImpl for NetworkActivityChart {
        fn constructed(&self) {
            self.parent_constructed();
            
            let obj = self.obj();
            obj.set_width_request(300);
            obj.set_height_request(120);
            
            self.max_points.set(60);
            
            // Initialize with zeros
            *self.inbound_data.borrow_mut() = vec![0.0; 60];
            *self.outbound_data.borrow_mut() = vec![0.0; 60];
        }
    }

    impl WidgetImpl for NetworkActivityChart {
        fn snapshot(&self, snapshot: &gtk4::Snapshot) {
            let widget = self.obj();
            let width = widget.width() as f64;
            let height = widget.height() as f64;
            
            if width <= 0.0 || height <= 0.0 {
                return;
            }
            
            let bounds = graphene::Rect::new(0.0, 0.0, width as f32, height as f32);
            let cr = snapshot.append_cairo(&bounds);
            
            // Get current color scheme
            let is_dark = adw::StyleManager::default().is_dark();
            
            // Background
            if is_dark {
                cr.set_source_rgba(0.1, 0.1, 0.1, 0.3);
            } else {
                cr.set_source_rgba(0.95, 0.95, 0.95, 0.5);
            }
            let _ = cr.paint();
            
            // Grid lines
            if is_dark {
                cr.set_source_rgba(1.0, 1.0, 1.0, 0.1);
            } else {
                cr.set_source_rgba(0.0, 0.0, 0.0, 0.1);
            }
            cr.set_line_width(0.5);
            for i in 1..4 {
                let y = height * (i as f64) / 4.0;
                cr.move_to(0.0, y);
                cr.line_to(width, y);
            }
            let _ = cr.stroke();

            let inbound = self.inbound_data.borrow();
            let outbound = self.outbound_data.borrow();
            
            // Find max value for scaling
            let max_val = inbound.iter().chain(outbound.iter())
                .cloned()
                .fold(1.0f64, f64::max);
            
            let step = if inbound.len() > 1 {
                width / (inbound.len() as f64 - 1.0)
            } else {
                width
            };
            
            // Draw inbound line (blue - like download)
            cr.set_source_rgba(0.21, 0.52, 0.89, 0.8);
            cr.set_line_width(2.0);
            for (i, &val) in inbound.iter().enumerate() {
                let x = i as f64 * step;
                let y = height - (val / max_val * height * 0.9) - 5.0;
                if i == 0 {
                    cr.move_to(x, y);
                } else {
                    cr.line_to(x, y);
                }
            }
            let _ = cr.stroke();
            
            // Fill under inbound line
            cr.set_source_rgba(0.21, 0.52, 0.89, 0.15);
            for (i, &val) in inbound.iter().enumerate() {
                let x = i as f64 * step;
                let y = height - (val / max_val * height * 0.9) - 5.0;
                if i == 0 {
                    cr.move_to(x, height);
                    cr.line_to(x, y);
                } else {
                    cr.line_to(x, y);
                }
            }
            cr.line_to(width, height);
            cr.close_path();
            let _ = cr.fill();
            
            // Draw outbound line (green - like upload)
            cr.set_source_rgba(0.18, 0.76, 0.49, 0.8);
            cr.set_line_width(2.0);
            for (i, &val) in outbound.iter().enumerate() {
                let x = i as f64 * step;
                let y = height - (val / max_val * height * 0.9) - 5.0;
                if i == 0 {
                    cr.move_to(x, y);
                } else {
                    cr.line_to(x, y);
                }
            }
            let _ = cr.stroke();
        }
    }
}
