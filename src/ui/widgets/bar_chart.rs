// Security Center - Bar Chart Widget
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: MIT

//! Animated horizontal bar chart for ranked data.

use std::cell::{Cell, RefCell};

use gtk4::prelude::*;
use gtk4::subclass::prelude::*;
use gtk4::{gdk, glib, graphene};

/// A bar entry for the chart.
#[derive(Debug, Clone)]
pub struct BarEntry {
    pub label: String,
    pub value: f64,
    pub max_value: f64,
}

impl BarEntry {
    /// Create a new bar entry.
    pub fn new(label: &str, value: f64, max_value: f64) -> Self {
        Self {
            label: label.to_string(),
            value,
            max_value: max_value.max(1.0),
        }
    }

    /// Get the normalized value (0.0 to 1.0).
    pub fn normalized(&self) -> f64 {
        (self.value / self.max_value).clamp(0.0, 1.0)
    }
}

glib::wrapper! {
    /// A horizontal bar chart widget showing ranked data.
    pub struct BarChart(ObjectSubclass<imp::BarChart>)
        @extends gtk4::Widget;
}

impl BarChart {
    /// Create a new bar chart.
    pub fn new() -> Self {
        glib::Object::new()
    }

    /// Set the data from a list of (label, value) tuples.
    pub fn set_data(&self, data: &[(String, u64)]) {
        let max_value = data.iter().map(|(_, v)| *v as f64).fold(1.0_f64, f64::max);
        let entries: Vec<BarEntry> = data.iter()
            .map(|(label, value)| BarEntry::new(label, *value as f64, max_value))
            .collect();
        self.set_entries(entries);
    }

    /// Set the bar entries to display.
    pub fn set_entries(&self, entries: Vec<BarEntry>) {
        let imp = self.imp();
        
        // Store target values and start animation
        let current = imp.current_values.borrow().clone();
        let target: Vec<f64> = entries.iter().map(|e| e.normalized()).collect();
        
        // Pad or truncate current values to match
        let mut padded_current = current;
        padded_current.resize(target.len(), 0.0);
        
        imp.current_values.replace(padded_current);
        imp.target_values.replace(target);
        imp.entries.replace(entries);
        
        if !imp.animating.get() {
            self.start_animation();
        }
    }

    /// Set the placeholder text when there's no data.
    pub fn set_placeholder(&self, text: &str) {
        let imp = self.imp();
        imp.placeholder.replace(text.to_string());
        // Clear entries so placeholder is shown
        imp.entries.replace(Vec::new());
        imp.current_values.replace(Vec::new());
        imp.target_values.replace(Vec::new());
        self.queue_draw();
    }

    /// Start the animation.
    fn start_animation(&self) {
        let imp = self.imp();
        imp.animating.set(true);
        
        let widget = self.clone();
        self.add_tick_callback(move |_, _| {
            let imp = widget.imp();
            
            let mut current = imp.current_values.borrow_mut();
            let target = imp.target_values.borrow();
            
            let mut all_done = true;
            
            for (i, curr) in current.iter_mut().enumerate() {
                if let Some(tgt) = target.get(i) {
                    let diff = tgt - *curr;
                    if diff.abs() > 0.001 {
                        *curr += diff * 0.12;
                        all_done = false;
                    } else {
                        *curr = *tgt;
                    }
                }
            }
            
            drop(current);
            drop(target);
            
            widget.queue_draw();
            
            if all_done {
                imp.animating.set(false);
                glib::ControlFlow::Break
            } else {
                glib::ControlFlow::Continue
            }
        });
    }
}

impl Default for BarChart {
    fn default() -> Self {
        Self::new()
    }
}

mod imp {
    use super::*;

    #[derive(Default)]
    pub struct BarChart {
        pub entries: RefCell<Vec<BarEntry>>,
        pub current_values: RefCell<Vec<f64>>,
        pub target_values: RefCell<Vec<f64>>,
        pub animating: Cell<bool>,
        pub placeholder: RefCell<String>,
    }

    #[glib::object_subclass]
    impl ObjectSubclass for BarChart {
        const NAME: &'static str = "SecurityCenterBarChart";
        type Type = super::BarChart;
        type ParentType = gtk4::Widget;
    }

    impl ObjectImpl for BarChart {
        fn constructed(&self) {
            self.parent_constructed();
            
            let obj = self.obj();
            obj.set_width_request(250);
            obj.set_height_request(150);
            
            self.placeholder.replace("No data available".to_string());
        }
    }

    impl WidgetImpl for BarChart {
        fn snapshot(&self, snapshot: &gtk4::Snapshot) {
            let widget = self.obj();
            let width = widget.width() as f64;
            let height = widget.height() as f64;
            
            let entries = self.entries.borrow();
            let current_values = self.current_values.borrow();
            
            // Get colors - use widget color() method (GTK 4.10+) with fallbacks
            let accent_color = gdk::RGBA::new(0.2, 0.52, 0.89, 1.0);  // Blue accent
            let text_color = widget.color();
            let dim_color = gdk::RGBA::new(0.5, 0.5, 0.5, 0.2);
            
            let bounds = graphene::Rect::new(0.0, 0.0, width as f32, height as f32);
            let cr = snapshot.append_cairo(&bounds);
            
            if entries.is_empty() {
                // Draw placeholder
                let placeholder = self.placeholder.borrow();
                cr.set_source_rgba(
                    text_color.red() as f64,
                    text_color.green() as f64,
                    text_color.blue() as f64,
                    0.5,
                );
                cr.select_font_face("Sans", gtk4::cairo::FontSlant::Normal, gtk4::cairo::FontWeight::Normal);
                cr.set_font_size(12.0);
                let extents = cr.text_extents(&placeholder).unwrap_or_else(|_| gtk4::cairo::TextExtents::new(0.0, 0.0, 0.0, 0.0, 0.0, 0.0));
                cr.move_to((width - extents.width()) / 2.0, height / 2.0);
                let _ = cr.show_text(&placeholder);
                return;
            }
            
            let bar_height = 24.0;
            let bar_spacing = 8.0;
            let label_width = 80.0;
            let value_width = 50.0;
            let bar_area_width = width - label_width - value_width - 20.0;
            
            let max_bars = 5;
            let bars_to_show = entries.len().min(max_bars);
            
            for (i, entry) in entries.iter().take(bars_to_show).enumerate() {
                let y = 10.0 + (i as f64 * (bar_height + bar_spacing));
                let current_value = current_values.get(i).copied().unwrap_or(0.0);
                
                // Draw label
                cr.set_source_rgba(
                    text_color.red() as f64,
                    text_color.green() as f64,
                    text_color.blue() as f64,
                    0.9,
                );
                cr.select_font_face("Sans", gtk4::cairo::FontSlant::Normal, gtk4::cairo::FontWeight::Normal);
                cr.set_font_size(11.0);
                
                // Truncate label if too long
                let label = if entry.label.len() > 12 {
                    format!("{}…", &entry.label[..11])
                } else {
                    entry.label.clone()
                };
                
                cr.move_to(10.0, y + bar_height / 2.0 + 4.0);
                let _ = cr.show_text(&label);
                
                // Draw bar background
                cr.set_source_rgba(
                    dim_color.red() as f64,
                    dim_color.green() as f64,
                    dim_color.blue() as f64,
                    dim_color.alpha() as f64,
                );
                Self::rounded_rect(&cr, label_width, y, bar_area_width, bar_height, 4.0);
                let _ = cr.fill();
                
                // Draw bar fill
                let fill_width = current_value * bar_area_width;
                if fill_width > 0.0 {
                    cr.set_source_rgba(
                        accent_color.red() as f64,
                        accent_color.green() as f64,
                        accent_color.blue() as f64,
                        accent_color.alpha() as f64,
                    );
                    Self::rounded_rect(&cr, label_width, y, fill_width.max(8.0), bar_height, 4.0);
                    let _ = cr.fill();
                }
                
                // Draw value
                cr.set_source_rgba(
                    text_color.red() as f64,
                    text_color.green() as f64,
                    text_color.blue() as f64,
                    0.7,
                );
                cr.set_font_size(10.0);
                let value_str = Self::format_count(entry.value as u64);
                cr.move_to(width - value_width, y + bar_height / 2.0 + 4.0);
                let _ = cr.show_text(&value_str);
            }
        }
    }

    impl BarChart {
        /// Draw a rounded rectangle.
        fn rounded_rect(cr: &gtk4::cairo::Context, x: f64, y: f64, w: f64, h: f64, r: f64) {
            let r = r.min(w / 2.0).min(h / 2.0);
            cr.new_path();
            cr.arc(x + r, y + r, r, std::f64::consts::PI, 1.5 * std::f64::consts::PI);
            cr.arc(x + w - r, y + r, r, 1.5 * std::f64::consts::PI, 2.0 * std::f64::consts::PI);
            cr.arc(x + w - r, y + h - r, r, 0.0, 0.5 * std::f64::consts::PI);
            cr.arc(x + r, y + h - r, r, 0.5 * std::f64::consts::PI, std::f64::consts::PI);
            cr.close_path();
        }

        /// Format a count for display.
        fn format_count(count: u64) -> String {
            if count >= 1_000_000 {
                format!("{:.1}M", count as f64 / 1_000_000.0)
            } else if count >= 1_000 {
                format!("{:.1}K", count as f64 / 1_000.0)
            } else {
                count.to_string()
            }
        }
    }
}
