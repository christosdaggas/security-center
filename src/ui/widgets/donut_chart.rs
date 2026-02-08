// Security Center - Donut Chart Widget
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: MIT

//! Animated donut chart for displaying ratios.

use std::cell::Cell;
use std::f64::consts::PI;

use gtk4::prelude::*;
use gtk4::subclass::prelude::*;
use gtk4::{gdk, glib, graphene};

glib::wrapper! {
    /// A donut chart widget showing accepted vs blocked traffic ratio.
    pub struct DonutChart(ObjectSubclass<imp::DonutChart>)
        @extends gtk4::Widget;
}

impl DonutChart {
    /// Create a new donut chart.
    pub fn new() -> Self {
        glib::Object::new()
    }

    /// Set the data for the chart (accepted and blocked counts).
    pub fn set_data(&self, accepted: f64, blocked: f64) {
        let total = accepted + blocked;
        let ratio = if total > 0.0 { accepted / total } else { 1.0 };
        
        self.set_ratio(ratio);
        
        // Update center text
        let percent = (ratio * 100.0).round() as i32;
        self.set_center_text(&format!("{}%", percent), "Allowed");
    }

    /// Set the accepted ratio (0.0 to 1.0).
    pub fn set_ratio(&self, accepted: f64) {
        let imp = self.imp();
        let accepted = accepted.clamp(0.0, 1.0);
        
        imp.target_ratio.set(accepted);
        
        // Start animation if not already running
        if !imp.animating.get() {
            self.start_animation();
        }
    }

    /// Set the center text.
    pub fn set_center_text(&self, primary: &str, secondary: &str) {
        let imp = self.imp();
        imp.primary_text.replace(primary.to_string());
        imp.secondary_text.replace(secondary.to_string());
        self.queue_draw();
    }

    /// Start the animation.
    fn start_animation(&self) {
        let imp = self.imp();
        imp.animating.set(true);
        
        let widget = self.clone();
        self.add_tick_callback(move |_, _clock| {
            let imp = widget.imp();
            
            let current = imp.current_ratio.get();
            let target = imp.target_ratio.get();
            
            // Ease-out interpolation
            let diff = target - current;
            if diff.abs() < 0.001 {
                imp.current_ratio.set(target);
                imp.animating.set(false);
                widget.queue_draw();
                return glib::ControlFlow::Break;
            }
            
            // Smooth interpolation (ease-out)
            let new_ratio = current + diff * 0.15;
            imp.current_ratio.set(new_ratio);
            widget.queue_draw();
            
            glib::ControlFlow::Continue
        });
    }
}

impl Default for DonutChart {
    fn default() -> Self {
        Self::new()
    }
}

mod imp {
    use super::*;
    use std::cell::RefCell;

    #[derive(Default)]
    pub struct DonutChart {
        pub current_ratio: Cell<f64>,
        pub target_ratio: Cell<f64>,
        pub animating: Cell<bool>,
        pub primary_text: RefCell<String>,
        pub secondary_text: RefCell<String>,
    }

    #[glib::object_subclass]
    impl ObjectSubclass for DonutChart {
        const NAME: &'static str = "SecurityCenterDonutChart";
        type Type = super::DonutChart;
        type ParentType = gtk4::Widget;
    }

    impl ObjectImpl for DonutChart {
        fn constructed(&self) {
            self.parent_constructed();
            
            let obj = self.obj();
            obj.set_width_request(160);
            obj.set_height_request(160);
            
            // Default values
            self.current_ratio.set(1.0);
            self.target_ratio.set(1.0);
            self.primary_text.replace("100%".to_string());
            self.secondary_text.replace("Allowed".to_string());
        }
    }

    impl WidgetImpl for DonutChart {
        fn snapshot(&self, snapshot: &gtk4::Snapshot) {
            let widget = self.obj();
            let width = widget.width() as f64;
            let height = widget.height() as f64;
            
            let cx = width / 2.0;
            let cy = height / 2.0;
            let radius = (width.min(height) / 2.0) - 10.0;
            let thickness = 16.0;
            let _inner_radius = radius - thickness;
            
            let ratio = self.current_ratio.get();
            
            // Get colors - use hardcoded theme-aware colors
            let accent_bg = gdk::RGBA::new(0.2, 0.52, 0.89, 1.0);  // Blue accent
            let error_color = gdk::RGBA::new(0.87, 0.18, 0.26, 1.0);  // Red error
            let dim_color = gdk::RGBA::new(0.5, 0.5, 0.5, 0.3);
            
            // Create a Cairo context
            let bounds = graphene::Rect::new(0.0, 0.0, width as f32, height as f32);
            let cr = snapshot.append_cairo(&bounds);
            
            // Draw background arc (full circle)
            cr.set_source_rgba(
                dim_color.red() as f64,
                dim_color.green() as f64,
                dim_color.blue() as f64,
                dim_color.alpha() as f64,
            );
            cr.set_line_width(thickness);
            cr.arc(cx, cy, radius - thickness / 2.0, 0.0, 2.0 * PI);
            let _ = cr.stroke();
            
            // Draw accepted arc (green/accent)
            if ratio > 0.0 {
                cr.set_source_rgba(
                    accent_bg.red() as f64,
                    accent_bg.green() as f64,
                    accent_bg.blue() as f64,
                    accent_bg.alpha() as f64,
                );
                cr.set_line_width(thickness);
                cr.set_line_cap(gtk4::cairo::LineCap::Round);
                
                let start_angle = -PI / 2.0;
                let end_angle = start_angle + (ratio * 2.0 * PI);
                cr.arc(cx, cy, radius - thickness / 2.0, start_angle, end_angle);
                let _ = cr.stroke();
            }
            
            // Draw blocked arc (red) if there's blocked traffic
            if ratio < 1.0 {
                cr.set_source_rgba(
                    error_color.red() as f64,
                    error_color.green() as f64,
                    error_color.blue() as f64,
                    error_color.alpha() as f64,
                );
                cr.set_line_width(thickness);
                cr.set_line_cap(gtk4::cairo::LineCap::Round);
                
                let start_angle = -PI / 2.0 + (ratio * 2.0 * PI);
                let end_angle = -PI / 2.0 + (2.0 * PI);
                cr.arc(cx, cy, radius - thickness / 2.0, start_angle, end_angle);
                let _ = cr.stroke();
            }
            
            // Draw center text
            let primary = self.primary_text.borrow();
            let secondary = self.secondary_text.borrow();
            
            // Get text color from widget (GTK 4.10+)
            let text_color = widget.color();
            
            cr.set_source_rgba(
                text_color.red() as f64,
                text_color.green() as f64,
                text_color.blue() as f64,
                text_color.alpha() as f64,
            );
            
            // Primary text (percentage)
            cr.select_font_face("Sans", gtk4::cairo::FontSlant::Normal, gtk4::cairo::FontWeight::Bold);
            cr.set_font_size(24.0);
            let extents = cr.text_extents(&primary).unwrap_or_else(|_| gtk4::cairo::TextExtents::new(0.0, 0.0, 0.0, 0.0, 0.0, 0.0));
            cr.move_to(cx - extents.width() / 2.0, cy);
            let _ = cr.show_text(&primary);
            
            // Secondary text (label)
            cr.select_font_face("Sans", gtk4::cairo::FontSlant::Normal, gtk4::cairo::FontWeight::Normal);
            cr.set_font_size(12.0);
            cr.set_source_rgba(
                text_color.red() as f64,
                text_color.green() as f64,
                text_color.blue() as f64,
                0.7,
            );
            let extents = cr.text_extents(&secondary).unwrap_or_else(|_| gtk4::cairo::TextExtents::new(0.0, 0.0, 0.0, 0.0, 0.0, 0.0));
            cr.move_to(cx - extents.width() / 2.0, cy + 18.0);
            let _ = cr.show_text(&secondary);
        }
    }
}
