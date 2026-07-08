// Security Center - Donut Chart Widget
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: MIT

//! A segmented donut (ring) chart drawn with Cairo, theme-aware, used on the
//! overview page for the connection-state breakdown.

use std::cell::RefCell;
use std::f64::consts::PI;

use gtk4::prelude::*;
use gtk4::subclass::prelude::*;
use gtk4::{glib, graphene};
use libadwaita as adw;

/// One ring segment: a value and its fill color as linear RGB in `0.0..=1.0`.
pub type DonutSegment = (f64, (f64, f64, f64));

glib::wrapper! {
    /// A donut chart plotting proportional segments around a ring.
    pub struct DonutChart(ObjectSubclass<imp::DonutChart>)
        @extends gtk4::Widget;
}

impl DonutChart {
    pub fn new() -> Self {
        glib::Object::new()
    }

    /// Replace the plotted segments (value, rgb). Zero-value segments are skipped.
    pub fn set_segments(&self, segments: &[DonutSegment]) {
        *self.imp().segments.borrow_mut() = segments.to_vec();
        self.queue_draw();
    }
}

impl Default for DonutChart {
    fn default() -> Self {
        Self::new()
    }
}

mod imp {
    use super::*;

    #[derive(Default)]
    pub struct DonutChart {
        pub segments: RefCell<Vec<DonutSegment>>,
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
            self.obj().set_size_request(132, 132);
        }
    }

    impl WidgetImpl for DonutChart {
        fn snapshot(&self, snapshot: &gtk4::Snapshot) {
            let widget = self.obj();
            let w = widget.width() as f64;
            let h = widget.height() as f64;
            if w <= 0.0 || h <= 0.0 {
                return;
            }

            let bounds = graphene::Rect::new(0.0, 0.0, w as f32, h as f32);
            let cr = snapshot.append_cairo(&bounds);

            let cx = w / 2.0;
            let cy = h / 2.0;
            let thickness = 16.0_f64.min(w.min(h) / 5.0);
            let radius = (w.min(h) / 2.0) - thickness / 2.0 - 2.0;
            if radius <= 0.0 {
                return;
            }

            let is_dark = adw::StyleManager::default().is_dark();

            // Background track ring.
            cr.set_line_width(thickness);
            let track_a = if is_dark { 0.12 } else { 0.08 };
            let track_v = if is_dark { 1.0 } else { 0.0 };
            cr.set_source_rgba(track_v, track_v, track_v, track_a);
            cr.arc(cx, cy, radius, 0.0, 2.0 * PI);
            let _ = cr.stroke();

            let segments = self.segments.borrow();
            let total: f64 = segments.iter().map(|(v, _)| *v).sum();
            if total <= 0.0 {
                return;
            }

            // Draw each segment clockwise from the top (12 o'clock).
            let mut start = -PI / 2.0;
            for (v, (r, g, b)) in segments.iter() {
                if *v <= 0.0 {
                    continue;
                }
                let sweep = (v / total) * 2.0 * PI;
                cr.set_source_rgb(*r, *g, *b);
                cr.arc(cx, cy, radius, start, start + sweep);
                let _ = cr.stroke();
                start += sweep;
            }
        }
    }
}
