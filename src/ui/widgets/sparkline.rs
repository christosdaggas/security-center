// Security Center - Sparkline Widget
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: MIT

//! A tiny inline area chart for per-app activity, drawn with Cairo and
//! theme-aware colors.

use std::cell::RefCell;

use gtk4::prelude::*;
use gtk4::subclass::prelude::*;
use gtk4::{glib, graphene};
use libadwaita as adw;

glib::wrapper! {
    /// A minimal sparkline (filled area line) for a short value series.
    pub struct Sparkline(ObjectSubclass<imp::Sparkline>)
        @extends gtk4::Widget;
}

impl Sparkline {
    pub fn new() -> Self {
        glib::Object::new()
    }

    /// Replace the plotted series.
    pub fn set_values(&self, values: &[f64]) {
        *self.imp().values.borrow_mut() = values.to_vec();
        self.queue_draw();
    }
}

impl Default for Sparkline {
    fn default() -> Self {
        Self::new()
    }
}

mod imp {
    use super::*;

    #[derive(Default)]
    pub struct Sparkline {
        pub values: RefCell<Vec<f64>>,
    }

    #[glib::object_subclass]
    impl ObjectSubclass for Sparkline {
        const NAME: &'static str = "SecurityCenterSparkline";
        type Type = super::Sparkline;
        type ParentType = gtk4::Widget;
    }

    impl ObjectImpl for Sparkline {
        fn constructed(&self) {
            self.parent_constructed();
            self.obj().set_height_request(24);
        }
    }

    impl WidgetImpl for Sparkline {
        fn snapshot(&self, snapshot: &gtk4::Snapshot) {
            let widget = self.obj();
            let width = widget.width() as f64;
            let height = widget.height() as f64;
            if width <= 0.0 || height <= 0.0 {
                return;
            }

            let values = self.values.borrow();
            if values.len() < 2 {
                return;
            }

            // If the series has no real activity, draw nothing rather than a
            // flat baseline that reads as a broken underline.
            let true_max = values.iter().cloned().fold(0.0_f64, f64::max);
            if true_max <= f64::EPSILON {
                return;
            }

            let bounds = graphene::Rect::new(0.0, 0.0, width as f32, height as f32);
            let cr = snapshot.append_cairo(&bounds);

            // Accent-ish blue that reads on both themes
            let is_dark = adw::StyleManager::default().is_dark();
            let (r, g, b) = if is_dark {
                (0.45, 0.62, 0.95)
            } else {
                (0.21, 0.52, 0.89)
            };

            let max = true_max.max(1.0);
            let step = width / (values.len() as f64 - 1.0);
            let pad = 2.0;
            let plot_h = (height - pad * 2.0).max(1.0);

            let y_at = |v: f64| height - pad - (v / max) * plot_h;

            // Filled area
            cr.set_source_rgba(r, g, b, 0.18);
            cr.move_to(0.0, height);
            for (i, &v) in values.iter().enumerate() {
                cr.line_to(i as f64 * step, y_at(v));
            }
            cr.line_to(width, height);
            cr.close_path();
            let _ = cr.fill();

            // Line
            cr.set_source_rgba(r, g, b, 0.9);
            cr.set_line_width(1.5);
            for (i, &v) in values.iter().enumerate() {
                let x = i as f64 * step;
                let y = y_at(v);
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
