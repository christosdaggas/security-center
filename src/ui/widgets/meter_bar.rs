// Security Center - Meter Bar Widget
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: MIT

//! A thin rounded horizontal fraction bar drawn with Cairo, used for the
//! protocol and country breakdowns on the overview page. Colour is caller-set;
//! the track adapts to the light/dark theme.

use std::cell::{Cell, RefCell};

use gtk4::prelude::*;
use gtk4::subclass::prelude::*;
use gtk4::{glib, graphene};
use libadwaita as adw;

glib::wrapper! {
    /// A single rounded progress/meter bar with a caller-defined fill colour.
    pub struct MeterBar(ObjectSubclass<imp::MeterBar>)
        @extends gtk4::Widget;
}

impl MeterBar {
    pub fn new() -> Self {
        glib::Object::new()
    }

    /// Set the filled fraction, clamped to `0.0..=1.0`.
    pub fn set_fraction(&self, fraction: f64) {
        self.imp().fraction.set(fraction.clamp(0.0, 1.0));
        self.queue_draw();
    }

    /// Set the fill colour as linear RGB in `0.0..=1.0`.
    pub fn set_color(&self, r: f64, g: f64, b: f64) {
        *self.imp().color.borrow_mut() = (r, g, b);
        self.queue_draw();
    }
}

impl Default for MeterBar {
    fn default() -> Self {
        Self::new()
    }
}

mod imp {
    use super::*;

    pub struct MeterBar {
        pub fraction: Cell<f64>,
        pub color: RefCell<(f64, f64, f64)>,
    }

    impl Default for MeterBar {
        fn default() -> Self {
            Self {
                fraction: Cell::new(0.0),
                color: RefCell::new((0.21, 0.52, 0.89)),
            }
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for MeterBar {
        const NAME: &'static str = "SecurityCenterMeterBar";
        type Type = super::MeterBar;
        type ParentType = gtk4::Widget;
    }

    impl ObjectImpl for MeterBar {
        fn constructed(&self) {
            self.parent_constructed();
            self.obj().set_height_request(8);
            self.obj().set_hexpand(true);
        }
    }

    impl WidgetImpl for MeterBar {
        fn snapshot(&self, snapshot: &gtk4::Snapshot) {
            let widget = self.obj();
            let w = widget.width() as f64;
            let h = widget.height() as f64;
            if w <= 0.0 || h <= 0.0 {
                return;
            }

            let bounds = graphene::Rect::new(0.0, 0.0, w as f32, h as f32);
            let cr = snapshot.append_cairo(&bounds);
            let radius = h / 2.0;

            let is_dark = adw::StyleManager::default().is_dark();
            let track_v = if is_dark { 1.0 } else { 0.0 };
            let track_a = if is_dark { 0.10 } else { 0.07 };

            // Track.
            rounded_rect(&cr, 0.0, 0.0, w, h, radius);
            cr.set_source_rgba(track_v, track_v, track_v, track_a);
            let _ = cr.fill();

            // Fill (at least a dot's worth when non-zero so tiny shares stay visible).
            let frac = self.fraction.get();
            if frac > 0.0 {
                let fw = (w * frac).max(h);
                let (r, g, b) = *self.color.borrow();
                rounded_rect(&cr, 0.0, 0.0, fw, h, radius);
                cr.set_source_rgb(r, g, b);
                let _ = cr.fill();
            }
        }
    }

    fn rounded_rect(cr: &gtk4::cairo::Context, x: f64, y: f64, w: f64, h: f64, r: f64) {
        use std::f64::consts::PI;
        let r = r.min(w / 2.0).min(h / 2.0);
        cr.new_sub_path();
        cr.arc(x + w - r, y + r, r, -PI / 2.0, 0.0);
        cr.arc(x + w - r, y + h - r, r, 0.0, PI / 2.0);
        cr.arc(x + r, y + h - r, r, PI / 2.0, PI);
        cr.arc(x + r, y + r, r, PI, 1.5 * PI);
        cr.close_path();
    }
}
