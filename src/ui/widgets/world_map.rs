// Security Center - World Map Widget
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: MIT

//! A choropleth world map drawn with Cairo: country polygons (Natural Earth,
//! via the `world-data` crate) filled by live per-country session counts.
//! Countries with no traffic render as a dark base; busier countries glow
//! with the accent colour. Fully offline — no tiles, no network.

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::OnceLock;

use gtk4::prelude::*;
use gtk4::subclass::prelude::*;
use gtk4::{glib, graphene};
use libadwaita as adw;

glib::wrapper! {
    /// A world map coloured by per-country (ISO-A2) session counts.
    pub struct WorldMap(ObjectSubclass<imp::WorldMap>)
        @extends gtk4::Widget;
}

type WorldData = world_data::world_data_types::data::WorldData;

/// Decompressed country polygons, loaded exactly once (a few MB of bincode).
static WORLD: OnceLock<WorldData> = OnceLock::new();

fn world() -> &'static WorldData {
    WORLD.get_or_init(|| {
        let t0 = std::time::Instant::now();
        let data = world_data::load();
        let polys: usize = data.countries.values().map(|c| c.polygons.len()).sum();
        tracing::debug!(
            "WorldMap: loaded {} countries ({} polygons) in {:?}",
            data.countries.len(),
            polys,
            t0.elapsed()
        );
        data
    })
}

/// English display name for an ISO-A2 code, e.g. "United States".
pub fn country_name(iso: &str) -> Option<String> {
    world()
        .countries
        .get(&iso.to_uppercase())
        .map(|c| c.common_name.clone())
}

impl WorldMap {
    pub fn new() -> Self {
        glib::Object::new()
    }

    /// Replace the per-country session counts (keys: ISO-A2, any case).
    pub fn set_country_counts(&self, counts: &HashMap<String, usize>) {
        let norm: HashMap<String, usize> =
            counts.iter().map(|(k, v)| (k.to_uppercase(), *v)).collect();
        *self.imp().counts.borrow_mut() = norm;
        self.queue_draw();
    }
}

impl Default for WorldMap {
    fn default() -> Self {
        Self::new()
    }
}

/// Equirectangular projection: lon [-180,180] -> x, lat [90,-90] -> y.
fn project(lon: f64, lat: f64, ox: f64, oy: f64, scale: f64) -> (f64, f64) {
    (ox + (lon + 180.0) * scale, oy + (90.0 - lat) * scale)
}

/// Append one ring to `cr`, breaking the subpath wherever the ring jumps
/// across the antimeridian so Russia/Fiji/Alaska don't smear a streak
/// across the whole map.
fn trace_ring(cr: &gtk4::cairo::Context, ring: &[(f64, f64)], ox: f64, oy: f64, scale: f64) {
    let mut prev_lon: Option<f64> = None;
    let mut open = false;
    for &(lon, lat) in ring {
        let jump = prev_lon.map(|p| (lon - p).abs() > 180.0).unwrap_or(false);
        let (x, y) = project(lon, lat, ox, oy, scale);
        if !open || jump {
            if open {
                cr.close_path();
            }
            cr.move_to(x, y);
            open = true;
        } else {
            cr.line_to(x, y);
        }
        prev_lon = Some(lon);
    }
    if open {
        cr.close_path();
    }
}

mod imp {
    use super::*;

    #[derive(Default)]
    pub struct WorldMap {
        pub counts: RefCell<HashMap<String, usize>>,
    }

    #[glib::object_subclass]
    impl ObjectSubclass for WorldMap {
        const NAME: &'static str = "SecurityCenterWorldMap";
        type Type = super::WorldMap;
        type ParentType = gtk4::Widget;
    }

    impl ObjectImpl for WorldMap {
        fn constructed(&self) {
            self.parent_constructed();
            // Wide 2:1 canvas (~65% of the card); the table takes ~35%.
            // Kept short on purpose: the right column drives the row height
            // and the map stretches to match it.
            self.obj().set_size_request(380, 300);
            self.obj().set_hexpand(true);
        }
    }

    impl WidgetImpl for WorldMap {
        fn snapshot(&self, snapshot: &gtk4::Snapshot) {
            let widget = self.obj();
            let w = widget.width() as f64;
            let h = widget.height() as f64;
            if w <= 0.0 || h <= 0.0 {
                return;
            }

            let bounds = graphene::Rect::new(0.0, 0.0, w as f32, h as f32);
            let cr = snapshot.append_cairo(&bounds);

            // Letterbox the 2:1 map into the allocation.
            let scale = (w / 360.0).min(h / 180.0);
            let ox = (w - 360.0 * scale) / 2.0;
            let oy = (h - 180.0 * scale) / 2.0;

            let is_dark = adw::StyleManager::default().is_dark();
            let counts = self.counts.borrow();
            let max = counts.values().copied().max().unwrap_or(0).max(1) as f64;

            // Accent-ish blue matching the app's charts.
            let (ar, ag, ab) = if is_dark {
                (0.45, 0.62, 0.95)
            } else {
                (0.21, 0.52, 0.89)
            };

            cr.set_fill_rule(gtk4::cairo::FillRule::EvenOdd);
            for country in world().countries.values() {
                let n = counts
                    .get(&country.iso_a2.to_uppercase())
                    .copied()
                    .unwrap_or(0) as f64;
                if n > 0.0 {
                    // Square-root scale: a single busy country shouldn't
                    // wash out the rest of the map.
                    let t = (n / max).sqrt();
                    cr.set_source_rgba(ar, ag, ab, 0.25 + 0.70 * t);
                } else if is_dark {
                    cr.set_source_rgba(1.0, 1.0, 1.0, 0.09);
                } else {
                    cr.set_source_rgba(0.0, 0.0, 0.0, 0.10);
                }
                for poly in &country.polygons {
                    let ext: Vec<(f64, f64)> = poly
                        .exterior()
                        .0
                        .iter()
                        .map(|c| (c.x as f64, c.y as f64))
                        .collect();
                    trace_ring(&cr, &ext, ox, oy, scale);
                    for hole in poly.interiors() {
                        let ring: Vec<(f64, f64)> =
                            hole.0.iter().map(|c| (c.x as f64, c.y as f64)).collect();
                        trace_ring(&cr, &ring, ox, oy, scale);
                    }
                }
                let _ = cr.fill_preserve();
                // Soft hairline borders — just enough for definition.
                if is_dark {
                    cr.set_source_rgba(0.0, 0.0, 0.0, 0.22);
                } else {
                    cr.set_source_rgba(1.0, 1.0, 1.0, 0.4);
                }
                cr.set_line_width(0.5);
                let _ = cr.stroke();
            }
        }
    }
}
