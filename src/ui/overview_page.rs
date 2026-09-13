// Security Center - Overview Page
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: MIT

//! Overview dashboard page: slim status hero, 4 KPIs, regional and traffic
//! insights, and a responsive live-connections table.

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};

use gtk4::glib;
use gtk4::prelude::*;
use gtk4::subclass::prelude::*;

use super::app_icons::{display_process_name, icon_for_process, protocol_of};
use super::widgets::{
    country_name, list_interfaces, MeterBar, NetworkActivityChart, Sparkline, WorldMap,
};
use crate::admin::is_local_ip;
use crate::i18n::gettext;
use crate::models::Zone;

/// How often the live connection dashboard refreshes.
const REFRESH_SECS: u32 = 5;
const INTERVAL_SECS: f64 = REFRESH_SECS as f64;
const DEFAULT_CONNECTION_CARDS: usize = 4;
const DEFAULT_WINDOW_HEIGHT: i32 = 880;
const CONNECTION_CARD_ROW_HEIGHT: i32 = 98;
const CONNECTION_CARDS_PER_ROW: usize = 2;

fn connection_card_limit(maximized: bool, window_height: i32) -> usize {
    if !maximized {
        return DEFAULT_CONNECTION_CARDS;
    }

    let extra_height = window_height.saturating_sub(DEFAULT_WINDOW_HEIGHT);
    DEFAULT_CONNECTION_CARDS
        + (extra_height / CONNECTION_CARD_ROW_HEIGHT).max(0) as usize * CONNECTION_CARDS_PER_ROW
}

/// Represents the overall firewall state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallState {
    /// Firewall is running, traffic flows through rules normally.
    Active,
    /// Firewall is running but panic mode is on — all traffic is blocked.
    PanicMode,
    /// Firewall service is stopped — traffic flows freely, unfiltered.
    Stopped,
}

glib::wrapper! {
    /// Overview page showing firewall status.
    pub struct OverviewPage(ObjectSubclass<imp::OverviewPage>)
        @extends gtk4::Box, gtk4::Widget,
        @implements gtk4::Orientable;
}

impl OverviewPage {
    /// Create a new overview page.
    pub fn new() -> Self {
        let page: Self = glib::Object::new();
        page.setup_ui();
        page
    }

    /// Get the traffic switch widget.
    pub fn traffic_switch(&self) -> Option<gtk4::Switch> {
        self.imp().traffic_switch.borrow().clone()
    }

    /// Update the traffic status display.
    /// `enabled` = true means firewall is active and traffic is flowing normally.
    pub fn set_traffic_enabled(&self, enabled: bool) {
        if enabled {
            self.set_firewall_state(FirewallState::Active);
        } else {
            self.set_firewall_state(FirewallState::PanicMode);
        }
    }

    /// Update the full firewall state display.
    pub fn set_firewall_state(&self, state: FirewallState) {
        let imp = self.imp();

        match state {
            FirewallState::Active => {
                if let Some(switch) = imp.traffic_switch.borrow().as_ref() {
                    switch.set_active(true);
                    switch.set_sensitive(true);
                }
                if let Some(label) = imp.traffic_label.borrow().as_ref() {
                    label.set_label(&gettext("Traffic Enabled"));
                    label.remove_css_class("error");
                    label.remove_css_class("warning");
                    label.add_css_class("success");
                }
                if let Some(icon) = imp.status_icon.borrow().as_ref() {
                    icon.set_icon_name(Some("security-high-symbolic"));
                    icon.remove_css_class("error");
                    icon.remove_css_class("warning");
                    icon.add_css_class("success");
                }
                if let Some(title) = imp.status_title.borrow().as_ref() {
                    title.set_label(&gettext("Firewall Active"));
                }
                if let Some(subtitle) = imp.status_subtitle.borrow().as_ref() {
                    subtitle.set_label(&gettext("Your system is protected"));
                }
            }
            FirewallState::PanicMode => {
                if let Some(switch) = imp.traffic_switch.borrow().as_ref() {
                    switch.set_active(false);
                    switch.set_sensitive(true);
                }
                if let Some(label) = imp.traffic_label.borrow().as_ref() {
                    label.set_label(&gettext("Traffic Blocked"));
                    label.remove_css_class("success");
                    label.remove_css_class("warning");
                    label.add_css_class("error");
                }
                if let Some(icon) = imp.status_icon.borrow().as_ref() {
                    icon.set_icon_name(Some("security-low-symbolic"));
                    icon.remove_css_class("success");
                    icon.remove_css_class("warning");
                    icon.add_css_class("error");
                }
                if let Some(title) = imp.status_title.borrow().as_ref() {
                    title.set_label(&gettext("Panic Mode"));
                }
                if let Some(subtitle) = imp.status_subtitle.borrow().as_ref() {
                    subtitle.set_label(&gettext("All network traffic is blocked"));
                }
            }
            FirewallState::Stopped => {
                if let Some(switch) = imp.traffic_switch.borrow().as_ref() {
                    switch.set_active(true);
                    switch.set_sensitive(false);
                }
                if let Some(label) = imp.traffic_label.borrow().as_ref() {
                    label.set_label(&gettext("Traffic Enabled"));
                    label.remove_css_class("error");
                    label.remove_css_class("success");
                    label.add_css_class("warning");
                }
                if let Some(icon) = imp.status_icon.borrow().as_ref() {
                    icon.set_icon_name(Some("security-low-symbolic"));
                    icon.remove_css_class("success");
                    icon.remove_css_class("error");
                    icon.add_css_class("warning");
                }
                if let Some(title) = imp.status_title.borrow().as_ref() {
                    title.set_label(&gettext("Firewall Inactive"));
                }
                if let Some(subtitle) = imp.status_subtitle.borrow().as_ref() {
                    subtitle.set_label(&gettext("Firewall is stopped — traffic is unfiltered"));
                }
            }
        }

        // Keep the System Status stat pill in sync with the firewall state.
        let (pill_text, pill_class) = match state {
            FirewallState::Active => (gettext("Protected"), "pill-ok"),
            FirewallState::PanicMode => (gettext("Locked"), "pill-err"),
            FirewallState::Stopped => (gettext("Unprotected"), "pill-warn"),
        };
        if let Some(label) = imp.stat_status.borrow().as_ref() {
            label.set_label(&pill_text);
            for c in ["pill-ok", "pill-warn", "pill-err"] {
                label.remove_css_class(c);
            }
            label.add_css_class(pill_class);
        }
    }

    /// Setup the UI.
    fn setup_ui(&self) {
        self.set_orientation(gtk4::Orientation::Vertical);
        self.set_spacing(0);

        // Make Flatpak-exported application icons resolvable by name.
        super::app_icons::register_flatpak_icon_paths();

        self.imp().connection_cards.set(DEFAULT_CONNECTION_CARDS);

        let scrolled = gtk4::ScrolledWindow::builder()
            .hscrollbar_policy(gtk4::PolicyType::Never)
            .vscrollbar_policy(gtk4::PolicyType::Automatic)
            .vexpand(true)
            .hexpand(true)
            .build();

        let content = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Vertical)
            .spacing(16)
            .margin_top(16)
            .margin_bottom(24)
            .margin_start(20)
            .margin_end(20)
            .hexpand(true)
            .build();

        // Hero first, then KPIs, then the 2:1 main grid (connections + insights).
        content.append(&self.build_status_card());
        content.append(&self.build_stat_cards());
        content.append(&self.build_main_grid());

        // Honour the saved "show connections overview" preference.
        self.set_connections_visible(crate::config::Settings::new().show_connections_overview());

        scrolled.set_child(Some(&content));
        self.append(&scrolled);

        // Kick off the live connection dashboard.
        let page = self.clone();
        glib::timeout_add_seconds_local_once(2, move || {
            page.refresh_connected_hosts();
        });
        let page = self.clone();
        glib::timeout_add_seconds_local(REFRESH_SECS, move || {
            page.refresh_connected_hosts();
            glib::ControlFlow::Continue
        });
    }

    /// Slim hero status bar (icon + title + zone pill + restart + traffic).
    fn build_status_card(&self) -> gtk4::Frame {
        let imp = self.imp();

        let status_frame = gtk4::Frame::new(None);
        status_frame.add_css_class("card");

        let status_box = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .spacing(12)
            .margin_top(12)
            .margin_bottom(12)
            .margin_start(16)
            .margin_end(16)
            .build();

        let status_icon = gtk4::Image::builder()
            .icon_name("security-high-symbolic")
            .pixel_size(36)
            .css_classes(vec!["success".to_string()])
            .build();
        imp.status_icon.replace(Some(status_icon.clone()));

        let status_text = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Vertical)
            .spacing(2)
            .valign(gtk4::Align::Center)
            .hexpand(true)
            .build();

        let status_title = gtk4::Label::builder()
            .label(gettext("Firewall Active"))
            .css_classes(vec!["title-2".to_string()])
            .halign(gtk4::Align::Start)
            .build();
        imp.status_title.replace(Some(status_title.clone()));

        let status_subtitle = gtk4::Label::builder()
            .label(gettext("Your system is protected"))
            .css_classes(vec!["dim-label".to_string()])
            .halign(gtk4::Align::Start)
            .build();
        imp.status_subtitle.replace(Some(status_subtitle.clone()));

        status_text.append(&status_title);
        status_text.append(&status_subtitle);
        status_box.append(&status_icon);
        status_box.append(&status_text);

        // Right-hand controls: zone pill · restart icon · traffic switch.
        let toggle_box = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .spacing(12)
            .valign(gtk4::Align::Center)
            .halign(gtk4::Align::End)
            .build();

        let zone_info_box = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .spacing(8)
            .valign(gtk4::Align::Center)
            .build();
        let zone_icon = gtk4::Image::builder()
            .icon_name("security-medium-symbolic")
            .css_classes(vec!["dim-label".to_string()])
            .build();
        zone_info_box.append(&zone_icon);
        let zone_name_label = gtk4::Label::builder()
            .label("public")
            .css_classes(vec!["caption".to_string(), "zone-pill".to_string()])
            .build();
        imp.default_zone_label
            .replace(Some(zone_name_label.clone()));
        zone_info_box.append(&zone_name_label);
        toggle_box.append(&zone_info_box);

        toggle_box.append(&gtk4::Separator::new(gtk4::Orientation::Vertical));

        // Restart firewall button (icon-only to save vertical space).
        let restart_box = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Vertical)
            .spacing(2)
            .valign(gtk4::Align::Center)
            .build();
        let restart_button = gtk4::Button::builder()
            .icon_name("view-refresh-symbolic")
            .tooltip_text(gettext("Reload firewall rules"))
            .css_classes(vec!["circular".to_string(), "flat".to_string()])
            .valign(gtk4::Align::Center)
            .halign(gtk4::Align::Center)
            .build();
        restart_button.connect_clicked(move |button| {
            button.set_sensitive(false);
            let btn = button.clone();
            glib::spawn_future_local(async move {
                let result = gtk4::gio::spawn_blocking(move || {
                    let mut client = crate::firewall::FirewallClient::new();
                    if let Err(e) = client.connect() {
                        return Err(format!("Not connected to firewalld: {}", e));
                    }
                    client.reload().map_err(|e| e.to_string())
                })
                .await;

                btn.set_sensitive(true);

                if let Some(root) = btn.root() {
                    if let Some(window) = root.downcast_ref::<gtk4::Window>() {
                        if let Some(main_window) = window.downcast_ref::<super::MainWindow>() {
                            match result {
                                Ok(Ok(())) => {
                                    main_window
                                        .show_toast(&gettext("Firewall reloaded successfully"));
                                    main_window.refresh_data();
                                }
                                Ok(Err(e)) => {
                                    main_window.show_toast(&format!(
                                        "{}: {}",
                                        gettext("Failed to reload"),
                                        e
                                    ));
                                }
                                Err(_) => {
                                    main_window.show_toast(&gettext("Failed to reload firewall"));
                                }
                            }
                        }
                    }
                }
            });
        });
        restart_box.append(&restart_button);
        toggle_box.append(&restart_box);

        toggle_box.append(&gtk4::Separator::new(gtk4::Orientation::Vertical));

        // Traffic switch.
        let switch_box = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Vertical)
            .spacing(4)
            .valign(gtk4::Align::Center)
            .build();
        let traffic_switch = gtk4::Switch::builder()
            .active(true)
            .valign(gtk4::Align::Center)
            .halign(gtk4::Align::Center)
            .build();
        imp.traffic_switch.replace(Some(traffic_switch.clone()));
        let toggle_label = gtk4::Label::builder()
            .label(gettext("Traffic Enabled"))
            .css_classes(vec!["caption".to_string(), "success".to_string()])
            .halign(gtk4::Align::Center)
            .build();
        imp.traffic_label.replace(Some(toggle_label.clone()));
        switch_box.append(&traffic_switch);
        switch_box.append(&toggle_label);
        toggle_box.append(&switch_box);

        status_box.append(&toggle_box);
        status_frame.set_child(Some(&status_box));
        status_frame
    }

    /// Three KPI cards in one row, Firewalla style: small label on top,
    /// big number below. Homogeneous is safe here — all children are
    /// small, equally-sized cards with no wide separators involved.
    fn build_stat_cards(&self) -> gtk4::Box {
        let imp = self.imp();

        let row = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .spacing(12)
            .homogeneous(true)
            .hexpand(true)
            .build();

        let (active_card, active_val) = stat_card(
            "network-transmit-receive-symbolic",
            "accent",
            &gettext("Active Sessions"),
        );
        imp.metric_active.replace(Some(active_val));
        row.append(&active_card);

        let (apps_card, apps_val) =
            stat_card("view-app-grid-symbolic", "purple", &gettext("Apps Online"));
        imp.metric_apps.replace(Some(apps_val));
        row.append(&apps_card);

        let (listen_card, listen_val) = stat_card(
            "network-server-symbolic",
            "success",
            &gettext("Listening Ports"),
        );
        imp.metric_listening.replace(Some(listen_val));
        row.append(&listen_card);

        let (blocked_card, blocked_val) = stat_card(
            "action-unavailable-symbolic",
            "error",
            &gettext("Blocked Ports"),
        );
        imp.metric_blocked.replace(Some(blocked_val));
        row.append(&blocked_card);

        row
    }

    /// Dashboard column: chart + side stack, connections table, top-app tables.
    /// Strictly vertical — nothing here can push siblings off-screen.
    fn build_main_grid(&self) -> gtk4::Box {
        let col = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Vertical)
            .spacing(16)
            .hexpand(true)
            .build();

        // Row: regions map (expands, left) + right stack (fixed narrow):
        // Network Activity on top, Exposure and Top Protocols below it.
        let mid = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .spacing(12)
            .hexpand(true)
            .build();
        let regions = self.build_regions_card();
        regions.set_hexpand(true);
        regions.set_halign(gtk4::Align::Fill);
        mid.append(&regions);
        let right = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Vertical)
            .spacing(12)
            .width_request(320)
            .build();
        right.append(&self.create_network_activity_card());
        right.append(&self.build_protocols_panel());
        mid.append(&right);
        col.append(&mid);

        // Live Connections last, full-width at the very bottom.
        col.append(&self.build_connections_hub());

        col
    }

    /// Regions card: live world map plus a top-countries table, Firewalla style.
    fn build_regions_card(&self) -> gtk4::Frame {
        let imp = self.imp();

        let frame = gtk4::Frame::new(None);
        frame.add_css_class("card");
        frame.set_hexpand(true);
        frame.set_halign(gtk4::Align::Fill);

        // Slim top/bottom padding so this card never outgrows the right
        // column — the row height is driven by Network + Protocols, and
        // the map simply stretches to match it.
        let outer = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Vertical)
            .spacing(4)
            .margin_top(8)
            .margin_bottom(8)
            .margin_start(18)
            .margin_end(18)
            .hexpand(true)
            .build();

        // No header: the reclaimed height goes to the map itself. The card
        // still matches the right-column height via the shared row stretch.
        let row = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .spacing(16)
            .hexpand(true)
            .build();
        let map = WorldMap::new();
        imp.world_map.replace(Some(map.clone()));
        // Right column: title on top, table below it, all top-aligned.
        let side = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Vertical)
            .spacing(8)
            .width_request(220)
            .valign(gtk4::Align::Start)
            .build();
        side.append(
            &gtk4::Label::builder()
                .label(gettext("Top Regions by Sessions"))
                .css_classes(vec!["heading".to_string()])
                .halign(gtk4::Align::Start)
                .ellipsize(gtk4::pango::EllipsizeMode::End)
                .build(),
        );
        let grid = gtk4::Grid::builder()
            .column_spacing(12)
            .row_spacing(10)
            .build();
        imp.region_grid.replace(Some(grid.clone()));
        side.append(&grid);
        // Title + table on the left, map on the right.
        row.append(&side);
        row.append(&gtk4::Separator::new(gtk4::Orientation::Vertical));
        row.append(&map);
        outer.append(&row);

        imp.regions_card.replace(Some(frame.clone()));
        frame.set_child(Some(&outer));
        frame
    }

    /// Rebuild the regions table + map colours from the ISO tally.
    fn render_regions(&self, iso_counts: &HashMap<String, usize>) {
        let imp = self.imp();
        if let Some(map) = imp.world_map.borrow().as_ref() {
            map.set_country_counts(iso_counts);
        }
        let grid_ref = imp.region_grid.borrow();
        let grid = match grid_ref.as_ref() {
            Some(g) => g,
            None => return,
        };
        while let Some(child) = grid.first_child() {
            grid.remove(&child);
        }
        if iso_counts.is_empty() {
            grid.attach(
                &gtk4::Label::builder()
                    .label(gettext("No remote connections"))
                    .css_classes(vec!["dim-label".to_string()])
                    .halign(gtk4::Align::Start)
                    .build(),
                0,
                0,
                2,
                1,
            );
            return;
        }
        let mut rows: Vec<(String, usize)> =
            iso_counts.iter().map(|(k, v)| (k.clone(), *v)).collect();
        rows.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        rows.truncate(6);
        th(grid, 0, &gettext("Region"), false);
        th(grid, 1, &gettext("Sessions"), true);
        for (i, (iso, count)) in rows.iter().enumerate() {
            let r = i as i32 + 1;
            let name = country_name(iso).unwrap_or_else(|| iso.clone());
            let label = format!("{} {}", crate::admin::flag_emoji(iso), name);
            td(grid, 0, r, &label, false, 22);
            td(grid, 1, r, &count.to_string(), true, 8);
        }
    }

    /// Firewall connections overview with a responsive two-column app grid.
    fn build_connections_hub(&self) -> gtk4::Frame {
        let imp = self.imp();

        let frame = gtk4::Frame::new(None);
        frame.add_css_class("card");
        frame.add_css_class("dashboard-card");
        frame.set_hexpand(true);
        frame.set_halign(gtk4::Align::Fill);

        let outer = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Vertical)
            .spacing(0)
            .build();

        // Header: title and subtitle on the left, live status chips on the right.
        let header = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .spacing(12)
            .margin_top(15)
            .margin_bottom(15)
            .margin_start(17)
            .margin_end(17)
            .build();

        header.append(
            &gtk4::Label::builder()
                .label(gettext("Firewall Connections Overview"))
                .css_classes(vec!["heading".to_string()])
                .halign(gtk4::Align::Start)
                .hexpand(true)
                .valign(gtk4::Align::Center)
                .build(),
        );

        let conn_chip_box = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .spacing(6)
            .css_classes(vec!["conn-chip".to_string()])
            .valign(gtk4::Align::Center)
            .build();
        conn_chip_box.append(
            &gtk4::Label::builder()
                .label("●")
                .css_classes(vec!["dot-success".to_string()])
                .build(),
        );
        let conn_chip = gtk4::Label::builder()
            .label("0 connected")
            .css_classes(vec!["caption".to_string()])
            .build();
        imp.conn_chip.replace(Some(conn_chip.clone()));
        conn_chip_box.append(&conn_chip);
        header.append(&conn_chip_box);

        header.append(
            &gtk4::Label::builder()
                .label(gettext("Updated just now"))
                .css_classes(vec!["caption".to_string(), "conn-chip".to_string()])
                .valign(gtk4::Align::Center)
                .build(),
        );
        outer.append(&header);

        let app_flow = gtk4::FlowBox::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .column_spacing(10)
            .row_spacing(10)
            .homogeneous(true)
            .min_children_per_line(2)
            .max_children_per_line(2)
            .hexpand(true)
            .selection_mode(gtk4::SelectionMode::None)
            .margin_top(14)
            .margin_bottom(14)
            .margin_start(14)
            .margin_end(14)
            .build();
        imp.app_flow.replace(Some(app_flow.clone()));
        outer.append(&app_flow);

        imp.connections_hub.replace(Some(frame.clone()));
        frame.set_child(Some(&outer));
        frame
    }

    /// Panel: top protocols as horizontal meter bars.
    fn build_protocols_panel(&self) -> gtk4::Frame {
        let imp = self.imp();
        let (frame, content) = panel_card(
            &gettext("Top Protocols"),
            &gettext("Share of active sessions"),
        );

        let list = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Vertical)
            .spacing(12)
            .build();
        placeholder(&list, &gettext("Scanning…"));
        imp.proto_box.replace(Some(list.clone()));
        content.append(&list);

        frame
    }

    /// Create the live network-activity card (real /proc/net/dev bandwidth).
    /// Compact: title + interface dropdown share one line; short chart.
    fn create_network_activity_card(&self) -> gtk4::Frame {
        let imp = self.imp();
        let frame = gtk4::Frame::new(None);
        frame.add_css_class("card");

        let content = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Vertical)
            .spacing(0)
            .margin_top(15)
            .margin_bottom(15)
            .margin_start(16)
            .margin_end(16)
            .build();

        // Title block left, interface dropdown top-right on the same line.
        let header = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .spacing(8)
            .margin_bottom(8)
            .build();
        let titles = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Vertical)
            .spacing(0)
            .hexpand(true)
            .valign(gtk4::Align::Center)
            .build();
        titles.append(
            &gtk4::Label::builder()
                .label(gettext("Network Activity"))
                .css_classes(vec!["heading".to_string()])
                .halign(gtk4::Align::Start)
                .build(),
        );
        titles.append(
            &gtk4::Label::builder()
                .label(gettext("Throughput · live"))
                .css_classes(vec!["caption".to_string(), "dim-label".to_string()])
                .halign(gtk4::Align::Start)
                .build(),
        );
        header.append(&titles);
        let mut iface_items = vec![gettext("All")];
        let interfaces = list_interfaces();
        iface_items.extend(interfaces.iter().cloned());
        let iface_refs: Vec<&str> = iface_items.iter().map(|s| s.as_str()).collect();
        let iface_dropdown = gtk4::DropDown::from_strings(&iface_refs);
        iface_dropdown.set_tooltip_text(Some(&gettext("Choose which interface to graph")));
        iface_dropdown.add_css_class("flat");
        iface_dropdown.set_valign(gtk4::Align::Start);
        header.append(&iface_dropdown);
        content.append(&header);

        let chart = NetworkActivityChart::new();
        chart.set_hexpand(true);
        chart.set_size_request(-1, 100);
        chart.set_margin_top(4);
        content.append(&chart);

        let rate_label = gtk4::Label::builder()
            .label("↓ 0.0 KB/s   ↑ 0.0 KB/s")
            .css_classes(vec![
                "dim-label".to_string(),
                "caption".to_string(),
                "numeric".to_string(),
            ])
            .halign(gtk4::Align::Start)
            .margin_top(6)
            .build();
        content.append(&rate_label);

        let chart_for_dd = chart.clone();
        let interfaces_for_dd = interfaces.clone();
        iface_dropdown.connect_selected_notify(move |dd| {
            let sel = dd.selected() as usize;
            let iface = if sel == 0 {
                None
            } else {
                interfaces_for_dd.get(sel - 1).cloned()
            };
            chart_for_dd.set_interface(iface);
        });

        let rate_label_cb = rate_label.clone();
        chart.connect_rate_updated(move |inb, outb| {
            rate_label_cb.set_label(&format!("↓ {:.1} KB/s   ↑ {:.1} KB/s", inb, outb));
        });
        chart.start_live_collection();

        imp.network_chart.replace(Some(chart));
        imp.rate_label.replace(Some(rate_label));
        frame.set_child(Some(&content));
        frame
    }

    /// Scan connections + per-socket bytes + country, then render the dashboard.
    fn refresh_connected_hosts(&self) {
        let page = self.clone();
        glib::spawn_future_local(async move {
            let data = gtk4::gio::spawn_blocking(|| {
                let mut scanner = crate::admin::NetworkExposure::new();
                let connections = scanner.scan_connections().unwrap_or_default();
                let listening = scanner.scan().unwrap_or_default();
                let socket_bytes = crate::admin::collect_socket_bytes().unwrap_or_default();
                let geo = crate::admin::GeoIp::load();
                let labels: HashMap<IpAddr, String> = connections
                    .iter()
                    .filter_map(|c| geo.country_label(c.remote_addr).map(|l| (c.remote_addr, l)))
                    .collect();
                let iso_labels: HashMap<IpAddr, String> = connections
                    .iter()
                    .filter_map(|c| geo.country_iso(c.remote_addr).map(|l| (c.remote_addr, l)))
                    .collect();
                (connections, listening, socket_bytes, labels, iso_labels)
            })
            .await;

            if let Ok((connections, listening, socket_bytes, geo_labels, iso_labels)) = data {
                page.render_app_dashboard(
                    connections,
                    listening,
                    socket_bytes,
                    geo_labels,
                    iso_labels,
                );
            }
        });
    }

    /// Aggregate connections per application and update every live widget.
    fn render_app_dashboard(
        &self,
        connections: Vec<crate::admin::ActiveConnection>,
        listening: Vec<crate::admin::ListeningEndpoint>,
        socket_bytes: HashMap<u32, (u64, u64)>,
        geo_labels: HashMap<IpAddr, String>,
        iso_labels: HashMap<IpAddr, String>,
    ) {
        let imp = self.imp();

        // --- Aggregate per remote application ---
        // Endpoints are keyed by (addr, port) so the busiest one we later show
        // on the card is always a real socket pair, not a fabricated mix of the
        // top host and an unrelated port.
        struct AppAgg {
            process: String,
            conn_count: usize,
            interval_in: u64,
            interval_out: u64,
            hosts: HashMap<(IpAddr, u16), u64>,
        }
        let mut apps: HashMap<String, AppAgg> = HashMap::new();

        // Protocol + country tallies (for the analytics panels).
        let mut proto_counts: HashMap<&'static str, usize> = HashMap::new();
        // ISO tally drives the world map (stable keys across languages).
        let mut iso_counts: HashMap<String, usize> = HashMap::new();

        // Per-socket byte deltas give a stable rate even as a process's many
        // short-lived sockets churn between samples.
        let mut prev_sock = imp.prev_sock.borrow_mut();
        let mut cur_sock: HashMap<u32, (u64, u64)> = HashMap::new();
        let mut remote_count = 0usize;

        for conn in &connections {
            // Only outbound / remote sessions belong on this dashboard.
            if is_local_ip(conn.remote_addr) {
                continue;
            }
            remote_count += 1;

            let inode = conn.inode as u32;
            let (bin, bout) = socket_bytes.get(&inode).copied().unwrap_or((0, 0));
            cur_sock.insert(inode, (bin, bout));
            // A socket we have not seen before contributes no delta this round.
            let (pin, pout) = prev_sock.get(&inode).copied().unwrap_or((bin, bout));
            let din = bin.saturating_sub(pin);
            let dout = bout.saturating_sub(pout);

            let proc = conn.process_label();
            let entry = apps.entry(proc.clone()).or_insert_with(|| AppAgg {
                process: proc.clone(),
                conn_count: 0,
                interval_in: 0,
                interval_out: 0,
                hosts: HashMap::new(),
            });
            entry.conn_count += 1;
            entry.interval_in = entry.interval_in.saturating_add(din);
            entry.interval_out = entry.interval_out.saturating_add(dout);
            *entry
                .hosts
                .entry((conn.remote_addr, conn.remote_port))
                .or_insert(0) += bin.saturating_add(bout);

            *proto_counts
                .entry(protocol_of(conn.remote_port))
                .or_insert(0) += 1;
            if let Some(iso) = iso_labels.get(&conn.remote_addr) {
                *iso_counts.entry(iso.to_uppercase()).or_insert(0) += 1;
            }
        }

        // Roll the per-socket snapshot forward for the next interval.
        *prev_sock = cur_sock;
        drop(prev_sock);

        // --- KPI cards + connections hub status ---
        set_label(&imp.metric_active, &remote_count.to_string());
        set_label(&imp.metric_apps, &apps.len().to_string());
        if let Some(chip) = imp.conn_chip.borrow().as_ref() {
            if apps.is_empty() {
                chip.set_label("0 connected");
            } else {
                chip.set_label(&format!("{} {}", apps.len(), gettext("connected")));
            }
        }
        set_label(&imp.metric_listening, &listening.len().to_string());

        // --- Protocols panel + regions map ---
        self.render_protocols(&proto_counts, remote_count);
        self.render_regions(&iso_counts);

        // --- Per-app cards, stable alphabetical order ---
        // Deliberately NOT sorted by live traffic: rates fluctuate every
        // refresh and would reshuffle the list constantly. New apps simply
        // appear at their alphabetical slot; per-app rates still update live.
        // (The Top Apps by Download/Upload tables keep rate-based ranking.)
        let mut app_list: Vec<AppAgg> = apps.into_values().collect();
        app_list.sort_by(|a, b| {
            display_process_name(&a.process)
                .cmp(&display_process_name(&b.process))
                .then(a.process.cmp(&b.process))
        });

        // Build enough cached render data for maximized layouts without a new
        // scan (which would reset the per-socket rate baseline).
        let mut spark = imp.app_spark.borrow_mut();
        let mut seen: HashSet<String> = HashSet::new();
        let mut cards: Vec<AppCardData> = Vec::new();
        for app in app_list.iter().take(crate::config::DASHBOARD_MAX_APPS_MAX) {
            seen.insert(app.process.clone());
            let down_kbs = (app.interval_in as f64 / INTERVAL_SECS) / 1024.0;
            let up_kbs = (app.interval_out as f64 / INTERVAL_SECS) / 1024.0;

            let history = spark.entry(app.process.clone()).or_default();
            history.push(down_kbs + up_kbs);
            while history.len() > 24 {
                history.remove(0);
            }

            // The busiest (addr, port) pair — a real socket group — carries the
            // IP, port and country shown in the row, so they always agree.
            let (primary_addr, primary_port) = app
                .hosts
                .iter()
                .max_by_key(|(_, b)| **b)
                .map(|((a, p), _)| (*a, *p))
                .unwrap_or((IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));

            cards.push(AppCardData {
                process: app.process.clone(),
                conn_count: app.conn_count,
                down_kbs,
                up_kbs,
                primary_addr,
                port: primary_port,
                country: geo_labels.get(&primary_addr).cloned(),
                history: history.clone(),
            });
        }
        spark.retain(|process, _| seen.contains(process));
        drop(spark);

        imp.last_apps.replace(cards);
        self.render_cards();
    }

    /// Rebuild the application-card grid from cached connection data.
    fn render_cards(&self) {
        let imp = self.imp();
        let flow_ref = imp.app_flow.borrow();
        let flow = match flow_ref.as_ref() {
            Some(flow) => flow,
            None => return,
        };
        while let Some(child) = flow.first_child() {
            flow.remove(&child);
        }

        let cards = imp.last_apps.borrow();
        if cards.is_empty() {
            flow.append(
                &gtk4::Label::builder()
                    .label(gettext("No active connections"))
                    .css_classes(vec!["dim-label".to_string()])
                    .margin_top(16)
                    .margin_bottom(16)
                    .build(),
            );
            return;
        }

        for card in cards.iter().take(imp.connection_cards.get()) {
            flow.append(&build_app_card(card.clone()));
        }
    }

    /// Rebuild the protocols panel from the current tally.
    fn render_protocols(&self, counts: &HashMap<&'static str, usize>, total: usize) {
        let imp = self.imp();
        let list_ref = imp.proto_box.borrow();
        let list = match list_ref.as_ref() {
            Some(l) => l,
            None => return,
        };
        while let Some(child) = list.first_child() {
            list.remove(&child);
        }
        if counts.is_empty() || total == 0 {
            placeholder(list, &gettext("No active sessions"));
            return;
        }

        let mut rows: Vec<(&'static str, usize)> = counts.iter().map(|(k, v)| (*k, *v)).collect();
        rows.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
        rows.truncate(4);

        for (name, count) in rows {
            let frac = count as f64 / total as f64;
            let row = gtk4::Box::builder()
                .orientation(gtk4::Orientation::Vertical)
                .spacing(5)
                .build();
            let top = gtk4::Box::builder()
                .orientation(gtk4::Orientation::Horizontal)
                .build();
            top.append(
                &gtk4::Label::builder()
                    .label(name)
                    .css_classes(vec!["caption".to_string()])
                    .halign(gtk4::Align::Start)
                    .hexpand(true)
                    .ellipsize(gtk4::pango::EllipsizeMode::End)
                    .max_width_chars(16)
                    .build(),
            );
            top.append(
                &gtk4::Label::builder()
                    .label(format!("{:.0}%", frac * 100.0))
                    .css_classes(vec!["caption".to_string(), "numeric".to_string()])
                    .halign(gtk4::Align::End)
                    .build(),
            );
            row.append(&top);
            let bar = MeterBar::new();
            let (r, g, b) = protocol_color(name);
            bar.set_color(r, g, b);
            bar.set_fraction(frac);
            row.append(&bar);
            list.append(&row);
        }
    }

    /// Update the page with zone data (keeps the status card's default zone).
    pub fn set_zones(&self, zones: &[Zone]) {
        let imp = self.imp();
        if let Some(default_zone) = zones.iter().find(|z| z.is_default) {
            if let Some(label) = imp.default_zone_label.borrow().as_ref() {
                label.set_label(&default_zone.name);
            }
        }
    }

    /// Update the blocked-ports count (KPI stat card).
    pub fn set_blocked_ports(&self, blocked_ports: &[crate::models::Port]) {
        let imp = self.imp();
        imp.blocked_count.set(blocked_ports.len());
        set_label(&imp.metric_blocked, &blocked_ports.len().to_string());
    }

    /// Show or hide the firewall connections overview section.
    pub fn set_connections_visible(&self, visible: bool) {
        if let Some(hub) = self.imp().connections_hub.borrow().as_ref() {
            hub.set_visible(visible);
        }
    }

    /// Keep four cards in a normal window and use only complete two-card rows
    /// that fit in the extra maximized height.
    pub fn set_window_layout(&self, maximized: bool, window_height: i32) {
        let cards = connection_card_limit(maximized, window_height);
        if self.imp().connection_cards.replace(cards) != cards {
            self.render_cards();
        }
    }
}

impl Default for OverviewPage {
    fn default() -> Self {
        Self::new()
    }
}

/// Data needed to render one application connection card.
#[derive(Clone)]
pub(crate) struct AppCardData {
    process: String,
    conn_count: usize,
    down_kbs: f64,
    up_kbs: f64,
    primary_addr: IpAddr,
    port: u16,
    country: Option<String>,
    history: Vec<f64>,
}

/// Build one application connection card in the restored dashboard style.
fn build_app_card(data: AppCardData) -> gtk4::Box {
    let tile = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(12)
        .css_classes(vec!["conn-tile".to_string(), "conn-tile-live".to_string()])
        .height_request(88)
        .hexpand(true)
        .build();

    tile.append(
        &gtk4::Image::builder()
            .icon_name(icon_for_process(&data.process, data.port).as_str())
            .pixel_size(24)
            .valign(gtk4::Align::Center)
            .css_classes(vec!["app-icon-tile".to_string()])
            .build(),
    );

    let main = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(1)
        .hexpand(true)
        .valign(gtk4::Align::Center)
        .build();

    let name_row = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(8)
        .build();
    name_row.append(
        &gtk4::Label::builder()
            .label(display_process_name(&data.process))
            .css_classes(vec!["heading".to_string()])
            .halign(gtk4::Align::Start)
            .hexpand(true)
            .ellipsize(gtk4::pango::EllipsizeMode::End)
            .build(),
    );
    let status = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(5)
        .valign(gtk4::Align::Center)
        .build();
    status.append(
        &gtk4::Label::builder()
            .label("●")
            .css_classes(vec!["dot-success".to_string()])
            .build(),
    );
    status.append(
        &gtk4::Label::builder()
            .label(gettext("CONNECTED"))
            .css_classes(vec!["caption".to_string(), "conn-status".to_string()])
            .build(),
    );
    name_row.append(&status);
    main.append(&name_row);

    let mut address = vec![format!("{}:{}", data.primary_addr, data.port)];
    if let Some(country) = &data.country {
        address.push(country.clone());
    }
    if data.conn_count > 1 {
        address.push(format!("{} {}", data.conn_count, gettext("conns")));
    }
    main.append(
        &gtk4::Label::builder()
            .label(address.join("  ·  "))
            .css_classes(vec![
                "caption".to_string(),
                "conn-meta".to_string(),
                "mono-addr".to_string(),
            ])
            .halign(gtk4::Align::Start)
            .ellipsize(gtk4::pango::EllipsizeMode::End)
            .build(),
    );

    let sparkline = Sparkline::new();
    sparkline.set_values(&data.history);
    sparkline.set_hexpand(true);
    sparkline.set_size_request(-1, 22);
    sparkline.set_margin_top(5);
    main.append(&sparkline);
    tile.append(&main);

    let rates = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(2)
        .valign(gtk4::Align::Center)
        .halign(gtk4::Align::End)
        .build();
    rates.append(
        &gtk4::Label::builder()
            .label(fmt_rate(data.down_kbs + data.up_kbs))
            .css_classes(vec!["heading".to_string(), "numeric".to_string()])
            .halign(gtk4::Align::End)
            .build(),
    );
    rates.append(
        &gtk4::Label::builder()
            .label(format!(
                "↓{} ↑{}",
                fmt_rate(data.down_kbs),
                fmt_rate(data.up_kbs)
            ))
            .css_classes(vec![
                "caption".to_string(),
                "conn-meta".to_string(),
                "numeric".to_string(),
            ])
            .halign(gtk4::Align::End)
            .build(),
    );
    tile.append(&rates);

    tile
}

/// Firewalla-style KPI card: tinted icon on the left, small dim label
/// on top and big number below on the right. Returns card + value label.
fn stat_card(icon: &str, tile_class: &str, caption: &str) -> (gtk4::Frame, gtk4::Label) {
    let frame = gtk4::Frame::new(None);
    frame.add_css_class("card");

    let row = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(14)
        .margin_top(14)
        .margin_bottom(14)
        .margin_start(18)
        .margin_end(18)
        .build();

    row.append(
        &gtk4::Image::builder()
            .icon_name(icon)
            .pixel_size(22)
            .valign(gtk4::Align::Center)
            .css_classes(vec!["icon-tile".to_string(), tile_class.to_string()])
            .build(),
    );

    let text = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(2)
        .valign(gtk4::Align::Center)
        .hexpand(true)
        .build();
    text.append(
        &gtk4::Label::builder()
            .label(caption)
            .css_classes(vec!["caption".to_string(), "dim-label".to_string()])
            .halign(gtk4::Align::Start)
            .ellipsize(gtk4::pango::EllipsizeMode::End)
            .build(),
    );
    let value = gtk4::Label::builder()
        .label("0")
        .css_classes(vec!["stat-value".to_string(), "numeric".to_string()])
        .halign(gtk4::Align::Start)
        .build();
    text.append(&value);
    row.append(&text);

    frame.set_child(Some(&row));
    (frame, value)
}

/// Header cell for table grids.
fn th(grid: &gtk4::Grid, col: i32, text: &str, right: bool) {
    let label = gtk4::Label::builder()
        .label(text)
        .css_classes(vec!["caption".to_string(), "dim-label".to_string()])
        .halign(if right {
            gtk4::Align::End
        } else {
            gtk4::Align::Start
        })
        .build();
    if !right {
        label.set_hexpand(true);
    }
    grid.attach(&label, col, 0, 1, 1);
}

/// Body cell. `bound` caps the label width so long addresses/hostnames can
/// never inflate the table past the viewport (anti-overflow insurance).
fn td(grid: &gtk4::Grid, col: i32, row: i32, text: &str, right: bool, bound: i32) -> gtk4::Label {
    let label = gtk4::Label::builder()
        .label(text)
        .css_classes(vec!["body".to_string(), "numeric".to_string()])
        .halign(if right {
            gtk4::Align::End
        } else {
            gtk4::Align::Start
        })
        .ellipsize(gtk4::pango::EllipsizeMode::End)
        .max_width_chars(bound)
        .build();
    grid.attach(&label, col, row, 1, 1);
    label
}

/// Compact `1.2 MB/s` / `850 B/s` rate formatting for table cells.
fn fmt_rate(kbs: f64) -> String {
    if kbs >= 1024.0 {
        format!("{:.1} MB/s", kbs / 1024.0)
    } else if kbs >= 1.0 {
        format!("{:.0} KB/s", kbs)
    } else if kbs > 0.0 {
        format!("{:.0} B/s", kbs * 1024.0)
    } else {
        "0 B/s".to_string()
    }
}

/// Side-stack section card: title + hint + content in a subtle card.
/// Returns the frame and the inner content box to append into.
fn panel_card(title: &str, hint: &str) -> (gtk4::Frame, gtk4::Box) {
    let frame = gtk4::Frame::new(None);
    frame.add_css_class("card");

    let content = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(0)
        .margin_top(15)
        .margin_bottom(15)
        .margin_start(16)
        .margin_end(16)
        .build();

    content.append(
        &gtk4::Label::builder()
            .label(title)
            .css_classes(vec!["heading".to_string()])
            .halign(gtk4::Align::Start)
            .build(),
    );
    content.append(
        &gtk4::Label::builder()
            .label(hint)
            .css_classes(vec!["caption".to_string(), "dim-label".to_string()])
            .halign(gtk4::Align::Start)
            .margin_bottom(12)
            .build(),
    );

    frame.set_child(Some(&content));
    (frame, content)
}

/// Replace a box's contents with a single dim placeholder label.
fn placeholder(list: &gtk4::Box, text: &str) {
    while let Some(child) = list.first_child() {
        list.remove(&child);
    }
    list.append(
        &gtk4::Label::builder()
            .label(text)
            .css_classes(vec!["caption".to_string(), "dim-label".to_string()])
            .halign(gtk4::Align::Start)
            .margin_top(6)
            .margin_bottom(6)
            .build(),
    );
}

/// Set an optional label's text if present.
fn set_label(cell: &RefCell<Option<gtk4::Label>>, text: &str) {
    if let Some(label) = cell.borrow().as_ref() {
        label.set_label(text);
    }
}

/// Colour (linear RGB) for a protocol bar.
fn protocol_color(name: &str) -> (f64, f64, f64) {
    match name {
        "HTTPS" => color_accent(),
        "HTTP" => (0.90, 0.65, 0.04),
        "DNS" => (0.57, 0.25, 0.67),
        "SSH" => color_success(),
        "Mail" => (0.13, 0.62, 0.64),
        _ => color_idle(),
    }
}

fn color_accent() -> (f64, f64, f64) {
    (0.21, 0.52, 0.89)
}
fn color_success() -> (f64, f64, f64) {
    (0.18, 0.76, 0.49)
}
fn color_idle() -> (f64, f64, f64) {
    (0.55, 0.55, 0.58)
}

mod imp {
    use super::*;

    #[derive(Default)]
    pub struct OverviewPage {
        // Status card
        pub status_icon: RefCell<Option<gtk4::Image>>,
        pub status_title: RefCell<Option<gtk4::Label>>,
        pub status_subtitle: RefCell<Option<gtk4::Label>>,
        pub traffic_switch: RefCell<Option<gtk4::Switch>>,
        pub traffic_label: RefCell<Option<gtk4::Label>>,
        pub default_zone_label: RefCell<Option<gtk4::Label>>,
        // Stat cards
        pub metric_active: RefCell<Option<gtk4::Label>>,
        pub metric_blocked: RefCell<Option<gtk4::Label>>,
        pub metric_apps: RefCell<Option<gtk4::Label>>,
        pub metric_listening: RefCell<Option<gtk4::Label>>,
        pub stat_status: RefCell<Option<gtk4::Label>>,
        // Regions map card
        pub regions_card: RefCell<Option<gtk4::Frame>>,
        pub world_map: RefCell<Option<WorldMap>>,
        pub region_grid: RefCell<Option<gtk4::Grid>>,
        // Responsive application connection cards
        pub connections_hub: RefCell<Option<gtk4::Frame>>,
        pub app_flow: RefCell<Option<gtk4::FlowBox>>,
        pub conn_chip: RefCell<Option<gtk4::Label>>,
        // Analytics: protocols
        pub proto_box: RefCell<Option<gtk4::Box>>,
        // Analytics: network activity chart
        pub network_chart: RefCell<Option<NetworkActivityChart>>,
        pub rate_label: RefCell<Option<gtk4::Label>>,
        // Live state
        pub blocked_count: Cell<usize>,
        // Responsive card limit and per-application sparkline history.
        pub connection_cards: Cell<usize>,
        pub app_spark: RefCell<HashMap<String, Vec<f64>>>,
        // Cached data lets maximize/restore re-render without a fresh scan.
        pub(crate) last_apps: RefCell<Vec<AppCardData>>,
        // Previous cumulative (bytes_in, bytes_out) per socket inode, for rates.
        pub prev_sock: RefCell<HashMap<u32, (u64, u64)>>,
    }

    #[glib::object_subclass]
    impl ObjectSubclass for OverviewPage {
        const NAME: &'static str = "SecurityCenterOverviewPage";
        type Type = super::OverviewPage;
        type ParentType = gtk4::Box;
    }

    impl ObjectImpl for OverviewPage {}
    impl WidgetImpl for OverviewPage {}
    impl BoxImpl for OverviewPage {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_window_always_shows_four_connection_cards() {
        assert_eq!(connection_card_limit(false, 880), 4);
        assert_eq!(connection_card_limit(false, 1200), 4);
    }

    #[test]
    fn maximized_connection_cards_use_only_complete_extra_rows() {
        assert_eq!(connection_card_limit(true, 880), 4);
        assert_eq!(connection_card_limit(true, 977), 4);
        assert_eq!(connection_card_limit(true, 978), 6);
        assert_eq!(connection_card_limit(true, 1032), 6);
    }
}
