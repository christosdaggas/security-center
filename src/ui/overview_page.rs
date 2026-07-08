// Security Center - Overview Page
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: MIT

//! Overview dashboard page: firewall status, live per-application connections,
//! and a real-time analytics row (connection breakdown, network activity,
//! protocols, and remote countries).

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};

use gtk4::glib;
use gtk4::prelude::*;
use gtk4::subclass::prelude::*;

use super::widgets::{list_interfaces, DonutChart, MeterBar, NetworkActivityChart, Sparkline};
use crate::i18n::gettext;
use crate::models::Zone;

/// How often the live connection dashboard refreshes.
const REFRESH_SECS: u32 = 5;
const INTERVAL_SECS: f64 = REFRESH_SECS as f64;

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
        if let Some(theme) = icon_theme() {
            theme.add_search_path("/var/lib/flatpak/exports/share/icons");
            if let Some(home) = std::env::var_os("HOME") {
                let mut p = std::path::PathBuf::from(home);
                p.push(".local/share/flatpak/exports/share/icons");
                theme.add_search_path(&p);
            }
        }

        let scrolled = gtk4::ScrolledWindow::builder()
            .hscrollbar_policy(gtk4::PolicyType::Never)
            .vscrollbar_policy(gtk4::PolicyType::Automatic)
            .vexpand(true)
            .hexpand(true)
            .build();

        let content = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Vertical)
            .spacing(18)
            .margin_top(20)
            .margin_bottom(20)
            .margin_start(20)
            .margin_end(20)
            .hexpand(true)
            .build();

        // Top controls and cards come first; the live connections overview
        // belongs at the bottom of the dashboard.
        content.append(&self.build_status_card());
        content.append(&self.build_stat_cards());
        content.append(&self.build_analytics());
        content.append(&self.build_connections_hub());

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

    /// Build the firewall status card (icon + title + zone/restart/traffic toggle).
    fn build_status_card(&self) -> gtk4::Frame {
        let imp = self.imp();

        let status_frame = gtk4::Frame::new(None);
        status_frame.add_css_class("card");

        let status_box = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .spacing(16)
            .margin_top(18)
            .margin_bottom(18)
            .margin_start(22)
            .margin_end(22)
            .build();

        let status_icon = gtk4::Image::builder()
            .icon_name("security-high-symbolic")
            .pixel_size(48)
            .css_classes(vec!["success".to_string()])
            .build();
        imp.status_icon.replace(Some(status_icon.clone()));

        let status_text = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Vertical)
            .spacing(4)
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

        // Right-hand controls: zone · restart · traffic switch.
        let toggle_box = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .spacing(16)
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
        let zone_label = gtk4::Label::builder()
            .label(gettext("Default Zone:"))
            .css_classes(vec!["caption".to_string(), "dim-label".to_string()])
            .build();
        zone_info_box.append(&zone_label);
        let zone_name_label = gtk4::Label::builder()
            .label("public")
            .css_classes(vec!["caption".to_string()])
            .build();
        imp.default_zone_label
            .replace(Some(zone_name_label.clone()));
        zone_info_box.append(&zone_name_label);
        toggle_box.append(&zone_info_box);

        toggle_box.append(&gtk4::Separator::new(gtk4::Orientation::Vertical));

        // Restart firewall button.
        let restart_box = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Vertical)
            .spacing(4)
            .valign(gtk4::Align::Center)
            .build();
        let restart_button = gtk4::Button::builder()
            .icon_name("view-refresh-symbolic")
            .tooltip_text(gettext("Restart Firewall"))
            .css_classes(vec!["circular".to_string()])
            .valign(gtk4::Align::Center)
            .halign(gtk4::Align::Center)
            .build();
        let restart_label = gtk4::Label::builder()
            .label(gettext("Restart"))
            .css_classes(vec!["caption".to_string(), "dim-label".to_string()])
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
        restart_box.append(&restart_label);
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

    /// Build the four summary stat cards.
    fn build_stat_cards(&self) -> gtk4::Box {
        let imp = self.imp();

        let row = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .spacing(12)
            .homogeneous(true)
            .build();

        let (active_card, active_val) = stat_card(
            "network-transmit-receive-symbolic",
            "accent",
            &gettext("Active Connections"),
        );
        imp.metric_active.replace(Some(active_val));
        row.append(&active_card);

        let (blocked_card, blocked_val) = stat_card(
            "action-unavailable-symbolic",
            "error",
            &gettext("Blocked Ports"),
        );
        imp.metric_blocked.replace(Some(blocked_val));
        row.append(&blocked_card);

        let (apps_card, apps_val) =
            stat_card("view-app-grid-symbolic", "purple", &gettext("Applications"));
        imp.metric_apps.replace(Some(apps_val));
        row.append(&apps_card);

        // System Status card carries a coloured pill instead of a number.
        let (status_card, status_val) = stat_card(
            "security-high-symbolic",
            "success",
            &gettext("System Status"),
        );
        status_val.remove_css_class("stat-value");
        status_val.add_css_class("pill-ok");
        status_val.set_label(&gettext("Protected"));
        status_val.set_halign(gtk4::Align::Start);
        imp.stat_status.replace(Some(status_val));
        row.append(&status_card);

        row
    }

    /// Build the "Firewall Connections Overview" hub containing the per-app grid.
    fn build_connections_hub(&self) -> gtk4::Frame {
        let imp = self.imp();

        let frame = gtk4::Frame::new(None);
        frame.add_css_class("card");
        frame.add_css_class("dashboard-card");

        let outer = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Vertical)
            .spacing(0)
            .build();

        // Header: title + subtitle on the left, chips on the right.
        let header = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .spacing(12)
            .margin_top(15)
            .margin_bottom(15)
            .margin_start(17)
            .margin_end(17)
            .build();

        let titles = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Vertical)
            .spacing(2)
            .hexpand(true)
            .valign(gtk4::Align::Center)
            .build();
        titles.append(
            &gtk4::Label::builder()
                .label(gettext("Firewall Connections Overview"))
                .css_classes(vec!["heading".to_string()])
                .halign(gtk4::Align::Start)
                .build(),
        );
        titles.append(
            &gtk4::Label::builder()
                .label(gettext("Outbound sessions permitted by the active ruleset"))
                .css_classes(vec!["caption".to_string(), "dim-label".to_string()])
                .halign(gtk4::Align::Start)
                .build(),
        );
        header.append(&titles);

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
        outer.append(&gtk4::Separator::new(gtk4::Orientation::Horizontal));

        // Two-column responsive grid of app connection tiles.
        let app_flow = gtk4::FlowBox::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .column_spacing(10)
            .row_spacing(10)
            .homogeneous(true)
            .min_children_per_line(1)
            .max_children_per_line(2)
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

    /// Build the analytics row: network activity, protocols, countries, connection state.
    fn build_analytics(&self) -> gtk4::FlowBox {
        let flow = gtk4::FlowBox::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .column_spacing(14)
            .row_spacing(14)
            .homogeneous(true)
            .min_children_per_line(1)
            .max_children_per_line(4)
            .selection_mode(gtk4::SelectionMode::None)
            .build();

        flow.append(&self.create_network_activity_card());
        flow.append(&self.build_protocols_panel());
        flow.append(&self.build_countries_panel());
        flow.append(&self.build_donut_panel());

        flow
    }

    /// Panel: connection-state donut with a legend.
    fn build_donut_panel(&self) -> gtk4::Frame {
        let imp = self.imp();
        let (frame, content) = panel_card(
            &gettext("Connection Overview"),
            &gettext("By current state"),
        );

        let donut = DonutChart::new();
        donut.set_halign(gtk4::Align::Center);
        imp.donut.replace(Some(donut.clone()));

        let overlay = gtk4::Overlay::new();
        overlay.set_halign(gtk4::Align::Center);
        overlay.set_child(Some(&donut));

        let center = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Vertical)
            .spacing(0)
            .halign(gtk4::Align::Center)
            .valign(gtk4::Align::Center)
            .can_target(false)
            .build();
        let total = gtk4::Label::builder()
            .label("0")
            .css_classes(vec!["title-1".to_string()])
            .build();
        imp.donut_total.replace(Some(total.clone()));
        center.append(&total);
        center.append(
            &gtk4::Label::builder()
                .label(gettext("Total"))
                .css_classes(vec!["caption".to_string(), "dim-label".to_string()])
                .build(),
        );
        overlay.add_overlay(&center);
        content.append(&overlay);

        // Legend.
        let legend = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Vertical)
            .spacing(8)
            .margin_top(14)
            .build();
        let active_val = legend_row(&legend, "sw-success", &gettext("Active"));
        let blocked_val = legend_row(&legend, "sw-error", &gettext("Blocked"));
        let idle_val = legend_row(&legend, "sw-idle", &gettext("Idle"));
        imp.donut_active_val.replace(Some(active_val));
        imp.donut_blocked_val.replace(Some(blocked_val));
        imp.donut_idle_val.replace(Some(idle_val));
        content.append(&legend);

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

    /// Panel: remote endpoints grouped by country.
    fn build_countries_panel(&self) -> gtk4::Frame {
        let imp = self.imp();
        let (frame, content) = panel_card(
            &gettext("Connection Status"),
            &gettext("Remote endpoints by country"),
        );

        let list = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Vertical)
            .spacing(11)
            .build();
        placeholder(&list, &gettext("Scanning…"));
        imp.country_box.replace(Some(list.clone()));
        content.append(&list);

        frame
    }

    /// Create the live network-activity card (real /proc/net/dev bandwidth).
    fn create_network_activity_card(&self) -> gtk4::Frame {
        let imp = self.imp();
        let (frame, content) =
            panel_card(&gettext("Network Activity"), &gettext("Throughput · live"));

        // Interface selector.
        let header = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .spacing(8)
            .build();
        header.append(&gtk4::Label::builder().hexpand(true).build());
        let mut iface_items = vec![gettext("All")];
        let interfaces = list_interfaces();
        iface_items.extend(interfaces.iter().cloned());
        let iface_refs: Vec<&str> = iface_items.iter().map(|s| s.as_str()).collect();
        let iface_dropdown = gtk4::DropDown::from_strings(&iface_refs);
        iface_dropdown.set_tooltip_text(Some(&gettext("Choose which interface to graph")));
        iface_dropdown.add_css_class("flat");
        header.append(&iface_dropdown);
        content.append(&header);

        let chart = NetworkActivityChart::new();
        chart.set_hexpand(true);
        chart.set_size_request(-1, 120);
        chart.set_margin_top(4);
        content.append(&chart);

        let rate_label = gtk4::Label::builder()
            .label("↓ 0.0 KB/s   ↑ 0.0 KB/s")
            .css_classes(vec!["dim-label".to_string(), "caption".to_string()])
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
        frame
    }

    /// Scan connections + per-socket bytes + country, then render the dashboard.
    fn refresh_connected_hosts(&self) {
        let page = self.clone();
        glib::spawn_future_local(async move {
            let data = gtk4::gio::spawn_blocking(|| {
                let mut scanner = crate::admin::NetworkExposure::new();
                let connections = scanner.scan_connections().unwrap_or_default();
                let listening = scanner.scan().map(|v| v.len()).unwrap_or(0);
                let socket_bytes = crate::admin::collect_socket_bytes().unwrap_or_default();
                let geo = crate::admin::GeoIp::load();
                let labels: HashMap<IpAddr, String> = connections
                    .iter()
                    .filter_map(|c| geo.country_label(c.remote_addr).map(|l| (c.remote_addr, l)))
                    .collect();
                (connections, listening, socket_bytes, labels)
            })
            .await;

            if let Ok((connections, listening, socket_bytes, geo_labels)) = data {
                page.render_app_dashboard(connections, listening, socket_bytes, geo_labels);
            }
        });
    }

    /// Aggregate connections per application and update every live widget.
    fn render_app_dashboard(
        &self,
        connections: Vec<crate::admin::ActiveConnection>,
        listening: usize,
        socket_bytes: HashMap<u32, (u64, u64)>,
        geo_labels: HashMap<IpAddr, String>,
    ) {
        let imp = self.imp();

        // --- Aggregate per remote application ---
        struct AppAgg {
            process: String,
            conn_count: usize,
            bytes_total: u64,
            interval_in: u64,
            interval_out: u64,
            hosts: HashMap<IpAddr, u64>,
            ports: HashSet<u16>,
            countries: HashSet<String>,
        }
        let mut apps: HashMap<String, AppAgg> = HashMap::new();

        // Protocol + country tallies (for the analytics panels).
        let mut proto_counts: HashMap<&'static str, usize> = HashMap::new();
        let mut dest_counts: HashMap<String, usize> = HashMap::new();

        // Per-socket byte deltas give a stable rate even as a process's many
        // short-lived sockets churn between samples.
        let mut prev_sock = imp.prev_sock.borrow_mut();
        let mut cur_sock: HashMap<u32, (u64, u64)> = HashMap::new();
        let mut remote_count = 0usize;

        for conn in &connections {
            // Only outbound / remote sessions belong on this dashboard.
            if is_local_addr(conn.remote_addr) {
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
                bytes_total: 0,
                interval_in: 0,
                interval_out: 0,
                hosts: HashMap::new(),
                ports: HashSet::new(),
                countries: HashSet::new(),
            });
            entry.conn_count += 1;
            entry.bytes_total = entry.bytes_total.saturating_add(bin).saturating_add(bout);
            entry.interval_in = entry.interval_in.saturating_add(din);
            entry.interval_out = entry.interval_out.saturating_add(dout);
            *entry.hosts.entry(conn.remote_addr).or_insert(0) += bin.saturating_add(bout);
            entry.ports.insert(conn.remote_port);
            if let Some(label) = geo_labels.get(&conn.remote_addr) {
                entry.countries.insert(label.clone());
            }

            *proto_counts
                .entry(protocol_of(conn.remote_port))
                .or_insert(0) += 1;
            let key = endpoint_label(conn.remote_addr, &geo_labels);
            *dest_counts.entry(key).or_insert(0) += 1;
        }

        // Roll the per-socket snapshot forward for the next interval.
        *prev_sock = cur_sock;
        drop(prev_sock);

        // --- Stat cards ---
        set_label(&imp.metric_active, &remote_count.to_string());
        set_label(&imp.metric_apps, &apps.len().to_string());

        // --- Connections hub chip ---
        if let Some(chip) = imp.conn_chip.borrow().as_ref() {
            if apps.is_empty() {
                chip.set_label("0 connected");
            } else {
                chip.set_label(&format!("{} {}", apps.len(), gettext("connected")));
            }
        }

        // --- Donut: active (remote) vs blocked vs idle/listening ---
        let blocked = imp.blocked_count.get();
        if let Some(donut) = imp.donut.borrow().as_ref() {
            donut.set_segments(&[
                (remote_count as f64, color_success()),
                (blocked as f64, color_error()),
                (listening as f64, color_idle()),
            ]);
        }
        set_label(
            &imp.donut_total,
            &(remote_count + blocked + listening).to_string(),
        );
        set_label(&imp.donut_active_val, &remote_count.to_string());
        set_label(&imp.donut_blocked_val, &blocked.to_string());
        set_label(&imp.donut_idle_val, &listening.to_string());

        // --- Protocols + countries panels ---
        self.render_protocols(&proto_counts, remote_count);
        self.render_countries(&dest_counts);

        // --- Per-app cards ---
        let mut app_list: Vec<AppAgg> = apps.into_values().collect();
        app_list.sort_by(|a, b| {
            (b.interval_in + b.interval_out)
                .cmp(&(a.interval_in + a.interval_out))
                .then(b.bytes_total.cmp(&a.bytes_total))
                .then(a.process.cmp(&b.process))
        });

        let mut spark = imp.app_spark.borrow_mut();

        let flow_ref = imp.app_flow.borrow();
        let flow = match flow_ref.as_ref() {
            Some(f) => f,
            None => return,
        };
        while let Some(child) = flow.first_child() {
            flow.remove(&child);
        }

        if app_list.is_empty() {
            let empty = gtk4::Label::builder()
                .label(gettext("No active connections"))
                .css_classes(vec!["dim-label".to_string()])
                .margin_top(16)
                .margin_bottom(16)
                .build();
            flow.append(&empty);
        }

        let mut seen: HashSet<String> = HashSet::new();
        for app in app_list.iter().take(6) {
            seen.insert(app.process.clone());

            let down_kbs = (app.interval_in as f64 / INTERVAL_SECS) / 1024.0;
            let up_kbs = (app.interval_out as f64 / INTERVAL_SECS) / 1024.0;

            let hist = spark.entry(app.process.clone()).or_default();
            hist.push(down_kbs + up_kbs);
            while hist.len() > 24 {
                hist.remove(0);
            }

            let (primary_addr, _) = app
                .hosts
                .iter()
                .max_by_key(|(_, b)| **b)
                .map(|(a, b)| (*a, *b))
                .unwrap_or((IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));

            let card = build_app_card(AppCardData {
                process: app.process.clone(),
                conn_count: app.conn_count,
                down_kbs,
                up_kbs,
                primary_addr,
                port: app.ports.iter().min().copied().unwrap_or(0),
                country: app.countries.iter().next().cloned(),
                history: hist.clone(),
            });
            flow.append(&card);
        }

        spark.retain(|k, _| seen.contains(k));
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

    /// Rebuild the countries panel from the current tally.
    fn render_countries(&self, counts: &HashMap<String, usize>) {
        let imp = self.imp();
        let list_ref = imp.country_box.borrow();
        let list = match list_ref.as_ref() {
            Some(l) => l,
            None => return,
        };
        while let Some(child) = list.first_child() {
            list.remove(&child);
        }
        if counts.is_empty() {
            placeholder(list, &gettext("No remote connections"));
            return;
        }

        let mut rows: Vec<(String, usize)> = counts.iter().map(|(k, v)| (k.clone(), *v)).collect();
        rows.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        rows.truncate(5);
        let max = rows.first().map(|(_, c)| *c).unwrap_or(1).max(1);

        for (name, count) in rows {
            let row = gtk4::Box::builder()
                .orientation(gtk4::Orientation::Vertical)
                .spacing(5)
                .build();
            let top = gtk4::Box::builder()
                .orientation(gtk4::Orientation::Horizontal)
                .build();
            top.append(
                &gtk4::Label::builder()
                    .label(&name)
                    .css_classes(vec!["caption".to_string(), "conn-meta".to_string()])
                    .halign(gtk4::Align::Start)
                    .hexpand(true)
                    .ellipsize(gtk4::pango::EllipsizeMode::End)
                    .build(),
            );
            top.append(
                &gtk4::Label::builder()
                    .label(count.to_string())
                    .css_classes(vec![
                        "caption".to_string(),
                        "conn-meta".to_string(),
                        "numeric".to_string(),
                    ])
                    .halign(gtk4::Align::End)
                    .build(),
            );
            row.append(&top);
            let bar = MeterBar::new();
            let (r, g, b) = color_accent();
            bar.set_color(r, g, b);
            bar.set_fraction(count as f64 / max as f64);
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

    /// Update the blocked-ports count (stat card + donut on next refresh).
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
}

impl Default for OverviewPage {
    fn default() -> Self {
        Self::new()
    }
}

/// Data needed to render one application connection card.
struct AppCardData {
    process: String,
    conn_count: usize,
    down_kbs: f64,
    up_kbs: f64,
    primary_addr: IpAddr,
    port: u16,
    country: Option<String>,
    history: Vec<f64>,
}

/// Build one GNOME-style application connection tile (horizontal layout).
fn build_app_card(d: AppCardData) -> gtk4::Box {
    // Internal spacing comes from CSS padding on `.conn-tile`; inter-tile gaps
    // come from the FlowBox row/column spacing.
    let tile = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(12)
        .css_classes(vec!["conn-tile".to_string()])
        .height_request(88)
        .build();

    // App icon in a neutral rounded tile. Symmetric CSS padding around the
    // natural-size icon keeps it centred inside the tile.
    let icon_tile = gtk4::Image::builder()
        .icon_name(icon_for_process(&d.process, d.port).as_str())
        .pixel_size(24)
        .valign(gtk4::Align::Center)
        .css_classes(vec!["app-icon-tile".to_string()])
        .build();
    tile.append(&icon_tile);

    // Main column.
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
            .label(display_process_name(&d.process))
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

    // Address line: IP:port · country · N conns.
    let mut addr_parts = vec![format!("{}:{}", d.primary_addr, d.port)];
    if let Some(country) = &d.country {
        addr_parts.push(country.clone());
    }
    if d.conn_count > 1 {
        addr_parts.push(format!("{} {}", d.conn_count, gettext("conns")));
    }
    main.append(
        &gtk4::Label::builder()
            .label(addr_parts.join("  ·  "))
            .css_classes(vec![
                "caption".to_string(),
                "conn-meta".to_string(),
                "mono-addr".to_string(),
            ])
            .halign(gtk4::Align::Start)
            .ellipsize(gtk4::pango::EllipsizeMode::End)
            .build(),
    );

    let spark = Sparkline::new();
    spark.set_values(&d.history);
    spark.set_hexpand(true);
    spark.set_size_request(-1, 22);
    spark.set_margin_top(5);
    main.append(&spark);
    tile.append(&main);

    // Rate column.
    let rate_col = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(2)
        .valign(gtk4::Align::Center)
        .halign(gtk4::Align::End)
        .build();
    rate_col.append(
        &gtk4::Label::builder()
            .label(format!("{:.0} KB/s", d.down_kbs + d.up_kbs))
            .css_classes(vec!["heading".to_string(), "numeric".to_string()])
            .halign(gtk4::Align::End)
            .build(),
    );
    rate_col.append(
        &gtk4::Label::builder()
            .label(format!("↓{:.0} ↑{:.0}", d.down_kbs, d.up_kbs))
            .css_classes(vec![
                "caption".to_string(),
                "conn-meta".to_string(),
                "numeric".to_string(),
            ])
            .halign(gtk4::Align::End)
            .build(),
    );
    tile.append(&rate_col);

    tile
}

/// Create a summary stat card, returning the card and its value label.
fn stat_card(icon: &str, tile_class: &str, caption: &str) -> (gtk4::Frame, gtk4::Label) {
    let frame = gtk4::Frame::new(None);
    frame.add_css_class("card");

    let content = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(9)
        .margin_top(14)
        .margin_bottom(14)
        .margin_start(15)
        .margin_end(15)
        .build();

    // Symmetric CSS padding around the natural-size icon centres it inside the
    // tinted tile (the tile grows uniformly around the glyph).
    let icon_tile = gtk4::Image::builder()
        .icon_name(icon)
        .pixel_size(18)
        .halign(gtk4::Align::Start)
        .css_classes(vec!["icon-tile".to_string(), tile_class.to_string()])
        .build();
    content.append(&icon_tile);

    let value = gtk4::Label::builder()
        .label("0")
        .css_classes(vec!["stat-value".to_string()])
        .halign(gtk4::Align::Start)
        .build();
    content.append(&value);

    content.append(
        &gtk4::Label::builder()
            .label(caption)
            .css_classes(vec!["caption".to_string(), "dim-label".to_string()])
            .halign(gtk4::Align::Start)
            .build(),
    );

    frame.set_child(Some(&content));
    (frame, value)
}

/// Create an analytics panel card with a title + hint, returning the card and
/// the inner content box to append into.
fn panel_card(title: &str, hint: &str) -> (gtk4::Frame, gtk4::Box) {
    let frame = gtk4::Frame::new(None);
    frame.add_css_class("card");
    frame.add_css_class("dashboard-card");

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

/// Append a donut legend row (swatch + label + value), returning the value label.
fn legend_row(parent: &gtk4::Box, swatch_class: &str, label: &str) -> gtk4::Label {
    let row = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(9)
        .build();
    row.append(
        &gtk4::Box::builder()
            .css_classes(vec!["swatch".to_string(), swatch_class.to_string()])
            .valign(gtk4::Align::Center)
            .build(),
    );
    row.append(
        &gtk4::Label::builder()
            .label(label)
            .css_classes(vec!["caption".to_string()])
            .halign(gtk4::Align::Start)
            .hexpand(true)
            .build(),
    );
    let value = gtk4::Label::builder()
        .label("0")
        .css_classes(vec!["caption".to_string(), "numeric".to_string()])
        .halign(gtk4::Align::End)
        .build();
    row.append(&value);
    parent.append(&row);
    value
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

/// Display a remote endpoint while keeping the IP visible. Offline GeoIP adds
/// `flag + country`; unresolved hosts fall back to the raw IP.
fn endpoint_label(addr: IpAddr, geo_labels: &HashMap<IpAddr, String>) -> String {
    match geo_labels.get(&addr) {
        Some(country) => format!("{} · {}", country, addr),
        None => addr.to_string(),
    }
}

/// Bucket a remote port into a coarse protocol name.
fn protocol_of(port: u16) -> &'static str {
    match port {
        443 | 8443 => "HTTPS",
        80 | 8080 | 8000 => "HTTP",
        53 => "DNS",
        22 => "SSH",
        25 | 110 | 143 | 465 | 587 | 993 | 995 => "Mail",
        _ => "Other",
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
fn color_error() -> (f64, f64, f64) {
    (0.88, 0.11, 0.14)
}
fn color_idle() -> (f64, f64, f64) {
    (0.55, 0.55, 0.58)
}

/// Convert process executable names into friendlier card titles.
fn display_process_name(process: &str) -> String {
    process
        .split(['-', '_', ' '])
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().chain(chars).collect::<String>(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Resolve the best themed icon name for a process: a real application icon
/// when one is installed, otherwise a symbolic category icon based on the port.
fn icon_for_process(process: &str, port: u16) -> String {
    let p = process.to_ascii_lowercase();

    let candidates: &[&str] = if p.contains("firefox") {
        &["firefox", "org.mozilla.firefox"]
    } else if p.contains("chromium") {
        &["chromium", "chromium-browser"]
    } else if p.contains("chrome") {
        &["google-chrome", "google-chrome-stable"]
    } else if p.contains("signal") {
        &["org.signal.Signal", "signal-desktop", "signal"]
    } else if p.contains("gnome-software") || p.contains("packagekit") {
        &["org.gnome.Software", "system-software-install"]
    } else if p.contains("vscod") || p.contains("code") {
        &[
            "vscode",
            "visual-studio-code",
            "code",
            "com.visualstudio.code",
        ]
    } else if p.contains("thunder") {
        &["thunderbird", "org.mozilla.Thunderbird"]
    } else if p.contains("discord") {
        &["discord", "com.discordapp.Discord"]
    } else if p.contains("steam") {
        &["steam"]
    } else if p.contains("spotify") {
        &["spotify", "com.spotify.Client"]
    } else if p.contains("telegram") {
        &["org.telegram.desktop", "telegram"]
    } else if p.contains("slack") {
        &["slack", "com.slack.Slack"]
    } else if p.contains("evolution") {
        &["org.gnome.Evolution", "evolution"]
    } else if p.contains("nautilus") {
        &["org.gnome.Nautilus"]
    } else if p.contains("curl") || p.contains("wget") {
        &["folder-download-symbolic"]
    } else {
        &[]
    };

    if let Some(theme) = icon_theme() {
        for name in candidates {
            if theme.has_icon(name) {
                return (*name).to_string();
            }
        }
        // Fall back to trying the raw process name as an icon.
        if !p.is_empty() && theme.has_icon(&p) {
            return p;
        }
    }
    category_icon(port).to_string()
}

/// The default display's icon theme, if a display is available.
fn icon_theme() -> Option<gtk4::IconTheme> {
    gtk4::gdk::Display::default().map(|d| gtk4::IconTheme::for_display(&d))
}

/// A symbolic fallback icon based on the connection's port category.
fn category_icon(port: u16) -> &'static str {
    match protocol_of(port) {
        "HTTPS" | "HTTP" => "web-browser-symbolic",
        "DNS" => "network-workgroup-symbolic",
        "SSH" => "utilities-terminal-symbolic",
        "Mail" => "mail-unread-symbolic",
        _ => "application-x-executable-symbolic",
    }
}

/// True for loopback / unspecified peers, including IPv4-mapped IPv6 forms
/// like `::ffff:127.0.0.1` that `IpAddr::is_loopback` alone misses.
fn is_local_addr(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_unspecified(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.is_loopback() || v4.is_unspecified(),
            None => v6.is_loopback() || v6.is_unspecified(),
        },
    }
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
        pub stat_status: RefCell<Option<gtk4::Label>>,
        // Connections hub
        pub connections_hub: RefCell<Option<gtk4::Frame>>,
        pub app_flow: RefCell<Option<gtk4::FlowBox>>,
        pub conn_chip: RefCell<Option<gtk4::Label>>,
        // Analytics: donut
        pub donut: RefCell<Option<DonutChart>>,
        pub donut_total: RefCell<Option<gtk4::Label>>,
        pub donut_active_val: RefCell<Option<gtk4::Label>>,
        pub donut_blocked_val: RefCell<Option<gtk4::Label>>,
        pub donut_idle_val: RefCell<Option<gtk4::Label>>,
        // Analytics: protocols + countries
        pub proto_box: RefCell<Option<gtk4::Box>>,
        pub country_box: RefCell<Option<gtk4::Box>>,
        // Analytics: network activity chart
        pub network_chart: RefCell<Option<NetworkActivityChart>>,
        pub rate_label: RefCell<Option<gtk4::Label>>,
        // Live state
        pub blocked_count: Cell<usize>,
        // Previous cumulative (bytes_in, bytes_out) per socket inode, for rates.
        pub prev_sock: RefCell<HashMap<u32, (u64, u64)>>,
        pub app_spark: RefCell<HashMap<String, Vec<f64>>>,
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
