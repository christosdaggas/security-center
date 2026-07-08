// Security Center - Network Exposure Page
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: MIT

//! Network Exposure tab showing listening ports and their firewall status.
//!
//! # Features
//!
//! - Display all listening network endpoints
//! - Show process names and PIDs
//! - Correlate with firewall rules
//! - Highlight risky configurations
//! - Quick actions to close ports or stop services
//!
//! # Architecture
//!
//! Network data is read from procfs (pure Rust, no shell commands).
//! Firewall status is obtained via the existing FirewallClient.

use std::cell::RefCell;

use gtk4::glib;
use gtk4::prelude::*;
use gtk4::subclass::prelude::*;
use libadwaita as adw;
use libadwaita::prelude::*;
use tracing::error;

use crate::admin::{get_service_name, FirewallStatus, ListeningEndpoint, NetworkExposure};
use crate::i18n::gettext;
use crate::ui::widgets::BarChart;
use crate::validation::validate_protocol;

glib::wrapper! {
    /// Page displaying network exposure information.
    pub struct NetworkExposurePage(ObjectSubclass<imp::NetworkExposurePage>)
        @extends gtk4::Widget, gtk4::Box,
        @implements gtk4::Accessible, gtk4::Buildable, gtk4::Orientable;
}

impl Default for NetworkExposurePage {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkExposurePage {
    pub fn new() -> Self {
        let obj: Self = glib::Object::new();
        obj.setup_ui();
        obj
    }

    fn setup_ui(&self) {
        let imp = self.imp();

        self.set_orientation(gtk4::Orientation::Vertical);
        self.set_spacing(0);

        // Header
        let header = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .spacing(12)
            .margin_start(24)
            .margin_end(24)
            .margin_top(24)
            .margin_bottom(12)
            .build();

        let title_box = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Vertical)
            .spacing(4)
            .hexpand(true)
            .build();

        let title = gtk4::Label::builder()
            .label(gettext("Network Exposure"))
            .css_classes(vec!["title-1".to_string()])
            .halign(gtk4::Align::Start)
            .build();

        let subtitle = gtk4::Label::builder()
            .label(gettext("Monitor listening ports and their firewall status"))
            .css_classes(vec!["dim-label".to_string()])
            .halign(gtk4::Align::Start)
            .build();

        title_box.append(&title);
        title_box.append(&subtitle);

        let refresh_button = gtk4::Button::builder()
            .icon_name("view-refresh-symbolic")
            .tooltip_text(gettext("Refresh"))
            .css_classes(vec!["flat".to_string()])
            .valign(gtk4::Align::Center)
            .build();

        let page = self.clone();
        refresh_button.connect_clicked(move |_| {
            page.refresh();
        });

        header.append(&title_box);
        header.append(&refresh_button);
        self.append(&header);

        // Scrollable content
        let scrolled = gtk4::ScrolledWindow::builder()
            .vexpand(true)
            .hexpand(true)
            .hscrollbar_policy(gtk4::PolicyType::Never)
            .build();

        imp.scrolled_window.replace(Some(scrolled.clone()));

        let content = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Vertical)
            .spacing(24)
            .margin_top(24)
            .margin_bottom(24)
            .margin_start(24)
            .margin_end(24)
            .hexpand(true)
            .build();

        // Summary cards
        let summary_box = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .spacing(12)
            .homogeneous(true)
            .margin_bottom(12)
            .build();

        let total_card =
            self.create_summary_card(&gettext("Total Ports"), "0", "network-server-symbolic");
        let exposed_card =
            self.create_summary_card(&gettext("Exposed"), "0", "security-low-symbolic");
        let blocked_card =
            self.create_summary_card(&gettext("Blocked"), "0", "security-high-symbolic");

        imp.total_card.replace(Some(total_card.clone()));
        imp.exposed_card.replace(Some(exposed_card.clone()));
        imp.blocked_card.replace(Some(blocked_card.clone()));

        summary_box.append(&total_card);
        summary_box.append(&exposed_card);
        summary_box.append(&blocked_card);
        content.append(&summary_box);

        // Exposed endpoints (risky)
        let exposed_header =
            Self::create_section_header("dialog-warning-symbolic", &gettext("Exposed to Network"));
        exposed_header.set_visible(false);
        imp.exposed_header.replace(Some(exposed_header.clone()));
        content.append(&exposed_header);
        let exposed_group = adw::PreferencesGroup::builder()
            .description(gettext("These ports are listening on all interfaces"))
            .visible(false)
            .build();
        imp.exposed_group.replace(Some(exposed_group.clone()));
        content.append(&exposed_group);

        // Local endpoints (safe)
        let local_header = Self::create_section_header("computer-symbolic", &gettext("Local Only"));
        local_header.set_visible(false);
        imp.local_header.replace(Some(local_header.clone()));
        content.append(&local_header);
        let local_group = adw::PreferencesGroup::builder()
            .description(gettext("These ports are only accessible locally"))
            .visible(false)
            .build();
        imp.local_group.replace(Some(local_group.clone()));
        content.append(&local_group);

        // Active connections (established sessions to remote hosts)
        let conn_header = Self::create_section_header(
            "network-transmit-receive-symbolic",
            &gettext("Active Connections"),
        );
        conn_header.set_visible(false);
        imp.connections_header.replace(Some(conn_header.clone()));
        content.append(&conn_header);

        // Top talkers — remote hosts ranked by number of open connections
        let talkers_card = self.create_chart_card(&gettext("Top Remote Hosts (by connections)"));
        let talkers_chart = BarChart::new();
        talkers_chart.set_size_request(-1, 140);
        talkers_chart.set_hexpand(true);
        talkers_chart.set_margin_top(8);
        talkers_chart.set_margin_bottom(8);
        if let Some(content_box) = talkers_card.first_child() {
            if let Some(box_content) = content_box.downcast_ref::<gtk4::Box>() {
                box_content.append(&talkers_chart);
            }
        }
        talkers_card.set_visible(false);
        imp.talkers_card.replace(Some(talkers_card.clone()));
        imp.talkers_chart.replace(Some(talkers_chart));
        content.append(&talkers_card);

        let connections_group = adw::PreferencesGroup::builder()
            .description(gettext("Established connections to remote hosts"))
            .visible(false)
            .build();
        imp.connections_group
            .replace(Some(connections_group.clone()));
        content.append(&connections_group);

        scrolled.set_child(Some(&content));
        self.append(&scrolled);

        // Status bar
        let status_bar = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .margin_start(24)
            .margin_end(24)
            .margin_top(6)
            .margin_bottom(6)
            .halign(gtk4::Align::Center)
            .build();

        let status_label = gtk4::Label::builder()
            .label(gettext("Scan to see listening ports"))
            .css_classes(vec!["dim-label".to_string()])
            .halign(gtk4::Align::Center)
            .build();

        imp.status_label.replace(Some(status_label.clone()));
        status_bar.append(&status_label);
        self.append(&status_bar);
    }

    /// Create a summary card widget.
    fn create_summary_card(&self, title: &str, value: &str, icon: &str) -> gtk4::Frame {
        let frame = gtk4::Frame::builder()
            .css_classes(vec!["card".to_string()])
            .build();

        let box_ = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Vertical)
            .spacing(6)
            .margin_start(16)
            .margin_end(16)
            .margin_top(12)
            .margin_bottom(12)
            .halign(gtk4::Align::Center)
            .build();

        let icon_widget = gtk4::Image::builder()
            .icon_name(icon)
            .pixel_size(24)
            .build();

        let value_label = gtk4::Label::builder()
            .label(value)
            .css_classes(vec!["title-1".to_string()])
            .build();

        // Store value label for updates
        value_label.set_widget_name(title);

        let title_label = gtk4::Label::builder()
            .label(title)
            .css_classes(vec!["dim-label".to_string()])
            .build();

        box_.append(&icon_widget);
        box_.append(&value_label);
        box_.append(&title_label);
        frame.set_child(Some(&box_));

        frame
    }

    /// Update a summary card's value.
    fn update_card_value(card: &gtk4::Frame, value: &str) {
        if let Some(box_) = card.child().and_then(|w| w.downcast::<gtk4::Box>().ok()) {
            let mut child = box_.first_child();
            while let Some(widget) = child {
                if let Ok(label) = widget.clone().downcast::<gtk4::Label>() {
                    if label.css_classes().iter().any(|c| c == "title-1") {
                        label.set_label(value);
                        return;
                    }
                }
                child = widget.next_sibling();
            }
        }
    }

    /// Refresh the network exposure data.
    pub fn refresh(&self) {
        let page = self.clone();

        glib::spawn_future_local(async move {
            let result = gtk4::gio::spawn_blocking(move || {
                let mut scanner = NetworkExposure::new();
                let endpoints = scanner.scan()?;
                // Established connections share the same scanner/inode map
                let connections = scanner.scan_connections().unwrap_or_default();
                // Real per-host byte totals via netlink sock_diag (best-effort)
                let talkers = crate::admin::collect_top_talkers().ok();
                // Resolve remote-host countries offline; empty when connections have no remotes
                let geo = crate::admin::GeoIp::load();
                let geo_labels: std::collections::HashMap<std::net::IpAddr, String> = connections
                    .iter()
                    .filter_map(|c| geo.country_label(c.remote_addr).map(|l| (c.remote_addr, l)))
                    .collect();
                Ok::<_, anyhow::Error>((endpoints, connections, talkers, geo_labels))
            })
            .await;

            match result {
                Ok(Ok((endpoints, connections, talkers, geo_labels))) => {
                    page.update_endpoints(endpoints);
                    page.update_connections(connections, talkers, geo_labels);
                }
                Ok(Err(e)) => {
                    error!("Failed to scan network: {}", e);
                    page.show_error(&format!("Failed to scan: {}", e));
                }
                Err(e) => {
                    error!("Task failed: {:?}", e);
                }
            }
        });
    }

    /// A titled card container matching the overview cards.
    fn create_chart_card(&self, title: &str) -> gtk4::Frame {
        let frame = gtk4::Frame::builder().build();
        frame.add_css_class("card");
        let card_content = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Vertical)
            .spacing(8)
            .margin_top(16)
            .margin_bottom(16)
            .margin_start(16)
            .margin_end(16)
            .build();
        let title_label = gtk4::Label::builder()
            .label(title)
            .css_classes(vec!["heading".to_string()])
            .halign(gtk4::Align::Start)
            .build();
        card_content.append(&title_label);
        frame.set_child(Some(&card_content));
        frame
    }

    /// Render the established-connections section.
    ///
    /// `talkers` carries real per-host byte totals from netlink sock_diag when
    /// available; otherwise the top-hosts chart falls back to connection counts.
    fn update_connections(
        &self,
        connections: Vec<crate::admin::ActiveConnection>,
        talkers: Option<Vec<crate::admin::TalkerBytes>>,
        geo_labels: std::collections::HashMap<std::net::IpAddr, String>,
    ) {
        let imp = self.imp();

        // Top talkers: prefer real byte totals, fall back to connection counts.
        {
            let ranked: Vec<(String, u64)> = match &talkers {
                Some(t) if !t.is_empty() => t
                    .iter()
                    .take(5)
                    .map(|tb| {
                        (
                            format!("{} ({})", tb.addr, format_bytes(tb.total())),
                            tb.total(),
                        )
                    })
                    .collect(),
                _ => {
                    let mut counts: std::collections::HashMap<String, u64> =
                        std::collections::HashMap::new();
                    for conn in &connections {
                        *counts.entry(conn.remote_addr.to_string()).or_insert(0) += 1;
                    }
                    let mut c: Vec<(String, u64)> = counts.into_iter().collect();
                    c.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
                    c.truncate(5);
                    c
                }
            };

            // Reflect the metric in the card title
            let title = if talkers.as_ref().is_some_and(|t| !t.is_empty()) {
                gettext("Top Remote Hosts (by traffic)")
            } else {
                gettext("Top Remote Hosts (by connections)")
            };
            if let Some(card) = imp.talkers_card.borrow().as_ref() {
                if let Some(content) = card.first_child() {
                    if let Some(label) = content.first_child().and_downcast::<gtk4::Label>() {
                        label.set_label(&title);
                    }
                }
                card.set_visible(!ranked.is_empty());
            }
            if let Some(chart) = imp.talkers_chart.borrow().as_ref() {
                chart.set_data(&ranked);
            }
        }

        // Clear previous rows
        if let Some(group) = imp.connections_group.borrow().as_ref() {
            while let Some(child) = group.first_child() {
                if child.is::<adw::ActionRow>() {
                    group.remove(&child);
                } else {
                    break;
                }
            }
        }

        // Per-host byte totals for enriching each connection row
        let bytes_by_host: std::collections::HashMap<std::net::IpAddr, u64> = talkers
            .as_ref()
            .map(|t| t.iter().map(|tb| (tb.addr, tb.total())).collect())
            .unwrap_or_default();

        // Group sockets by (process, remote host, port) so one host is one row
        // with a connection count — no more identical rows repeated per socket.
        struct ConnGroup {
            process: String,
            protocol: &'static str,
            addr: std::net::IpAddr,
            port: u16,
            count: usize,
        }
        let mut groups: Vec<ConnGroup> = Vec::new();
        for conn in &connections {
            let proc = conn.process_label();
            if let Some(g) = groups.iter_mut().find(|g| {
                g.process == proc && g.addr == conn.remote_addr && g.port == conn.remote_port
            }) {
                g.count += 1;
            } else {
                groups.push(ConnGroup {
                    process: proc,
                    protocol: conn.protocol.as_str(),
                    addr: conn.remote_addr,
                    port: conn.remote_port,
                    count: 1,
                });
            }
        }
        // Highest-traffic hosts first
        groups.sort_by(|a, b| {
            let ba = bytes_by_host.get(&a.addr).copied().unwrap_or(0);
            let bb = bytes_by_host.get(&b.addr).copied().unwrap_or(0);
            bb.cmp(&ba).then(b.count.cmp(&a.count))
        });

        let has_any = !groups.is_empty();
        if let Some(group) = imp.connections_group.borrow().as_ref() {
            for g in &groups {
                let title = format!("{} → {}:{}", g.process, g.addr, g.port);

                let mut parts: Vec<String> = vec![g.protocol.to_string()];
                if g.count > 1 {
                    parts.push(format!("{} connections", g.count));
                }
                if let Some(&total) = bytes_by_host.get(&g.addr) {
                    parts.push(format_bytes(total));
                }
                let subtitle = parts.join(" · ");

                let row = adw::ActionRow::builder()
                    .title(glib::markup_escape_text(&title).as_str())
                    .subtitle(glib::markup_escape_text(&subtitle).as_str())
                    .build();
                row.add_prefix(&gtk4::Image::from_icon_name(
                    "network-transmit-receive-symbolic",
                ));

                // Country flag (offline GeoIP) when the remote resolves
                if let Some(label) = geo_labels.get(&g.addr) {
                    let flag = gtk4::Label::builder()
                        .label(label)
                        .css_classes(vec!["caption".to_string()])
                        .valign(gtk4::Align::Center)
                        .build();
                    row.add_suffix(&flag);
                }
                if let Some(service) = get_service_name(g.port) {
                    let badge = gtk4::Label::builder()
                        .label(service)
                        .css_classes(vec!["caption".to_string(), "dim-label".to_string()])
                        .valign(gtk4::Align::Center)
                        .build();
                    row.add_suffix(&badge);
                }
                group.add(&row);
            }
            group.set_visible(has_any);
        }
        if let Some(header) = imp.connections_header.borrow().as_ref() {
            header.set_visible(has_any);
        }
    }

    /// Update the UI with scanned endpoints.
    fn update_endpoints(&self, endpoints: Vec<ListeningEndpoint>) {
        let imp = self.imp();

        // Clear existing rows
        self.clear_groups();

        let mut exposed_count = 0;
        let mut blocked_count = 0;
        let total = endpoints.len();

        // Store endpoints
        imp.endpoints.replace(endpoints.clone());

        for endpoint in &endpoints {
            let row = self.create_endpoint_row(endpoint);

            if endpoint.is_exposed() {
                if let Some(group) = imp.exposed_group.borrow().as_ref() {
                    group.add(&row);
                    group.set_visible(true);
                }
                if let Some(header) = imp.exposed_header.borrow().as_ref() {
                    header.set_visible(true);
                }
                exposed_count += 1;
            } else {
                if let Some(group) = imp.local_group.borrow().as_ref() {
                    group.add(&row);
                    group.set_visible(true);
                }
                if let Some(header) = imp.local_header.borrow().as_ref() {
                    header.set_visible(true);
                }
            }

            if matches!(endpoint.firewall_status, FirewallStatus::Blocked) {
                blocked_count += 1;
            }
        }

        // Update summary cards
        if let Some(card) = imp.total_card.borrow().as_ref() {
            Self::update_card_value(card, &total.to_string());
        }
        if let Some(card) = imp.exposed_card.borrow().as_ref() {
            Self::update_card_value(card, &exposed_count.to_string());
        }
        if let Some(card) = imp.blocked_card.borrow().as_ref() {
            Self::update_card_value(card, &blocked_count.to_string());
        }

        // Update status
        if let Some(label) = imp.status_label.borrow().as_ref() {
            label.set_label(&format!(
                "Found {} listening ports ({} exposed, {} blocked by firewall)",
                total, exposed_count, blocked_count
            ));
        }
    }

    /// Clear all endpoint rows.
    fn clear_groups(&self) {
        let imp = self.imp();

        for group_ref in [&imp.exposed_group, &imp.local_group] {
            if let Some(group) = group_ref.borrow().as_ref() {
                while let Some(child) = group.first_child() {
                    if child.is::<adw::ActionRow>() || child.is::<adw::ExpanderRow>() {
                        group.remove(&child);
                    } else {
                        break;
                    }
                }
            }
        }
    }

    /// Create a row for an endpoint.
    fn create_endpoint_row(&self, endpoint: &ListeningEndpoint) -> adw::ExpanderRow {
        let port_label = if let Some(service) = get_service_name(endpoint.port) {
            format!("{} ({})", endpoint.port, service)
        } else {
            endpoint.port.to_string()
        };

        let process_name = endpoint
            .process_name
            .clone()
            .unwrap_or_else(|| gettext("Unknown Process"));

        let row = adw::ExpanderRow::builder()
            .title(&port_label)
            .subtitle(format!("{} • {}", process_name, endpoint.protocol.as_str()))
            .build();

        // Status icon based on exposure
        let icon_name = if endpoint.is_exposed() {
            "security-low-symbolic"
        } else {
            "security-high-symbolic"
        };

        let status_icon = gtk4::Image::builder().icon_name(icon_name).build();
        row.add_prefix(&status_icon);

        // Firewall status badge
        let fw_label = gtk4::Label::builder()
            .label(endpoint.firewall_status.label())
            .css_classes(vec!["caption".to_string()])
            .valign(gtk4::Align::Center)
            .build();

        match &endpoint.firewall_status {
            FirewallStatus::Allowed { .. } => {
                fw_label.add_css_class("warning");
            }
            FirewallStatus::Blocked => {
                fw_label.add_css_class("success");
            }
            _ => {}
        }

        row.add_suffix(&fw_label);

        // Warning if risky
        if let Some(warning) = endpoint.warning() {
            let warning_row = adw::ActionRow::builder()
                .title("⚠️ Warning")
                .subtitle(warning)
                .build();
            row.add_row(&warning_row);
        }

        // Details row
        let details_row = adw::ActionRow::builder()
            .title(gettext("Listening Address"))
            .subtitle(format!("{}:{}", endpoint.local_addr, endpoint.port))
            .build();
        row.add_row(&details_row);

        // Process info
        if let Some(pid) = endpoint.pid {
            let mut subtitle = format!("PID: {}", pid);
            if let Some(cmdline) = &endpoint.cmdline {
                let truncated: String = cmdline.chars().take(60).collect();
                subtitle = format!("{} • {}", subtitle, truncated);
            }

            let process_row = adw::ActionRow::builder()
                .title(gettext("Process"))
                .subtitle(&subtitle)
                .build();
            row.add_row(&process_row);
        }

        // Actions row
        let actions_row = adw::ActionRow::builder().title(gettext("Actions")).build();

        let button_box = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .spacing(6)
            .valign(gtk4::Align::Center)
            .build();

        // Stop service button (if we know the process)
        if let Some(process_name) = &endpoint.process_name {
            let stop_btn = gtk4::Button::builder()
                .label(gettext("Stop Service"))
                .css_classes(vec!["flat".to_string()])
                .tooltip_text(gettext("Stop the systemd service using this port"))
                .build();

            let unit = format!("{}.service", process_name);
            let display = process_name.clone();
            let page_clone = self.clone();
            stop_btn.connect_clicked(move |btn| {
                btn.set_sensitive(false);
                page_clone.confirm_stop_service(&unit, &display, btn.clone());
            });
            button_box.append(&stop_btn);
        }

        // Block port button (red with white text)
        let block_btn = gtk4::Button::builder()
            .label(gettext("Block Port"))
            .css_classes(vec!["destructive-action".to_string()])
            .tooltip_text(gettext("Add a firewall rule to block this port"))
            .build();

        // Connect to firewall block action
        let port = endpoint.port;
        let protocol = endpoint.protocol.as_str().to_lowercase();
        let page_clone = self.clone();
        block_btn.connect_clicked(move |btn| {
            btn.set_sensitive(false);
            page_clone.block_port(port, &protocol);
        });

        button_box.append(&block_btn);

        actions_row.add_suffix(&button_box);
        row.add_row(&actions_row);

        row
    }

    /// Confirm, then stop a systemd service via D-Bus (polkit-authenticated).
    fn confirm_stop_service(&self, unit: &str, display: &str, btn: gtk4::Button) {
        let page = self.clone();
        let unit = unit.to_string();
        let display = display.to_string();

        let dialog = adw::AlertDialog::builder()
            .heading(format!("Stop {}?", display))
            .body(format!(
                "This stops the systemd unit '{}'. The service will no longer \
                 listen on this port until it is started again.",
                unit
            ))
            .build();
        dialog.add_response("cancel", "_Cancel");
        dialog.add_response("stop", "_Stop Service");
        dialog.set_response_appearance("stop", adw::ResponseAppearance::Destructive);
        dialog.set_default_response(Some("cancel"));

        let btn_for_response = btn.clone();
        dialog.connect_response(None, move |_, response| {
            if response != "stop" {
                btn_for_response.set_sensitive(true);
                return;
            }

            let page = page.clone();
            let unit = unit.clone();
            let display = display.clone();
            let btn = btn_for_response.clone();
            glib::spawn_future_local(async move {
                let unit_clone = unit.clone();
                let result = gtk4::gio::spawn_blocking(move || {
                    let mut client = crate::systemd::SystemdClient::new();
                    client.connect()?;
                    client.stop_service(&unit_clone)
                })
                .await;

                match result {
                    Ok(Ok(())) => {
                        page.show_toast(&format!("Stopped {}", display));
                        page.refresh();
                    }
                    Ok(Err(e)) => {
                        page.show_toast(&format!("Failed to stop {}: {}", display, e));
                        btn.set_sensitive(true);
                    }
                    Err(_) => {
                        page.show_toast(&format!("Failed to stop {}", display));
                        btn.set_sensitive(true);
                    }
                }
            });
        });

        if let Some(root) = self.root() {
            if let Some(window) = root.downcast_ref::<gtk4::Window>() {
                dialog.present(Some(window));
            }
        }
    }

    /// Block a port by adding a reject rich rule.
    fn block_port(&self, port: u16, protocol: &str) {
        let page = self.clone();
        let port_str = port.to_string();
        let protocol = protocol.to_string();

        glib::spawn_future_local(async move {
            let port_clone = port_str.clone();
            let protocol_clone = protocol.clone();

            let result = gtk4::gio::spawn_blocking(move || {
                let mut client = crate::firewall::FirewallClient::new();
                if let Err(e) = client.connect() {
                    return Err(anyhow::anyhow!("Failed to connect to firewalld: {}", e));
                }

                // Get the default zone to add the rule to
                let zone = client
                    .get_default_zone()
                    .unwrap_or_else(|_| "public".to_string());

                // Validate protocol before constructing rich rule
                let valid_proto = validate_protocol(&protocol_clone)
                    .ok_or_else(|| anyhow::anyhow!("Invalid protocol: {}", protocol_clone))?;

                // Add rich rule to reject connections on this port.
                // No family attribute so the block covers IPv4 and IPv6.
                let rule = format!(
                    "rule port port=\"{}\" protocol=\"{}\" reject",
                    port_clone, valid_proto
                );

                // Add once with permanent=true: the client writes both runtime
                // and permanent config in a single call and reports the outcome
                let outcome = client.add_rich_rule(&zone, &rule, true)?;

                Ok((zone, outcome.failed()))
            })
            .await;

            match result {
                Ok(Ok((zone, permanent_failed))) => {
                    if permanent_failed {
                        page.show_toast(&format!(
                            "Port {}/{} blocked in '{}' for this session only — saving permanently failed",
                            port_str, protocol, zone
                        ));
                    } else {
                        page.show_toast(&format!(
                            "Port {}/{} blocked in zone '{}'",
                            port_str, protocol, zone
                        ));
                    }
                    // Refresh to show updated status
                    page.refresh();
                    // Also refresh main window data so Ports page updates
                    page.request_refresh();
                }
                Ok(Err(e)) => {
                    error!("Failed to block port: {}", e);
                    page.show_toast(&format!("{}: {}", gettext("Failed to block port"), e));
                }
                Err(_e) => {
                    error!("Task failed");
                    page.show_toast(&gettext("Failed to block port"));
                }
            }
        });
    }

    /// Show a toast notification.
    fn show_toast(&self, message: &str) {
        if let Some(root) = self.root() {
            if let Some(window) = root.downcast_ref::<gtk4::Window>() {
                if let Some(main_window) = window.downcast_ref::<super::MainWindow>() {
                    main_window.show_toast(message);
                }
            }
        }
    }

    /// Request a global refresh from the main window.
    fn request_refresh(&self) {
        if let Some(root) = self.root() {
            if let Some(window) = root.downcast_ref::<gtk4::Window>() {
                if let Some(main_window) = window.downcast_ref::<super::MainWindow>() {
                    main_window.refresh_data();
                }
            }
        }
    }

    /// Show an error message.
    fn show_error(&self, message: &str) {
        error!("Error: {}", message);
    }
    /// Create a section header with icon on the left.
    fn create_section_header(icon_name: &str, title: &str) -> gtk4::Box {
        let header = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .spacing(8)
            .margin_bottom(6)
            .build();

        let icon = gtk4::Image::builder()
            .icon_name(icon_name)
            .css_classes(vec!["heading".to_string()])
            .build();

        let label = gtk4::Label::builder()
            .label(title)
            .css_classes(vec!["heading".to_string()])
            .halign(gtk4::Align::Start)
            .build();

        header.append(&icon);
        header.append(&label);
        header
    }
}

/// Format a byte count as a compact human-readable string (B/KB/MB/GB).
fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{} {}", bytes, UNITS[unit])
    } else {
        format!("{:.1} {}", value, UNITS[unit])
    }
}

mod imp {
    use super::*;

    #[derive(Default)]
    pub struct NetworkExposurePage {
        pub scrolled_window: RefCell<Option<gtk4::ScrolledWindow>>,
        pub total_card: RefCell<Option<gtk4::Frame>>,
        pub exposed_card: RefCell<Option<gtk4::Frame>>,
        pub blocked_card: RefCell<Option<gtk4::Frame>>,
        pub exposed_header: RefCell<Option<gtk4::Box>>,
        pub exposed_group: RefCell<Option<adw::PreferencesGroup>>,
        pub local_header: RefCell<Option<gtk4::Box>>,
        pub local_group: RefCell<Option<adw::PreferencesGroup>>,
        pub connections_header: RefCell<Option<gtk4::Box>>,
        pub connections_group: RefCell<Option<adw::PreferencesGroup>>,
        pub talkers_card: RefCell<Option<gtk4::Frame>>,
        pub talkers_chart: RefCell<Option<BarChart>>,
        pub status_label: RefCell<Option<gtk4::Label>>,
        pub endpoints: RefCell<Vec<ListeningEndpoint>>,
    }

    #[glib::object_subclass]
    impl ObjectSubclass for NetworkExposurePage {
        const NAME: &'static str = "SecurityCenterNetworkExposurePage";
        type Type = super::NetworkExposurePage;
        type ParentType = gtk4::Box;
    }

    impl ObjectImpl for NetworkExposurePage {}
    impl WidgetImpl for NetworkExposurePage {}
    impl BoxImpl for NetworkExposurePage {}
}
