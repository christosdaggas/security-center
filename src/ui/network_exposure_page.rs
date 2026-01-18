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

use gtk4::prelude::*;
use gtk4::subclass::prelude::*;
use gtk4::glib;
use libadwaita as adw;
use libadwaita::prelude::*;
use tracing::error;

use crate::admin::{ListeningEndpoint, NetworkExposure, FirewallStatus, get_service_name};

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
            .label("Network Exposure")
            .css_classes(vec!["title-1".to_string()])
            .halign(gtk4::Align::Start)
            .build();

        let subtitle = gtk4::Label::builder()
            .label("Monitor listening ports and their firewall status")
            .css_classes(vec!["dim-label".to_string()])
            .halign(gtk4::Align::Start)
            .build();

        title_box.append(&title);
        title_box.append(&subtitle);

        let refresh_button = gtk4::Button::builder()
            .icon_name("view-refresh-symbolic")
            .tooltip_text("Refresh")
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

        let total_card = self.create_summary_card("Total Ports", "0", "network-server-symbolic");
        let exposed_card = self.create_summary_card("Exposed", "0", "security-low-symbolic");
        let blocked_card = self.create_summary_card("Blocked", "0", "security-high-symbolic");

        imp.total_card.replace(Some(total_card.clone()));
        imp.exposed_card.replace(Some(exposed_card.clone()));
        imp.blocked_card.replace(Some(blocked_card.clone()));

        summary_box.append(&total_card);
        summary_box.append(&exposed_card);
        summary_box.append(&blocked_card);
        content.append(&summary_box);

        // Exposed endpoints (risky)
        let exposed_header = Self::create_section_header("dialog-warning-symbolic", "Exposed to Network");
        exposed_header.set_visible(false);
        imp.exposed_header.replace(Some(exposed_header.clone()));
        content.append(&exposed_header);
        let exposed_group = adw::PreferencesGroup::builder()
            .description("These ports are listening on all interfaces")
            .visible(false)
            .build();
        imp.exposed_group.replace(Some(exposed_group.clone()));
        content.append(&exposed_group);

        // Local endpoints (safe)
        let local_header = Self::create_section_header("computer-symbolic", "Local Only");
        local_header.set_visible(false);
        imp.local_header.replace(Some(local_header.clone()));
        content.append(&local_header);
        let local_group = adw::PreferencesGroup::builder()
            .description("These ports are only accessible locally")
            .visible(false)
            .build();
        imp.local_group.replace(Some(local_group.clone()));
        content.append(&local_group);

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
            .label("Scan to see listening ports")
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
                scanner.scan()
            })
            .await;

            match result {
                Ok(Ok(endpoints)) => {
                    page.update_endpoints(endpoints);
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

        let process_name = endpoint.process_name.clone().unwrap_or_else(|| "Unknown Process".to_string());

        let row = adw::ExpanderRow::builder()
            .title(&port_label)
            .subtitle(&format!("{} • {}", process_name, endpoint.protocol.as_str()))
            .build();

        // Status icon based on exposure
        let icon_name = if endpoint.is_exposed() {
            "security-low-symbolic"
        } else {
            "security-high-symbolic"
        };

        let status_icon = gtk4::Image::builder()
            .icon_name(icon_name)
            .build();
        row.add_prefix(&status_icon);

        // Firewall status badge
        let fw_label = gtk4::Label::builder()
            .label(&endpoint.firewall_status.label())
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
            .title("Listening Address")
            .subtitle(&format!("{}:{}", endpoint.local_addr, endpoint.port))
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
                .title("Process")
                .subtitle(&subtitle)
                .build();
            row.add_row(&process_row);
        }

        // Actions row
        let actions_row = adw::ActionRow::builder()
            .title("Actions")
            .build();

        let button_box = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .spacing(6)
            .valign(gtk4::Align::Center)
            .build();

        // Stop service button (if we know the process)
        if endpoint.process_name.is_some() {
            let stop_btn = gtk4::Button::builder()
                .label("Stop Service")
                .css_classes(vec!["flat".to_string()])
                .tooltip_text("Stop the service using this port")
                .build();

            // TODO: Connect to service stop action
            button_box.append(&stop_btn);
        }

        // Block port button (red with white text)
        let block_btn = gtk4::Button::builder()
            .label("Block Port")
            .css_classes(vec!["destructive-action".to_string()])
            .tooltip_text("Add a firewall rule to block this port")
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
                let zone = client.get_default_zone()
                    .unwrap_or_else(|_| "public".to_string());

                // Add rich rule to reject connections on this port
                let rule = format!(
                    "rule family=\"ipv4\" port port=\"{}\" protocol=\"{}\" reject",
                    port_clone, protocol_clone
                );

                // Add to both runtime and permanent config
                client.add_rich_rule(&zone, &rule, false)?;
                client.add_rich_rule(&zone, &rule, true)?;

                Ok(zone)
            }).await;

            match result {
                Ok(Ok(zone)) => {
                    page.show_toast(&format!("Port {}/{} blocked in zone '{}'", port_str, protocol, zone));
                    // Refresh to show updated status
                    page.refresh();
                    // Also refresh main window data so Ports page updates
                    page.request_refresh();
                }
                Ok(Err(e)) => {
                    error!("Failed to block port: {}", e);
                    page.show_toast(&format!("Failed to block port: {}", e));
                }
                Err(_e) => {
                    error!("Task failed");
                    page.show_toast("Failed to block port");
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
