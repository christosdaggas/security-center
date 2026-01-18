// Security Center - Services Page
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: MIT

//! Services management page.

use std::cell::RefCell;
use std::rc::Rc;

use gtk4::prelude::*;
use gtk4::subclass::prelude::*;
use gtk4::glib;
use libadwaita as adw;
use libadwaita::prelude::*;

use crate::firewall::FirewallClient;
use crate::models::Service;

glib::wrapper! {
    /// Services page showing firewall services.
    pub struct ServicesPage(ObjectSubclass<imp::ServicesPage>)
        @extends gtk4::Box, gtk4::Widget,
        @implements gtk4::Orientable;
}

impl ServicesPage {
    /// Create a new services page.
    pub fn new() -> Self {
        let page: Self = glib::Object::new();
        page.setup_ui();
        page
    }

    /// Set the firewall client for operations.
    pub fn set_client(&self, client: Rc<RefCell<FirewallClient>>) {
        self.imp().client.replace(Some(client));
    }

    /// Setup the UI.
    fn setup_ui(&self) {
        let imp = self.imp();

        self.set_orientation(gtk4::Orientation::Vertical);
        self.set_spacing(0);

        // Header
        let header_box = gtk4::Box::builder()
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
            .label("Services")
            .css_classes(vec!["title-1".to_string()])
            .halign(gtk4::Align::Start)
            .build();

        let subtitle = gtk4::Label::builder()
            .label("Enable or disable network services in the firewall")
            .css_classes(vec!["dim-label".to_string()])
            .halign(gtk4::Align::Start)
            .build();

        title_box.append(&title);
        title_box.append(&subtitle);
        header_box.append(&title_box);
        self.append(&header_box);

        // Scrolled container
        let scrolled = gtk4::ScrolledWindow::builder()
            .vexpand(true)
            .hexpand(true)
            .hscrollbar_policy(gtk4::PolicyType::Never)
            .build();
        self.append(&scrolled);

        // Main content - no clamp for full width
        let content = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Vertical)
            .spacing(24)
            .margin_top(24)
            .margin_bottom(24)
            .margin_start(24)
            .margin_end(24)
            .hexpand(true)
            .build();
        scrolled.set_child(Some(&content));

        // Info banner about authentication
        let info_banner = adw::Banner::builder()
            .title("Authentication may be required to modify services")
            .revealed(true)
            .build();
        content.append(&info_banner);

        // Enabled services group
        content.append(&Self::create_section_header("preferences-system-symbolic", "Enabled Services"));
        let enabled_group = adw::PreferencesGroup::builder()
            .description("Services allowing traffic through the firewall")
            .build();
        content.append(&enabled_group);
        imp.enabled_group.replace(Some(enabled_group));

        // Common services group (for quick enable)
        content.append(&Self::create_section_header("starred-symbolic", "Common Services"));
        let common_group = adw::PreferencesGroup::builder()
            .description("Frequently used network services")
            .build();
        content.append(&common_group);
        imp.common_group.replace(Some(common_group));
    }

    /// Set the default zone for operations.
    pub fn set_default_zone(&self, zone: &str) {
        self.imp().default_zone.replace(zone.to_string());
    }

    /// Update the page with service data.
    pub fn set_services(&self, services: &[Service]) {
        let imp = self.imp();

        // Clear ALL existing rows from both groups using helper
        Self::clear_preferences_group(imp.enabled_group.borrow().as_ref());
        Self::clear_preferences_group(imp.common_group.borrow().as_ref());

        // Common service names to highlight
        let common_names = [
            "ssh", "http", "https", "dns", "dhcp", "samba", 
            "ftp", "nfs", "mdns", "cockpit", "vnc-server", "rdp"
        ];

        let mut enabled_services: Vec<_> = services.iter()
            .filter(|s| s.is_enabled)
            .collect();
        enabled_services.sort_by(|a, b| a.name.cmp(&b.name));

        let mut common_services: Vec<_> = services.iter()
            .filter(|s| !s.is_enabled && common_names.contains(&s.name.as_str()))
            .collect();
        common_services.sort_by(|a, b| a.name.cmp(&b.name));

        // Add enabled services
        if enabled_services.is_empty() {
            if let Some(group) = imp.enabled_group.borrow().as_ref() {
                let placeholder = adw::ActionRow::builder()
                    .title("No services enabled")
                    .subtitle("Enable services to allow specific traffic")
                    .sensitive(false)
                    .build();
                group.add(&placeholder);
            }
        } else {
            for service in enabled_services {
                self.add_service_row(service, true);
            }
        }

        // Add common services (limited to 10)
        for service in common_services.into_iter().take(10) {
            self.add_service_row(service, false);
        }
    }

    /// Helper to clear all rows from a PreferencesGroup.
    fn clear_preferences_group(group: Option<&adw::PreferencesGroup>) {
        if let Some(group) = group {
            // Collect all rows first to avoid modification during iteration
            let mut rows_to_remove: Vec<gtk4::Widget> = Vec::new();
            
            // Recursively find all ActionRow and ExpanderRow widgets
            fn find_rows(widget: &gtk4::Widget, rows: &mut Vec<gtk4::Widget>) {
                // Check if this widget is a row type
                if widget.downcast_ref::<adw::ActionRow>().is_some() 
                    || widget.downcast_ref::<adw::ExpanderRow>().is_some() {
                    rows.push(widget.clone());
                }
                // Check children
                if let Some(first) = widget.first_child() {
                    let mut child = Some(first);
                    while let Some(c) = child {
                        find_rows(&c, rows);
                        child = c.next_sibling();
                    }
                }
            }
            
            // Find all rows in the group
            if let Some(first) = group.first_child() {
                let mut child = Some(first);
                while let Some(c) = child {
                    find_rows(&c, &mut rows_to_remove);
                    child = c.next_sibling();
                }
            }
            
            // Remove each row using the group's remove method
            for row in rows_to_remove {
                group.remove(&row);
            }
        }
    }

    /// Add a service row to the appropriate group.
    fn add_service_row(&self, service: &Service, enabled: bool) {
        let imp = self.imp();
        
        let group = if enabled {
            imp.enabled_group.borrow()
        } else {
            imp.common_group.borrow()
        };

        if let Some(group) = group.as_ref() {
            let row = adw::ActionRow::builder()
                .title(&service.name)
                .subtitle(service.human_description())
                .build();

            // Service icon
            let icon_name = self.get_service_icon(&service.name);
            row.add_prefix(&gtk4::Image::from_icon_name(icon_name));

            // Ports badge
            let ports_summary = service.ports_summary();
            if !ports_summary.is_empty() {
                let ports_label = gtk4::Label::builder()
                    .label(&ports_summary)
                    .css_classes(vec!["caption".to_string(), "dim-label".to_string()])
                    .valign(gtk4::Align::Center)
                    .build();
                row.add_suffix(&ports_label);
            }

            // Toggle switch
            let switch = gtk4::Switch::builder()
                .active(enabled)
                .valign(gtk4::Align::Center)
                .tooltip_text(if enabled { "Disable service" } else { "Enable service" })
                .build();

            let service_name = service.name.clone();
            let page = self.clone();
            let is_enabled = enabled;

            switch.connect_state_set(move |switch, state| {
                // Prevent loops
                if state == is_enabled {
                    return glib::Propagation::Stop;
                }

                let service_name = service_name.clone();
                let page = page.clone();
                let switch = switch.clone();

                switch.set_sensitive(false);

                if state {
                    page.enable_service(&service_name, switch);
                } else {
                    page.disable_service(&service_name, switch);
                }

                glib::Propagation::Proceed
            });

            row.add_suffix(&switch);
            group.add(&row);
        }
    }

    /// Get appropriate icon for service type.
    fn get_service_icon(&self, name: &str) -> &'static str {
        match name {
            "ssh" => "utilities-terminal-symbolic",
            "http" | "https" => "web-browser-symbolic",
            "ftp" => "folder-remote-symbolic",
            "dns" => "network-server-symbolic",
            "dhcp" | "dhcpv6" | "dhcpv6-client" => "network-wired-symbolic",
            "samba" | "samba-client" => "folder-publicshare-symbolic",
            "nfs" | "nfs3" => "folder-remote-symbolic",
            "vnc-server" | "rdp" => "computer-symbolic",
            "smtp" | "smtps" | "imap" | "imaps" | "pop3" | "pop3s" => "mail-send-symbolic",
            "mdns" => "network-workgroup-symbolic",
            "cockpit" => "preferences-system-symbolic",
            _ => "application-x-executable-symbolic",
        }
    }

    /// Enable a service.
    fn enable_service(&self, name: &str, switch: gtk4::Switch) {
        let imp = self.imp();
        let zone = imp.default_zone.borrow().clone();
        let service_name = name.to_string();
        let page = self.clone();
        
        glib::spawn_future_local(async move {
            let service_clone = service_name.clone();
            let zone_clone = zone.clone();
            let result = gtk4::gio::spawn_blocking(move || {
                let mut client = crate::firewall::FirewallClient::new();
                if client.connect().is_err() {
                    return Err(anyhow::anyhow!("Not connected to firewalld"));
                }
                client.enable_service(&zone_clone, &service_clone, true)
            }).await;

            match result {
                Ok(Ok(())) => {
                    page.show_toast(&format!("Service '{}' enabled", service_name));
                    page.request_refresh();
                }
                Ok(Err(e)) => {
                    switch.set_active(false);
                    page.show_toast(&format!("Failed to enable service: {}", e));
                }
                Err(_) => {
                    switch.set_active(false);
                    page.show_toast("Failed to enable service");
                }
            }
            switch.set_sensitive(true);
        });
    }

    /// Disable a service.
    fn disable_service(&self, name: &str, switch: gtk4::Switch) {
        let imp = self.imp();
        let zone = imp.default_zone.borrow().clone();
        let service_name = name.to_string();
        let page = self.clone();
        
        glib::spawn_future_local(async move {
            let service_clone = service_name.clone();
            let zone_clone = zone.clone();
            let result = gtk4::gio::spawn_blocking(move || {
                let mut client = crate::firewall::FirewallClient::new();
                if client.connect().is_err() {
                    return Err(anyhow::anyhow!("Not connected to firewalld"));
                }
                client.disable_service(&zone_clone, &service_clone, true)
            }).await;

            match result {
                Ok(Ok(())) => {
                    page.show_toast(&format!("Service '{}' disabled", service_name));
                    page.request_refresh();
                }
                Ok(Err(e)) => {
                    switch.set_active(true);
                    page.show_toast(&format!("Failed to disable service: {}", e));
                }
                Err(_) => {
                    switch.set_active(true);
                    page.show_toast("Failed to disable service");
                }
            }
            switch.set_sensitive(true);
        });
    }

    /// Request a refresh from the main window.
    fn request_refresh(&self) {
        if let Some(root) = self.root() {
            if let Some(window) = root.downcast_ref::<gtk4::Window>() {
                if let Some(main_window) = window.downcast_ref::<super::MainWindow>() {
                    main_window.refresh_data();
                }
            }
        }
    }

    /// Show a toast message.
    fn show_toast(&self, message: &str) {
        if let Some(root) = self.root() {
            if let Some(window) = root.downcast_ref::<gtk4::Window>() {
                if let Some(main_window) = window.downcast_ref::<super::MainWindow>() {
                    main_window.show_toast(message);
                }
            }
        }
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

impl Default for ServicesPage {
    fn default() -> Self {
        Self::new()
    }
}

mod imp {
    use super::*;

    #[derive(Default)]
    pub struct ServicesPage {
        pub enabled_group: RefCell<Option<adw::PreferencesGroup>>,
        pub common_group: RefCell<Option<adw::PreferencesGroup>>,
        pub default_zone: RefCell<String>,
        pub client: RefCell<Option<Rc<RefCell<FirewallClient>>>>,
    }

    #[glib::object_subclass]
    impl ObjectSubclass for ServicesPage {
        const NAME: &'static str = "SecurityCenterServicesPage";
        type Type = super::ServicesPage;
        type ParentType = gtk4::Box;
    }

    impl ObjectImpl for ServicesPage {}
    impl WidgetImpl for ServicesPage {}
    impl BoxImpl for ServicesPage {}
}
