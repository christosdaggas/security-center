// Security Center - Services Page
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: MIT

//! Services management page.

use std::cell::RefCell;
use std::rc::Rc;

use gtk4::glib;
use gtk4::prelude::*;
use gtk4::subclass::prelude::*;
use libadwaita as adw;
use libadwaita::prelude::*;

use crate::firewall::FirewallClient;
use crate::i18n::gettext;
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
            .label(gettext("Services"))
            .css_classes(vec!["title-1".to_string()])
            .halign(gtk4::Align::Start)
            .build();

        let subtitle = gtk4::Label::builder()
            .label(gettext(
                "Enable or disable network services in the firewall",
            ))
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
            .title(gettext("Authentication may be required to modify services"))
            .revealed(true)
            .build();
        content.append(&info_banner);

        // Zone selector — enable/disable applies to the chosen zone
        let zone_group = adw::PreferencesGroup::builder().build();
        let zone_dropdown = adw::ComboRow::builder()
            .title(gettext("Zone"))
            .subtitle(gettext("Services are enabled or disabled in this zone"))
            .model(&gtk4::StringList::new(&[]))
            .build();
        zone_dropdown.add_prefix(&gtk4::Image::from_icon_name("network-server-symbolic"));
        let page_for_zone = self.clone();
        zone_dropdown.connect_selected_notify(move |row| {
            if let Some(model) = row.model() {
                if let Some(item) = model.item(row.selected()) {
                    if let Some(s) = item.downcast_ref::<gtk4::StringObject>() {
                        page_for_zone
                            .imp()
                            .selected_zone
                            .replace(s.string().to_string());
                        // Re-render so enabled state reflects the selected zone
                        let services = page_for_zone.imp().services.borrow().clone();
                        page_for_zone.render_services(&services);
                    }
                }
            }
        });
        zone_group.add(&zone_dropdown);
        content.append(&zone_group);
        imp.zone_dropdown.replace(Some(zone_dropdown));

        // Search filter over the full service list
        let search_entry = gtk4::SearchEntry::builder()
            .placeholder_text(gettext(
                "Search services (e.g. postgresql, wireguard, mosh)",
            ))
            .hexpand(true)
            .build();
        let page_for_search = self.clone();
        search_entry.connect_search_changed(move |entry| {
            page_for_search
                .imp()
                .search_text
                .replace(entry.text().to_string().to_lowercase());
            let services = page_for_search.imp().services.borrow().clone();
            page_for_search.render_services(&services);
        });
        content.append(&search_entry);

        // Enabled services group
        content.append(&Self::create_section_header(
            "preferences-system-symbolic",
            &gettext("Enabled Services"),
        ));
        let enabled_group = adw::PreferencesGroup::builder()
            .description(gettext("Services allowing traffic through the firewall"))
            .build();
        content.append(&enabled_group);
        imp.enabled_group.replace(Some(enabled_group));

        // All services group — every firewalld service definition
        content.append(&Self::create_section_header(
            "view-list-symbolic",
            &gettext("All Services"),
        ));
        let all_group = adw::PreferencesGroup::builder()
            .description(gettext("Every service firewalld knows about"))
            .build();
        content.append(&all_group);
        imp.all_group.replace(Some(all_group));
    }

    /// Set the default zone for operations.
    pub fn set_default_zone(&self, zone: &str) {
        let imp = self.imp();
        imp.default_zone.replace(zone.to_string());
        // Adopt the default as the selected zone until the user changes it
        if imp.selected_zone.borrow().is_empty() {
            imp.selected_zone.replace(zone.to_string());
        }
    }

    /// Provide the available zones for the zone selector.
    pub fn set_available_zones(&self, zones: &[String]) {
        let imp = self.imp();
        imp.available_zones.replace(zones.to_vec());

        if let Some(dropdown) = imp.zone_dropdown.borrow().as_ref() {
            let model =
                gtk4::StringList::new(&zones.iter().map(|z| z.as_str()).collect::<Vec<_>>());
            dropdown.set_model(Some(&model));
            // Select the currently targeted zone
            let target = imp.selected_zone.borrow().clone();
            if let Some(pos) = zones.iter().position(|z| z == &target) {
                dropdown.set_selected(pos as u32);
            }
        }
    }

    /// Provide the per-zone enabled-service lists so the page can show the
    /// correct state for whichever zone is selected.
    pub fn set_zone_services(&self, zone_services: std::collections::HashMap<String, Vec<String>>) {
        self.imp().zone_enabled.replace(zone_services);
    }

    /// Update the page with the full service list, then render.
    pub fn set_services(&self, services: &[Service]) {
        self.imp().services.replace(services.to_vec());
        self.render_services(services);
    }

    /// Render the enabled and all-services groups for the selected zone,
    /// honoring the current search filter.
    fn render_services(&self, services: &[Service]) {
        let imp = self.imp();

        Self::clear_preferences_group(imp.enabled_group.borrow().as_ref());
        Self::clear_preferences_group(imp.all_group.borrow().as_ref());

        let selected_zone = imp.selected_zone.borrow().clone();
        let zone_enabled = imp.zone_enabled.borrow();
        let enabled_in_zone: std::collections::HashSet<&str> = zone_enabled
            .get(&selected_zone)
            .map(|v| v.iter().map(|s| s.as_str()).collect())
            .unwrap_or_default();

        let search = imp.search_text.borrow().clone();
        let matches = |name: &str| search.is_empty() || name.to_lowercase().contains(&search);

        // Enabled services (in the selected zone)
        let mut enabled_services: Vec<&Service> = services
            .iter()
            .filter(|s| enabled_in_zone.contains(s.name.as_str()) && matches(&s.name))
            .collect();
        enabled_services.sort_by(|a, b| a.name.cmp(&b.name));

        // Every other service, filtered by search
        let mut all_services: Vec<&Service> = services
            .iter()
            .filter(|s| !enabled_in_zone.contains(s.name.as_str()) && matches(&s.name))
            .collect();
        all_services.sort_by(|a, b| a.name.cmp(&b.name));

        if enabled_services.is_empty() {
            if let Some(group) = imp.enabled_group.borrow().as_ref() {
                let placeholder = adw::ActionRow::builder()
                    .title(gettext("No services enabled in '%s'").replace("%s", &selected_zone))
                    .subtitle(gettext("Enable services below to allow specific traffic"))
                    .sensitive(false)
                    .build();
                group.add(&placeholder);
            }
        } else {
            for service in enabled_services {
                self.add_service_row(service, true);
            }
        }

        if all_services.is_empty() {
            if let Some(group) = imp.all_group.borrow().as_ref() {
                let placeholder = adw::ActionRow::builder()
                    .title(if search.is_empty() {
                        gettext("No services available")
                    } else {
                        gettext("No matching services")
                    })
                    .sensitive(false)
                    .build();
                group.add(&placeholder);
            }
        } else {
            for service in all_services {
                self.add_service_row(service, false);
            }
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
                    || widget.downcast_ref::<adw::ExpanderRow>().is_some()
                {
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
            imp.all_group.borrow()
        };

        if let Some(group) = group.as_ref() {
            // Escape defensively: AdwActionRow renders title/subtitle as markup
            let row = adw::ActionRow::builder()
                .title(glib::markup_escape_text(&service.name).as_str())
                .subtitle(glib::markup_escape_text(service.human_description()).as_str())
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
                .tooltip_text(if enabled {
                    gettext("Disable service")
                } else {
                    gettext("Enable service")
                })
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
        let zone = imp.selected_zone.borrow().clone();
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
            })
            .await;

            match result {
                Ok(Ok(outcome)) => {
                    if outcome.failed() {
                        page.show_toast(&format!(
                            "Service '{}' enabled for this session only — saving permanently failed",
                            service_name
                        ));
                    } else {
                        page.show_toast(
                            &gettext("Service '%s' enabled").replace("%s", &service_name),
                        );
                    }
                    page.request_refresh();
                }
                Ok(Err(e)) => {
                    switch.set_active(false);
                    page.show_toast(&format!("{}: {}", gettext("Failed to enable service"), e));
                }
                Err(_) => {
                    switch.set_active(false);
                    page.show_toast(&gettext("Failed to enable service"));
                }
            }
            switch.set_sensitive(true);
        });
    }

    /// Disable a service.
    fn disable_service(&self, name: &str, switch: gtk4::Switch) {
        let imp = self.imp();
        let zone = imp.selected_zone.borrow().clone();
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
            })
            .await;

            match result {
                Ok(Ok(outcome)) => {
                    if outcome.failed() {
                        page.show_toast(&format!(
                            "Service '{}' disabled for this session only — saving permanently failed",
                            service_name
                        ));
                    } else {
                        page.show_toast(
                            &gettext("Service '%s' disabled").replace("%s", &service_name),
                        );
                    }
                    page.request_refresh();
                }
                Ok(Err(e)) => {
                    switch.set_active(true);
                    page.show_toast(&format!("{}: {}", gettext("Failed to disable service"), e));
                }
                Err(_) => {
                    switch.set_active(true);
                    page.show_toast(&gettext("Failed to disable service"));
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
        pub all_group: RefCell<Option<adw::PreferencesGroup>>,
        pub default_zone: RefCell<String>,
        pub client: RefCell<Option<Rc<RefCell<FirewallClient>>>>,
        // The zone currently targeted by enable/disable (defaults to the
        // firewalld default zone, overridable via the selector).
        pub selected_zone: RefCell<String>,
        pub available_zones: RefCell<Vec<String>>,
        // Per-zone enabled service names, so state reflects the selected zone.
        pub zone_enabled: RefCell<std::collections::HashMap<String, Vec<String>>>,
        // Cache of the last service list so search re-filters without a D-Bus round-trip.
        pub services: RefCell<Vec<Service>>,
        pub search_text: RefCell<String>,
        pub zone_dropdown: RefCell<Option<adw::ComboRow>>,
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
