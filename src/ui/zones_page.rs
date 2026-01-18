// Security Center - Zones Page
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: MIT

//! Zones management page.

use std::cell::RefCell;
use std::rc::Rc;

use gtk4::prelude::*;
use gtk4::subclass::prelude::*;
use gtk4::glib;
use libadwaita as adw;
use libadwaita::prelude::*;

use crate::firewall::FirewallClient;
use crate::models::Zone;

glib::wrapper! {
    /// Zones page showing firewall zones.
    pub struct ZonesPage(ObjectSubclass<imp::ZonesPage>)
        @extends gtk4::Box, gtk4::Widget,
        @implements gtk4::Orientable;
}

impl ZonesPage {
    /// Create a new zones page.
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
            .label("Zones")
            .css_classes(vec!["title-1".to_string()])
            .halign(gtk4::Align::Start)
            .build();

        let subtitle = gtk4::Label::builder()
            .label("Manage firewall zones and their settings")
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

        // Active zones group
        content.append(&Self::create_section_header("network-workgroup-symbolic", "Active Zones"));
        let active_group = adw::PreferencesGroup::builder()
            .description("Zones with assigned interfaces or sources")
            .build();
        content.append(&active_group);
        imp.active_group.replace(Some(active_group));

        // Available zones group
        content.append(&Self::create_section_header("view-list-symbolic", "Available Zones"));
        let available_group = adw::PreferencesGroup::builder()
            .description("Click 'Set Default' to change the default zone")
            .build();
        content.append(&available_group);
        imp.available_group.replace(Some(available_group));
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

    /// Set a zone as the default zone.
    fn set_default_zone(&self, zone_name: &str) {
        let zone = zone_name.to_string();
        let page = self.clone();
        
        glib::spawn_future_local(async move {
            let zone_clone = zone.clone();
            let result = gtk4::gio::spawn_blocking(move || {
                // Create a new client for this operation
                let mut client = crate::firewall::FirewallClient::new();
                if client.connect().is_err() {
                    return Err(anyhow::anyhow!("Failed to connect"));
                }
                client.set_default_zone(&zone_clone)
            }).await;

            match result {
                Ok(Ok(())) => {
                    page.show_toast(&format!("Default zone set to '{}'", zone));
                    page.request_refresh();
                }
                Ok(Err(e)) => {
                    page.show_toast(&format!("Failed to set default zone: {}", e));
                }
                Err(_) => {
                    page.show_toast("Failed to set default zone");
                }
            }
        });
    }

    /// Update the page with zone data.
    pub fn set_zones(&self, zones: &[Zone]) {
        let imp = self.imp();

        // Clear ALL existing rows from both groups using helper
        Self::clear_preferences_group(imp.active_group.borrow().as_ref());
        Self::clear_preferences_group(imp.available_group.borrow().as_ref());

        // Separate active (with interfaces/sources) vs available zones
        let (active, available): (Vec<_>, Vec<_>) = zones.iter()
            .partition(|z| !z.interfaces.is_empty() || !z.sources.is_empty());

        // Add active zones
        if let Some(group) = imp.active_group.borrow().as_ref() {
            for zone in &active {
                let row = self.create_zone_row_new(zone);
                group.add(&row);
            }
        }

        // Add available zones  
        if let Some(group) = imp.available_group.borrow().as_ref() {
            for zone in &available {
                let row = self.create_zone_row_new(zone);
                group.add(&row);
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

    /// Create a row for a zone (new working version).
    fn create_zone_row_new(&self, zone: &Zone) -> adw::ExpanderRow {
        let row = adw::ExpanderRow::builder()
            .title(&zone.name)
            .subtitle(&zone.description)
            .build();
        
        // Icon based on zone type
        let icon = match zone.name.as_str() {
            "trusted" => "security-high-symbolic",
            "home" | "internal" | "work" => "security-medium-symbolic",
            "public" | "external" | "dmz" => "security-low-symbolic",
            "drop" | "block" => "action-unavailable-symbolic",
            _ => "network-server-symbolic",
        };
        row.add_prefix(&gtk4::Image::from_icon_name(icon));
        
        // Default badge if this is the default zone
        if zone.is_default {
            let badge = gtk4::Label::builder()
                .label("Default")
                .css_classes(["success", "caption"])
                .valign(gtk4::Align::Center)
                .build();
            row.add_suffix(&badge);
        } else {
            // "Set Default" button
            let zone_name = zone.name.clone();
            let page = self.clone();
            let button = gtk4::Button::builder()
                .label("Set Default")
                .valign(gtk4::Align::Center)
                .css_classes(["flat"])
                .build();
            button.connect_clicked(move |_| {
                page.set_default_zone(&zone_name);
            });
            row.add_suffix(&button);
        }
        
        // Sub-rows for zone details
        if !zone.services.is_empty() {
            let services_row = adw::ActionRow::builder()
                .title("Services")
                .subtitle(&zone.services.join(", "))
                .build();
            row.add_row(&services_row);
        }
        
        if !zone.ports.is_empty() {
            let ports_row = adw::ActionRow::builder()
                .title("Ports")
                .subtitle(&zone.ports.join(", "))
                .build();
            row.add_row(&ports_row);
        }
        
        if !zone.interfaces.is_empty() {
            let ifaces_row = adw::ActionRow::builder()
                .title("Interfaces")
                .subtitle(&zone.interfaces.join(", "))
                .build();
            row.add_row(&ifaces_row);
        }
        
        if !zone.sources.is_empty() {
            let sources_row = adw::ActionRow::builder()
                .title("Sources")
                .subtitle(&zone.sources.join(", "))
                .build();
            row.add_row(&sources_row);
        }
        
        row
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

impl Default for ZonesPage {
    fn default() -> Self {
        Self::new()
    }
}

mod imp {
    use super::*;

    #[derive(Default)]
    pub struct ZonesPage {
        pub active_group: RefCell<Option<adw::PreferencesGroup>>,
        pub available_group: RefCell<Option<adw::PreferencesGroup>>,
        pub client: RefCell<Option<Rc<RefCell<FirewallClient>>>>,
    }

    #[glib::object_subclass]
    impl ObjectSubclass for ZonesPage {
        const NAME: &'static str = "SecurityCenterZonesPage";
        type Type = super::ZonesPage;
        type ParentType = gtk4::Box;
    }

    impl ObjectImpl for ZonesPage {}
    impl WidgetImpl for ZonesPage {}
    impl BoxImpl for ZonesPage {}
}
