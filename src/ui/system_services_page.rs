// Security Center - System Services Page
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: GPL-3.0-or-later

//! System services management page.

use std::cell::RefCell;

use gtk4::prelude::*;
use gtk4::subclass::prelude::*;
use gtk4::glib;
use libadwaita as adw;
use libadwaita::prelude::*;

use crate::systemd::{SystemdClient, ServiceInfo, ServiceState};

glib::wrapper! {
    /// System services management page.
    pub struct SystemServicesPage(ObjectSubclass<imp::SystemServicesPage>)
        @extends gtk4::Box, gtk4::Widget,
        @implements gtk4::Orientable;
}

impl SystemServicesPage {
    /// Create a new system services page.
    pub fn new() -> Self {
        let page: Self = glib::Object::new();
        page.setup_ui();
        page
    }

    /// Setup the UI.
    fn setup_ui(&self) {
        let imp = self.imp();

        self.set_orientation(gtk4::Orientation::Vertical);
        self.set_spacing(0);

        // Header with refresh button
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
            .label("System Services")
            .css_classes(vec!["title-1".to_string()])
            .halign(gtk4::Align::Start)
            .build();

        let subtitle = gtk4::Label::builder()
            .label("Manage system services and daemons")
            .css_classes(vec!["dim-label".to_string()])
            .halign(gtk4::Align::Start)
            .build();

        title_box.append(&title);
        title_box.append(&subtitle);

        let refresh_button = gtk4::Button::builder()
            .icon_name("view-refresh-symbolic")
            .css_classes(vec!["flat".to_string()])
            .tooltip_text("Refresh services list")
            .valign(gtk4::Align::Center)
            .build();

        let page_clone = self.clone();
        refresh_button.connect_clicked(move |_| {
            page_clone.refresh_services();
        });

        header_box.append(&title_box);
        header_box.append(&refresh_button);
        self.append(&header_box);

        // Scrolled container
        let scrolled = gtk4::ScrolledWindow::builder()
            .hscrollbar_policy(gtk4::PolicyType::Never)
            .vscrollbar_policy(gtk4::PolicyType::Automatic)
            .vexpand(true)
            .hexpand(true)
            .build();

        let content = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Vertical)
            .spacing(24)
            .margin_top(24)
            .margin_bottom(24)
            .margin_start(24)
            .margin_end(24)
            .hexpand(true)
            .build();

        // Search entry
        let search_entry = gtk4::SearchEntry::builder()
            .placeholder_text("Search services...")
            .hexpand(true)
            .build();
        imp.search_entry.replace(Some(search_entry.clone()));
        content.append(&search_entry);

        // Connect search changed signal
        let page = self.clone();
        search_entry.connect_search_changed(move |entry| {
            let query = entry.text().to_string().to_lowercase();
            page.filter_services(&query);
        });

        // Running services group
        content.append(&Self::create_section_header("media-playback-start-symbolic", "Running Services"));
        let running_group = adw::PreferencesGroup::builder()
            .description("Services that are currently active")
            .build();
        imp.running_group.replace(Some(running_group.clone()));
        content.append(&running_group);

        // Stopped services group
        content.append(&Self::create_section_header("media-playback-stop-symbolic", "Stopped Services"));
        let stopped_group = adw::PreferencesGroup::builder()
            .description("Services that are not running")
            .build();
        imp.stopped_group.replace(Some(stopped_group.clone()));
        content.append(&stopped_group);

        // Failed services group
        content.append(&Self::create_section_header("dialog-error-symbolic", "Failed Services"));
        let failed_group = adw::PreferencesGroup::builder()
            .description("Services that have failed")
            .build();
        imp.failed_group.replace(Some(failed_group.clone()));
        content.append(&failed_group);

        scrolled.set_child(Some(&content));
        self.append(&scrolled);

        // Toast overlay for notifications
        imp.toast_overlay.replace(None);
    }

    /// Show a toast message.
    fn show_toast(&self, message: &str) {
        // Find the toast overlay by walking up the widget tree
        let mut parent = self.parent();
        while let Some(p) = parent {
            if let Some(overlay) = p.downcast_ref::<adw::ToastOverlay>() {
                overlay.add_toast(adw::Toast::new(message));
                return;
            }
            parent = p.parent();
        }
    }

    /// Refresh the services list.
    pub fn refresh_services(&self) {
        let page = self.clone();

        glib::spawn_future_local(async move {
            let services = gtk4::gio::spawn_blocking(move || {
                let mut client = SystemdClient::new();
                if client.connect().is_err() {
                    return Vec::new();
                }
                client.list_security_services().unwrap_or_default()
            }).await;

            if let Ok(services) = services {
                page.store_and_display_services(&services);
            }
        });
    }

    /// Store services and display them.
    fn store_and_display_services(&self, services: &[ServiceInfo]) {
        let imp = self.imp();
        imp.services.replace(services.to_vec());
        self.display_services(services);
    }

    /// Filter services based on search query.
    fn filter_services(&self, query: &str) {
        let imp = self.imp();
        let services = imp.services.borrow().clone();
        
        if query.is_empty() {
            self.display_services(&services);
        } else {
            let filtered: Vec<ServiceInfo> = services
                .iter()
                .filter(|s| s.name.to_lowercase().contains(query) || 
                           s.description.to_lowercase().contains(query))
                .cloned()
                .collect();
            self.display_services(&filtered);
        }
    }

    /// Display services in groups.
    fn display_services(&self, services: &[ServiceInfo]) {
        let imp = self.imp();

        // Remove all previously tracked rows
        let old_rows = imp.current_rows.take();
        for row in old_rows {
            if let Some(parent) = row.parent() {
                if let Some(group) = parent.downcast_ref::<adw::PreferencesGroup>() {
                    group.remove(&row);
                } else if let Some(listbox) = parent.downcast_ref::<gtk4::ListBox>() {
                    listbox.remove(&row);
                }
            }
        }

        let mut new_rows: Vec<adw::ActionRow> = Vec::new();
        let mut running_count = 0;
        let mut stopped_count = 0;
        let mut failed_count = 0;

        for service in services {
            let row = self.create_service_row(service);
            new_rows.push(row.clone());

            match service.state {
                ServiceState::Running => {
                    if let Some(group) = imp.running_group.borrow().as_ref() {
                        group.add(&row);
                        running_count += 1;
                    }
                }
                ServiceState::Failed => {
                    if let Some(group) = imp.failed_group.borrow().as_ref() {
                        group.add(&row);
                        failed_count += 1;
                    }
                }
                _ => {
                    if let Some(group) = imp.stopped_group.borrow().as_ref() {
                        group.add(&row);
                        stopped_count += 1;
                    }
                }
            }
        }

        // Store the new rows for later removal
        imp.current_rows.replace(new_rows);

        // Update group descriptions with counts
        if let Some(group) = imp.running_group.borrow().as_ref() {
            group.set_description(Some(&format!("{} services currently active", running_count)));
        }
        if let Some(group) = imp.stopped_group.borrow().as_ref() {
            group.set_description(Some(&format!("{} services not running", stopped_count)));
        }
        if let Some(group) = imp.failed_group.borrow().as_ref() {
            group.set_description(Some(&format!("{} services have failed", failed_count)));
            group.set_visible(failed_count > 0);
        }
    }

    /// Create a row for a service.
    fn create_service_row(&self, service: &ServiceInfo) -> adw::ActionRow {
        // Build subtitle with description and PID/Memory info
        let mut subtitle_parts = vec![service.description.clone()];
        
        if service.main_pid > 0 {
            subtitle_parts.push(format!("PID: {}", service.main_pid));
        }
        
        if let Some(mem) = service.memory_display() {
            subtitle_parts.push(format!("Memory: {}", mem));
        }
        
        let subtitle = subtitle_parts.join(" • ");

        let row = adw::ActionRow::builder()
            .title(&service.display_name)
            .subtitle(&subtitle)
            .build();

        // State indicator icon
        let state_icon = gtk4::Image::builder()
            .icon_name(match service.state {
                ServiceState::Running => "media-playback-start-symbolic",
                ServiceState::Stopped => "media-playback-stop-symbolic",
                ServiceState::Failed => "dialog-error-symbolic",
                ServiceState::Unknown => "dialog-question-symbolic",
            })
            .build();
        row.add_prefix(&state_icon);

        // Action buttons box
        let actions_box = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .spacing(4)
            .valign(gtk4::Align::Center)
            .build();

        let service_name = service.name.clone();
        let is_running = service.state == ServiceState::Running;

        // Start/Stop button
        let toggle_button = gtk4::Button::builder()
            .icon_name(if is_running { "media-playback-stop-symbolic" } else { "media-playback-start-symbolic" })
            .css_classes(vec!["flat".to_string()])
            .tooltip_text(if is_running { "Stop service" } else { "Start service" })
            .valign(gtk4::Align::Center)
            .build();

        let page_clone = self.clone();
        let service_name_clone = service_name.clone();
        let is_running_clone = is_running;
        toggle_button.connect_clicked(move |button| {
            button.set_sensitive(false);
            if is_running_clone {
                page_clone.stop_service(&service_name_clone);
            } else {
                page_clone.start_service(&service_name_clone);
            }
        });

        actions_box.append(&toggle_button);

        // Restart button (only for running services)
        if is_running {
            let restart_button = gtk4::Button::builder()
                .icon_name("view-refresh-symbolic")
                .css_classes(vec!["flat".to_string()])
                .tooltip_text("Restart service")
                .valign(gtk4::Align::Center)
                .build();

            let page_clone = self.clone();
            let service_name_clone = service_name.clone();
            restart_button.connect_clicked(move |button| {
                button.set_sensitive(false);
                page_clone.restart_service(&service_name_clone);
            });

            actions_box.append(&restart_button);
        }

        // Enable/Disable toggle
        let enable_switch = gtk4::Switch::builder()
            .active(service.is_enabled)
            .valign(gtk4::Align::Center)
            .tooltip_text(if service.is_enabled { "Disable (won't start on boot)" } else { "Enable (start on boot)" })
            .build();

        let page_clone = self.clone();
        let service_name_clone = service_name.clone();
        enable_switch.connect_state_set(move |switch, state| {
            let page = page_clone.clone();
            let name = service_name_clone.clone();
            let name_for_toast = name.clone();
            glib::spawn_future_local(async move {
                let result = gtk4::gio::spawn_blocking(move || {
                    let mut client = SystemdClient::new();
                    if client.connect().is_err() {
                        return Err("Failed to connect to systemd".to_string());
                    }
                    if state {
                        // Enable and start the service
                        client.enable_service(&name).map_err(|e| e.to_string())?;
                        client.start_service(&name).map_err(|e| e.to_string())
                    } else {
                        // Stop and disable the service
                        client.stop_service(&name).map_err(|e| e.to_string())?;
                        client.disable_service(&name).map_err(|e| e.to_string())
                    }
                }).await;

                match result {
                    Ok(Ok(())) => {
                        page.show_toast(&format!("Service {} {} and {}", 
                            name_for_toast.trim_end_matches(".service"),
                            if state { "started" } else { "stopped" },
                            if state { "enabled" } else { "disabled" }
                        ));
                        // Refresh to move service between groups
                        let page_refresh = page.clone();
                        glib::timeout_add_local_once(std::time::Duration::from_millis(500), move || {
                            page_refresh.refresh_services();
                        });
                    }
                    Ok(Err(e)) => {
                        page.show_toast(&format!("Error: {}", e));
                        page.refresh_services();
                    }
                    Err(e) => {
                        page.show_toast(&format!("Error: {:?}", e));
                        page.refresh_services();
                    }
                }
            });
            switch.set_state(state);
            glib::Propagation::Stop
        });

        actions_box.append(&enable_switch);

        row.add_suffix(&actions_box);

        row
    }

    /// Start a service.
    fn start_service(&self, name: &str) {
        let page = self.clone();
        let service_name = name.to_string();

        glib::spawn_future_local(async move {
            let name_clone = service_name.clone();
            let result = gtk4::gio::spawn_blocking(move || {
                let mut client = SystemdClient::new();
                if client.connect().is_err() {
                    return Err("Failed to connect to systemd".to_string());
                }
                client.start_service(&name_clone).map_err(|e| e.to_string())
            }).await;

            match result {
                Ok(Ok(())) => {
                    page.show_toast(&format!("Started {}", service_name.trim_end_matches(".service")));
                    // Wait a moment then refresh
                    glib::timeout_add_local_once(std::time::Duration::from_millis(500), move || {
                        page.refresh_services();
                    });
                }
                Ok(Err(e)) => {
                    page.show_toast(&format!("Failed to start: {}", e));
                    page.refresh_services();
                }
                Err(e) => {
                    page.show_toast(&format!("Error: {:?}", e));
                    page.refresh_services();
                }
            }
        });
    }

    /// Stop a service.
    fn stop_service(&self, name: &str) {
        let page = self.clone();
        let service_name = name.to_string();

        glib::spawn_future_local(async move {
            let name_clone = service_name.clone();
            let result = gtk4::gio::spawn_blocking(move || {
                let mut client = SystemdClient::new();
                if client.connect().is_err() {
                    return Err("Failed to connect to systemd".to_string());
                }
                client.stop_service(&name_clone).map_err(|e| e.to_string())
            }).await;

            match result {
                Ok(Ok(())) => {
                    page.show_toast(&format!("Stopped {}", service_name.trim_end_matches(".service")));
                    glib::timeout_add_local_once(std::time::Duration::from_millis(500), move || {
                        page.refresh_services();
                    });
                }
                Ok(Err(e)) => {
                    page.show_toast(&format!("Failed to stop: {}", e));
                    page.refresh_services();
                }
                Err(e) => {
                    page.show_toast(&format!("Error: {:?}", e));
                    page.refresh_services();
                }
            }
        });
    }

    /// Restart a service.
    fn restart_service(&self, name: &str) {
        let page = self.clone();
        let service_name = name.to_string();

        glib::spawn_future_local(async move {
            let name_clone = service_name.clone();
            let result = gtk4::gio::spawn_blocking(move || {
                let mut client = SystemdClient::new();
                if client.connect().is_err() {
                    return Err("Failed to connect to systemd".to_string());
                }
                client.restart_service(&name_clone).map_err(|e| e.to_string())
            }).await;

            match result {
                Ok(Ok(())) => {
                    page.show_toast(&format!("Restarted {}", service_name.trim_end_matches(".service")));
                    glib::timeout_add_local_once(std::time::Duration::from_millis(500), move || {
                        page.refresh_services();
                    });
                }
                Ok(Err(e)) => {
                    page.show_toast(&format!("Failed to restart: {}", e));
                    page.refresh_services();
                }
                Err(e) => {
                    page.show_toast(&format!("Error: {:?}", e));
                    page.refresh_services();
                }
            }
        });
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

impl Default for SystemServicesPage {
    fn default() -> Self {
        Self::new()
    }
}

mod imp {
    use super::*;

    #[derive(Default)]
    pub struct SystemServicesPage {
        pub running_group: RefCell<Option<adw::PreferencesGroup>>,
        pub stopped_group: RefCell<Option<adw::PreferencesGroup>>,
        pub failed_group: RefCell<Option<adw::PreferencesGroup>>,
        pub toast_overlay: RefCell<Option<adw::ToastOverlay>>,
        pub search_entry: RefCell<Option<gtk4::SearchEntry>>,
        pub services: RefCell<Vec<ServiceInfo>>,
        pub current_rows: RefCell<Vec<adw::ActionRow>>,
    }

    #[glib::object_subclass]
    impl ObjectSubclass for SystemServicesPage {
        const NAME: &'static str = "SecurityCenterSystemServicesPage";
        type Type = super::SystemServicesPage;
        type ParentType = gtk4::Box;
    }

    impl ObjectImpl for SystemServicesPage {}
    impl WidgetImpl for SystemServicesPage {}
    impl BoxImpl for SystemServicesPage {}
}
