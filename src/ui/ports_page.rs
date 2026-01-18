// GNOME Firewall - Ports Page
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: GPL-3.0-or-later

//! Ports management page.

use std::cell::RefCell;
use std::rc::Rc;

use gtk4::prelude::*;
use gtk4::subclass::prelude::*;
use gtk4::glib;
use libadwaita as adw;
use libadwaita::prelude::*;

use crate::firewall::FirewallClient;
use crate::models::Port;
use crate::storage::{PortMetadata, PortStorage};

glib::wrapper! {
    /// Ports page for managing open ports.
    pub struct PortsPage(ObjectSubclass<imp::PortsPage>)
        @extends gtk4::Box, gtk4::Widget,
        @implements gtk4::Orientable;
}

impl PortsPage {
    /// Create a new ports page.
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

        // Header with Add button
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
            .label("Ports")
            .css_classes(vec!["title-1".to_string()])
            .halign(gtk4::Align::Start)
            .build();

        let subtitle = gtk4::Label::builder()
            .label("Manage open and blocked ports in the firewall")
            .css_classes(vec!["dim-label".to_string()])
            .halign(gtk4::Align::Start)
            .build();

        title_box.append(&title);
        title_box.append(&subtitle);
        header_box.append(&title_box);

        let add_button = gtk4::Button::builder()
            .label("Add Port")
            .css_classes(vec!["suggested-action".to_string()])
            .valign(gtk4::Align::Center)
            .build();

        let page_clone = self.clone();
        add_button.connect_clicked(move |_| {
            page_clone.show_add_dialog();
        });
        header_box.append(&add_button);
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

        // Ports group
        content.append(&Self::create_section_header("network-transmit-symbolic", "Open Ports"));
        let ports_group = adw::PreferencesGroup::builder()
            .description("Custom ports opened in the firewall")
            .build();
        content.append(&ports_group);
        imp.ports_group.replace(Some(ports_group));

        // Blocked ports group
        content.append(&Self::create_section_header("action-unavailable-symbolic", "Blocked Ports"));
        let blocked_ports_group = adw::PreferencesGroup::builder()
            .description("Ports explicitly blocked via rich rules")
            .build();
        content.append(&blocked_ports_group);
        imp.blocked_ports_group.replace(Some(blocked_ports_group));

        // Summary group
        content.append(&Self::create_section_header("view-list-symbolic", "Summary"));
        let summary_group = adw::PreferencesGroup::builder()
            .build();
        content.append(&summary_group);
        imp.summary_group.replace(Some(summary_group));
    }

    /// Set the current zone and load ports.
    pub fn set_zone(&self, zone: &str) {
        self.imp().current_zone.replace(zone.to_string());
    }

    /// Set available zones for the dropdown.
    pub fn set_available_zones(&self, zones: &[String]) {
        self.imp().cached_zones.replace(zones.to_vec());
    }

    /// Populate with ports data.
    pub fn set_ports(&self, ports: &[Port]) {
        let imp = self.imp();

        // Clear existing rows from ports group using tracked rows
        Self::clear_preferences_group_rows(imp.ports_group.borrow().as_ref(), &imp.ports_rows);

        // Clear existing rows from summary group using tracked rows
        Self::clear_preferences_group_rows(imp.summary_group.borrow().as_ref(), &imp.summary_rows);

        let mut tcp_count = 0;
        let mut udp_count = 0;
        let mut tcp_deny_count = 0;
        let mut udp_deny_count = 0;

        // Collect ports from firewalld (allowed ports)
        let mut all_ports: Vec<Port> = ports.to_vec();
        
        // Add deny rules from our storage (these aren't in firewalld's port list)
        let deny_rules = imp.storage.borrow_mut().get_deny_rules();
        for rule in deny_rules {
            if rule.port > 0 {
                let mut port = Port::new(rule.port, &rule.protocol);
                port.zone = if rule.zone.is_empty() { None } else { Some(rule.zone.clone()) };
                port.name = if rule.name.is_empty() { None } else { Some(rule.name.clone()) };
                port.action = if rule.incoming_action == "deny" { "deny".to_string() } else { "accept".to_string() };
                port.description = Some(rule.description.clone());
                
                // Don't add if already in the list (from firewalld)
                if !all_ports.iter().any(|p| p.number == port.number && p.protocol == port.protocol) {
                    all_ports.push(port);
                }
            }
        }

        if all_ports.is_empty() {
            if let Some(group) = imp.ports_group.borrow().as_ref() {
                let placeholder = adw::ActionRow::builder()
                    .title("No port rules configured")
                    .subtitle("Click 'Add Port' to create a rule")
                    .sensitive(false)
                    .build();
                group.add(&placeholder);
                imp.ports_rows.borrow_mut().push(placeholder);
            }
        } else {
            // Sort by port number
            all_ports.sort_by_key(|p| p.number);

            for port in &all_ports {
                if port.protocol == "tcp" {
                    if port.action == "deny" {
                        tcp_deny_count += 1;
                    } else {
                        tcp_count += 1;
                    }
                } else {
                    if port.action == "deny" {
                        udp_deny_count += 1;
                    } else {
                        udp_count += 1;
                    }
                }

                self.add_port_row(port);
            }
        }

        // Update summary
        if let Some(group) = imp.summary_group.borrow().as_ref() {
            let tcp_row = adw::ActionRow::builder()
                .title("TCP Ports")
                .subtitle(&format!("{} allowed, {} blocked", tcp_count, tcp_deny_count))
                .build();
            tcp_row.add_prefix(&gtk4::Image::from_icon_name("network-transmit-symbolic"));
            group.add(&tcp_row);
            imp.summary_rows.borrow_mut().push(tcp_row);

            let udp_row = adw::ActionRow::builder()
                .title("UDP Ports")
                .subtitle(&format!("{} allowed, {} blocked", udp_count, udp_deny_count))
                .build();
            udp_row.add_prefix(&gtk4::Image::from_icon_name("network-receive-symbolic"));
            group.add(&udp_row);
            imp.summary_rows.borrow_mut().push(udp_row);
        }
    }

    /// Populate with blocked ports data (from rich rules).
    pub fn set_blocked_ports(&self, blocked_ports: &[Port]) {
        let imp = self.imp();

        // Clear existing blocked ports rows using tracked rows
        Self::clear_preferences_group_rows(imp.blocked_ports_group.borrow().as_ref(), &imp.blocked_rows);

        if blocked_ports.is_empty() {
            if let Some(group) = imp.blocked_ports_group.borrow().as_ref() {
                let placeholder = adw::ActionRow::builder()
                    .title("No blocked ports")
                    .subtitle("Ports blocked via rich rules will appear here")
                    .sensitive(false)
                    .build();
                group.add(&placeholder);
                imp.blocked_rows.borrow_mut().push(placeholder);
            }
        } else {
            for port in blocked_ports {
                self.add_blocked_port_row(port);
            }
        }
    }

    /// Add a blocked port row to the blocked ports list.
    fn add_blocked_port_row(&self, port: &Port) {
        let imp = self.imp();

        if let Some(group) = imp.blocked_ports_group.borrow().as_ref() {
            let title = format!("{}/{}", port.number, port.protocol.to_uppercase());
            let zone = port.zone.as_deref().unwrap_or("unknown");
            let action_label = if port.action == "reject" { "Rejected" } else { "Dropped" };

            let row = adw::ActionRow::builder()
                .title(&title)
                .subtitle(&format!("Zone: {} • {}", zone, action_label))
                .build();

            // Blocked icon
            let icon = gtk4::Image::from_icon_name("dialog-error-symbolic");
            icon.add_css_class("error");
            row.add_prefix(&icon);

            // Protocol badge
            let proto_label = gtk4::Label::builder()
                .label(&port.protocol.to_uppercase())
                .css_classes(vec!["caption".to_string()])
                .valign(gtk4::Align::Center)
                .build();
            row.add_suffix(&proto_label);

            // Unblock button
            let unblock_button = gtk4::Button::builder()
                .icon_name("edit-undo-symbolic")
                .css_classes(vec!["flat".to_string(), "success".to_string()])
                .valign(gtk4::Align::Center)
                .tooltip_text("Remove block rule")
                .build();

            let port_number = port.number;
            let port_protocol = port.protocol.clone();
            let port_zone = port.zone.clone().unwrap_or_else(|| "public".to_string());
            let page_clone = self.clone();
            let row_clone = row.clone();

            unblock_button.connect_clicked(move |button| {
                button.set_sensitive(false);
                row_clone.set_sensitive(false);
                row_clone.add_css_class("dim-label");
                page_clone.unblock_port(&port_zone, port_number, &port_protocol);
            });

            row.add_suffix(&unblock_button);
            group.add(&row);
            imp.blocked_rows.borrow_mut().push(row);
        }
    }

    /// Unblock a port by removing the rich rule.
    fn unblock_port(&self, zone: &str, port: u16, protocol: &str) {
        let zone = zone.to_string();
        let port_num = port;
        let protocol = protocol.to_string();
        let page = self.clone();

        glib::spawn_future_local(async move {
            let zone_clone = zone.clone();
            let protocol_clone = protocol.clone();

            let result = gtk4::gio::spawn_blocking(move || {
                let mut client = crate::firewall::FirewallClient::new();
                if let Err(e) = client.connect() {
                    return Err(anyhow::anyhow!("Not connected to firewalld: {}", e));
                }

                let port_str = port_num.to_string();

                // Remove the reject rich rule (both runtime and permanent)
                let reject_rule = format!(
                    "rule family=\"ipv4\" port port=\"{}\" protocol=\"{}\" reject",
                    port_str, protocol_clone
                );
                let _ = client.remove_rich_rule(&zone_clone, &reject_rule, false);
                let _ = client.remove_rich_rule(&zone_clone, &reject_rule, true);

                // Also try drop rule
                let drop_rule = format!(
                    "rule family=\"ipv4\" port port=\"{}\" protocol=\"{}\" drop",
                    port_str, protocol_clone
                );
                let _ = client.remove_rich_rule(&zone_clone, &drop_rule, false);
                let _ = client.remove_rich_rule(&zone_clone, &drop_rule, true);

                Ok(())
            }).await;

            match result {
                Ok(Ok(())) => {
                    page.show_toast(&format!("Port {}/{} unblocked", port_num, protocol));
                    page.request_refresh();
                }
                Ok(Err(e)) => {
                    page.show_toast(&format!("Failed to unblock port: {}", e));
                }
                Err(_) => {
                    page.show_toast("Failed to unblock port: task error");
                }
            }
        });
    }

    /// Add a port row to the list.
    fn add_port_row(&self, port: &Port) {
        let imp = self.imp();

        if let Some(group) = imp.ports_group.borrow().as_ref() {
            // Try to get saved name from storage
            let mut storage = imp.storage.borrow_mut();
            let zone = port.zone.as_deref().unwrap_or("public");
            let key = PortStorage::make_key(port.number, &port.protocol, zone);
            
            let display_name = storage.get(&key)
                .map(|m| m.name)
                .filter(|n| !n.is_empty())
                .or_else(|| port.well_known_service().map(|s| s.to_string()))
                .or_else(|| port.name.clone());
            
            let title = if let Some(name) = &display_name {
                format!("{} ({}/{})", name, port.number, port.protocol)
            } else {
                port.display_string()
            };
            
            drop(storage); // Release borrow before creating UI

            // Determine if this is a deny rule
            let is_blocked = port.action == "reject" || port.action == "drop" || port.action == "deny";
            
            let row = adw::ActionRow::builder()
                .title(&title)
                .subtitle(&format!("Zone: {} • {}", 
                    port.zone.as_deref().unwrap_or("unknown"),
                    if is_blocked { "Blocked" } else { "Allowed" }
                ))
                .build();

            // Action icon (block or allow)
            let action_icon = if is_blocked {
                let icon = gtk4::Image::from_icon_name("dialog-error-symbolic");
                icon.add_css_class("error");
                icon
            } else {
                let icon = gtk4::Image::from_icon_name("object-select-symbolic");
                icon.add_css_class("success");
                icon
            };
            row.add_prefix(&action_icon);

            // Protocol badge
            let proto_label = gtk4::Label::builder()
                .label(&port.protocol.to_uppercase())
                .css_classes(vec!["caption".to_string()])
                .valign(gtk4::Align::Center)
                .build();
            if port.protocol == "tcp" {
                proto_label.add_css_class("accent");
            }
            row.add_suffix(&proto_label);

            // Delete button
            let delete_button = gtk4::Button::builder()
                .icon_name("user-trash-symbolic")
                .css_classes(vec!["flat".to_string(), "error".to_string()])
                .valign(gtk4::Align::Center)
                .tooltip_text("Delete this port rule")
                .build();

            let port_number = port.number;
            let port_protocol = port.protocol.clone();
            let port_zone = port.zone.clone().unwrap_or_default();
            let page_clone = self.clone();
            let row_clone = row.clone();

            delete_button.connect_clicked(move |button| {
                button.set_sensitive(false);
                row_clone.set_sensitive(false);
                row_clone.add_css_class("dim-label");
                page_clone.delete_port(&port_zone, port_number, &port_protocol);
            });

            row.add_suffix(&delete_button);

            group.add(&row);
            imp.ports_rows.borrow_mut().push(row);
        }
    }

    /// Delete a port permanently.
    fn delete_port(&self, zone: &str, port: u16, protocol: &str) {
        let zone = zone.to_string();
        let port_num = port;
        let protocol = protocol.to_string();
        let page = self.clone();
        
        glib::spawn_future_local(async move {
            let zone_clone = zone.clone();
            let protocol_clone = protocol.clone();
            
            let result = gtk4::gio::spawn_blocking(move || {
                let mut client = crate::firewall::FirewallClient::new();
                if let Err(e) = client.connect() {
                    return Err(anyhow::anyhow!("Not connected to firewalld: {}", e));
                }
                
                let port_str = port_num.to_string();
                
                // Remove from both runtime and permanent
                let _ = client.remove_port(&zone_clone, &port_str, &protocol_clone, false);
                client.remove_port(&zone_clone, &port_str, &protocol_clone, true)?;
                
                // Also try to remove any rich rule that might be blocking this port
                let reject_rule = format!(
                    "rule family=\"ipv4\" port port=\"{}\" protocol=\"{}\" reject",
                    port_str, protocol_clone
                );
                let _ = client.remove_rich_rule(&zone_clone, &reject_rule, false);
                let _ = client.remove_rich_rule(&zone_clone, &reject_rule, true);
                
                Ok(())
            }).await;

            match result {
                Ok(Ok(())) => {
                    page.show_toast(&format!("Port {}/{} deleted", port_num, protocol));
                    
                    // Remove metadata from storage
                    let key = PortStorage::make_key(port_num, &protocol, &zone);
                    page.imp().storage.borrow_mut().remove(&key);
                    
                    page.request_refresh();
                }
                Ok(Err(e)) => {
                    page.show_toast(&format!("Failed to delete port: {}", e));
                }
                Err(_) => {
                    page.show_toast("Failed to delete port: task error");
                }
            }
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

    /// Helper to clear all rows from a PreferencesGroup.
    /// Stores row references in the imp module for safe removal.
    fn clear_preferences_group_rows(group: Option<&adw::PreferencesGroup>, stored_rows: &RefCell<Vec<adw::ActionRow>>) {
        if let Some(group) = group {
            // Remove only the rows we previously added and tracked
            let rows = stored_rows.borrow();
            for row in rows.iter() {
                // Check if row is still a child before removing
                if row.parent().is_some() {
                    group.remove(row);
                }
            }
            drop(rows);
            stored_rows.borrow_mut().clear();
        }
    }

    /// Show the add port dialog.
    fn show_add_dialog(&self) {
        let imp = self.imp();

        let current_zone = imp.current_zone.borrow().clone();
        let default_zone = if current_zone.is_empty() { "public".to_string() } else { current_zone };

        let dialog = adw::AlertDialog::builder()
            .heading("Add Port Rule")
            .build();

        // Create form content
        let content = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Vertical)
            .spacing(16)
            .margin_top(12)
            .margin_bottom(12)
            .margin_start(12)
            .margin_end(12)
            .build();

        // === Port Details Section ===
        let details_group = adw::PreferencesGroup::builder()
            .title("Port Details")
            .build();
        
        // Name entry (optional, for user reference)
        let name_entry = adw::EntryRow::builder()
            .title("Name (optional)")
            .build();
        details_group.add(&name_entry);

        // Port number entry
        let port_entry = adw::EntryRow::builder()
            .title("Port Number")
            .build();
        port_entry.set_input_purpose(gtk4::InputPurpose::Digits);
        details_group.add(&port_entry);

        // Protocol selection
        let protocol_row = adw::ComboRow::builder()
            .title("Protocol")
            .model(&gtk4::StringList::new(&["TCP", "UDP", "Both"]))
            .selected(0)
            .build();
        details_group.add(&protocol_row);

        content.append(&details_group);

        // === Rule Action Section ===
        let action_group = adw::PreferencesGroup::builder()
            .title("Firewall Action")
            .description("How the firewall should handle incoming traffic on this port")
            .build();

        // Action selection (Allow or Block)
        let action_row = adw::ComboRow::builder()
            .title("Action")
            .subtitle("Allow opens the port, Block rejects connections")
            .model(&gtk4::StringList::new(&["Allow (Open Port)", "Block (Reject Connections)"]))
            .selected(0)
            .build();
        action_row.add_prefix(&gtk4::Image::from_icon_name("security-medium-symbolic"));
        action_group.add(&action_row);

        content.append(&action_group);

        // === Zone & Options Section ===
        let options_group = adw::PreferencesGroup::builder()
            .title("Options")
            .build();

        // Zone dropdown - fetch available zones
        let cached_zones = imp.cached_zones.borrow().clone();
        let default_zone_list = vec![
            "public".to_string(), 
            "home".to_string(), 
            "work".to_string(), 
            "internal".to_string(), 
            "external".to_string(), 
            "dmz".to_string(), 
            "block".to_string(), 
            "drop".to_string(), 
            "trusted".to_string()
        ];
        
        // Use cached zones if available, otherwise use defaults
        let zone_names: Vec<String> = if cached_zones.is_empty() {
            default_zone_list
        } else {
            cached_zones
        };
        
        let zone_list: Vec<&str> = zone_names.iter().map(|s| s.as_str()).collect();
        let zone_string_list = gtk4::StringList::new(&zone_list);
        
        let zone_row = adw::ComboRow::builder()
            .title("Zone")
            .subtitle("Select the firewall zone to apply this rule")
            .model(&zone_string_list)
            .build();
        
        // Set default selection to match current zone or "public"
        let default_idx = zone_names.iter().position(|z| z == &default_zone).unwrap_or(0) as u32;
        zone_row.set_selected(default_idx);
        options_group.add(&zone_row);

        // Permanent switch
        let permanent_row = adw::SwitchRow::builder()
            .title("Make Permanent")
            .subtitle("Rule persists after reboot")
            .active(true)
            .build();
        options_group.add(&permanent_row);

        content.append(&options_group);

        dialog.set_extra_child(Some(&content));
        dialog.add_response("cancel", "_Cancel");
        dialog.add_response("add", "_Add");
        dialog.set_response_appearance("add", adw::ResponseAppearance::Suggested);

        let zone_names_clone = zone_names.clone();
        let page = self.clone();
        dialog.connect_response(None, move |_dialog, response| {
            if response == "add" {
                let name_text = name_entry.text().to_string();
                let port_text = port_entry.text().to_string();
                let protocol_idx = protocol_row.selected();
                let action = action_row.selected(); // 0=Allow, 1=Block
                // Get zone from dropdown selection
                let zone_idx = zone_row.selected() as usize;
                let zone = zone_names_clone.get(zone_idx)
                    .cloned()
                    .unwrap_or_else(|| "public".to_string());
                let permanent = permanent_row.is_active();

                // Validate port number (u16 range is 0-65535, we only accept 1-65535)
                match port_text.parse::<u16>() {
                    Ok(port_num) if port_num >= 1 => {
                        let name = if name_text.is_empty() { None } else { Some(name_text) };
                        
                        // Determine protocols to add
                        let protocols: Vec<&str> = match protocol_idx {
                            0 => vec!["tcp"],
                            1 => vec!["udp"],
                            _ => vec!["tcp", "udp"],
                        };
                        
                        // Add rules based on selections
                        for protocol in protocols {
                            page.add_port_rule(
                                &zone, 
                                &port_text, 
                                protocol, 
                                action,
                                permanent, 
                                name.clone()
                            );
                        }
                    }
                    Ok(_) => {
                        page.show_toast("Port must be between 1 and 65535");
                    }
                    Err(_) => {
                        page.show_toast("Invalid port number");
                    }
                }
            }
            // Note: AdwAlertDialog closes itself after response, don't call dialog.close()
        });

        // Present dialog
        if let Some(root) = self.root() {
            if let Some(window) = root.downcast_ref::<gtk4::Window>() {
                dialog.present(Some(window));
            }
        }
    }

    /// Add a port rule (Allow or Block incoming traffic).
    fn add_port_rule(&self, zone: &str, port: &str, protocol: &str, action: u32, permanent: bool, name: Option<String>) {
        let zone = zone.to_string();
        let port = port.to_string();
        let protocol = protocol.to_string();
        let page = self.clone();
        
        glib::spawn_future_local(async move {
            let zone_clone = zone.clone();
            let port_clone = port.clone();
            let protocol_clone = protocol.clone();
            
            let result = gtk4::gio::spawn_blocking(move || {
                let mut client = crate::firewall::FirewallClient::new();
                if let Err(e) = client.connect() {
                    return Err(anyhow::anyhow!("Not connected to firewalld: {}", e));
                }
                
                // action: 0=Allow (open port), 1=Block (reject connections)
                if action == 0 {
                    // Allow = add port to zone (opens the port)
                    client.add_port(&zone_clone, &port_clone, &protocol_clone, permanent)?;
                } else {
                    // Block = add rich rule to reject connections
                    let rule = format!(
                        "rule family=\"ipv4\" port port=\"{}\" protocol=\"{}\" reject",
                        port_clone, protocol_clone
                    );
                    client.add_rich_rule(&zone_clone, &rule, permanent)?;
                }
                
                // Don't reload - the port is already added to runtime config
                // Reloading would wipe runtime if permanent save failed
                
                if action == 0 {
                    Ok("Port opened (allowed)")
                } else {
                    Ok("Port blocked (rejected)")
                }
            }).await;

            match result {
                Ok(Ok(msg)) => {
                    page.show_toast(&format!("Port {}/{}: {}", port, protocol, msg));
                    
                    // Save rule metadata
                    if let Ok(port_num) = port.parse::<u16>() {
                        let key = PortStorage::make_key(port_num, &protocol, &zone);
                        let mut metadata = PortMetadata::new(name.as_deref().unwrap_or(""));
                        metadata.port = port_num;
                        metadata.protocol = protocol.clone();
                        metadata.zone = zone.clone();
                        metadata.incoming_action = if action == 0 { "allow".to_string() } else { "block".to_string() };
                        metadata.description = if action == 0 { 
                            "Incoming: Allowed".to_string() 
                        } else { 
                            "Incoming: Blocked".to_string() 
                        };
                        page.imp().storage.borrow_mut().set(key, metadata);
                    }
                    
                    page.request_refresh();
                }
                Ok(Err(e)) => {
                    page.show_toast(&format!("Failed to add port: {}", e));
                }
                Err(_) => {
                    page.show_toast("Failed to add port");
                }
            }
        });
    }

    /// Add a port to the firewall (legacy method).
    #[allow(dead_code)]
    fn add_port(&self, zone: &str, port: &str, protocol: &str, _direction: &str, permanent: bool, name: Option<String>) {
        // Convert to new method - only supports incoming now
        let action = 0; // Allow
        self.add_port_rule(zone, port, protocol, action, permanent, name);
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

impl Default for PortsPage {
    fn default() -> Self {
        Self::new()
    }
}

mod imp {
    use super::*;

    #[derive(Default)]
    pub struct PortsPage {
        pub ports_group: RefCell<Option<adw::PreferencesGroup>>,
        pub blocked_ports_group: RefCell<Option<adw::PreferencesGroup>>,
        pub summary_group: RefCell<Option<adw::PreferencesGroup>>,
        pub current_zone: RefCell<String>,
        pub client: RefCell<Option<Rc<RefCell<FirewallClient>>>>,
        pub storage: RefCell<PortStorage>,
        // Track rows we've added for safe removal
        pub ports_rows: RefCell<Vec<adw::ActionRow>>,
        pub summary_rows: RefCell<Vec<adw::ActionRow>>,
        pub blocked_rows: RefCell<Vec<adw::ActionRow>>,
        // Cached zone names for the dropdown
        pub cached_zones: RefCell<Vec<String>>,
    }

    #[glib::object_subclass]
    impl ObjectSubclass for PortsPage {
        const NAME: &'static str = "SecurityCenterPortsPage";
        type Type = super::PortsPage;
        type ParentType = gtk4::Box;
    }

    impl ObjectImpl for PortsPage {
        fn constructed(&self) {
            self.parent_constructed();
            // Storage will be initialized lazily when needed
        }
    }
    impl WidgetImpl for PortsPage {}
    impl BoxImpl for PortsPage {}
}
