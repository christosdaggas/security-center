// Security Center - Quick Actions Page
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: GPL-3.0-or-later

//! Quick Admin Actions page providing one-click administrative operations.
//!
//! # Features
//!
//! - Categorized action buttons for common admin tasks
//! - Firewall management: enable, disable, reload, panic mode
//! - Network management: restart NetworkManager
//! - Service management: restart common services
//!
//! # Architecture
//!
//! Actions are executed via the QuickActionsManager which routes to
//! appropriate D-Bus services (firewalld, systemd).

use std::cell::RefCell;

use gtk4::prelude::*;
use gtk4::subclass::prelude::*;
use gtk4::glib;
use libadwaita as adw;
use libadwaita::prelude::*;
use tracing::{error, info};

use crate::admin::{AdminAction, AdminActionResult, QuickActionsManager, ActionCategory, QUICK_ACTIONS};

glib::wrapper! {
    /// Page with quick one-click admin actions.
    pub struct QuickActionsPage(ObjectSubclass<imp::QuickActionsPage>)
        @extends gtk4::Widget, gtk4::Box,
        @implements gtk4::Accessible, gtk4::Buildable, gtk4::Orientable;
}

impl Default for QuickActionsPage {
    fn default() -> Self {
        Self::new()
    }
}

impl QuickActionsPage {
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
            .label("Quick Actions")
            .css_classes(vec!["title-1".to_string()])
            .halign(gtk4::Align::Start)
            .build();

        let subtitle = gtk4::Label::builder()
            .label("One-click administrative operations")
            .css_classes(vec!["dim-label".to_string()])
            .halign(gtk4::Align::Start)
            .build();

        title_box.append(&title);
        title_box.append(&subtitle);
        header.append(&title_box);
        self.append(&header);

        // Toast overlay for feedback
        let toast_overlay = adw::ToastOverlay::new();
        toast_overlay.set_vexpand(true);
        imp.toast_overlay.replace(Some(toast_overlay.clone()));

        // Scrollable content
        let scrolled = gtk4::ScrolledWindow::builder()
            .vexpand(true)
            .hexpand(true)
            .hscrollbar_policy(gtk4::PolicyType::Never)
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

        // Warning banner (same style as Services page)
        let warning_banner = adw::Banner::builder()
            .title("These actions may affect system security and stability")
            .revealed(true)
            .build();
        content.append(&warning_banner);

        // Build action groups by category
        let firewall_group = adw::PreferencesGroup::builder()
            .description("Manage firewalld service and rules")
            .build();

        let network_group = adw::PreferencesGroup::builder()
            .description("Network service management")
            .build();

        let services_group = adw::PreferencesGroup::builder()
            .description("Manage system services")
            .build();

        for action in QUICK_ACTIONS.iter() {
            let row = self.create_action_row(action);

            match action.category {
                ActionCategory::Firewall => firewall_group.add(&row),
                ActionCategory::Network => network_group.add(&row),
                ActionCategory::Services => services_group.add(&row),
            }
        }

        content.append(&Self::create_section_header("security-high-symbolic", "Firewall"));
        content.append(&firewall_group);
        content.append(&Self::create_section_header("network-wired-symbolic", "Network"));
        content.append(&network_group);
        content.append(&Self::create_section_header("emblem-system-symbolic", "Services"));
        content.append(&services_group);

        scrolled.set_child(Some(&content));
        toast_overlay.set_child(Some(&scrolled));
        self.append(&toast_overlay);

        // Status bar
        // Status bar - centered result display
        let status_bar = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .margin_start(24)
            .margin_end(24)
            .margin_top(12)
            .margin_bottom(12)
            .halign(gtk4::Align::Center)
            .build();

        let status_label = gtk4::Label::builder()
            .label("Ready to execute actions")
            .css_classes(vec!["dim-label".to_string()])
            .halign(gtk4::Align::Center)
            .hexpand(false)
            .build();

        imp.status_label.replace(Some(status_label.clone()));
        status_bar.append(&status_label);
        self.append(&status_bar);
    }

    /// Create an action row for a quick action.
    fn create_action_row(&self, action: &AdminAction) -> adw::ActionRow {
        let row = adw::ActionRow::builder()
            .title(action.title)
            .subtitle(action.description)
            .activatable(true)
            .build();

        // Action icon
        let icon = gtk4::Image::builder()
            .icon_name(action.icon)
            .build();
        row.add_prefix(&icon);

        // Execute button
        let execute_btn = gtk4::Button::builder()
            .label("Execute")
            .valign(gtk4::Align::Center)
            .build();

        if action.destructive {
            execute_btn.add_css_class("destructive-action");
        } else {
            execute_btn.add_css_class("suggested-action");
        }

        // Clone values for the closure
        let action_id = action.id.to_string();
        let action_title = action.title.to_string();
        let is_destructive = action.destructive;
        let page = self.clone();

        execute_btn.connect_clicked(move |button| {
            if is_destructive {
                // Show confirmation dialog for destructive actions
                page.show_confirmation_dialog(&action_id, &action_title, button);
            } else {
                page.execute_action(&action_id, button);
            }
        });

        row.add_suffix(&execute_btn);

        // Make row activatable as well
        let action_id = action.id.to_string();
        let is_destructive = action.destructive;
        let page = self.clone();

        row.connect_activated(move |row| {
            // Find the button in the row suffix
            if let Some(suffix) = row.last_child() {
                if let Ok(btn) = suffix.downcast::<gtk4::Button>() {
                    if is_destructive {
                        page.show_confirmation_dialog(&action_id, row.title().as_str(), &btn);
                    } else {
                        page.execute_action(&action_id, &btn);
                    }
                }
            }
        });

        row
    }

    /// Show confirmation dialog for destructive actions.
    fn show_confirmation_dialog(&self, action_id: &str, action_title: &str, button: &gtk4::Button) {
        let dialog = adw::AlertDialog::builder()
            .heading("Confirm Action")
            .body(&format!(
                "Are you sure you want to execute \"{}\"?\n\nThis action may affect system security or stability.",
                action_title
            ))
            .build();

        dialog.add_responses(&[
            ("cancel", "Cancel"),
            ("confirm", "Execute"),
        ]);
        dialog.set_response_appearance("confirm", adw::ResponseAppearance::Destructive);
        dialog.set_default_response(Some("cancel"));
        dialog.set_close_response("cancel");

        let page = self.clone();
        let action_id = action_id.to_string();
        let button = button.clone();

        dialog.connect_response(None, move |dialog, response| {
            if response == "confirm" {
                page.execute_action(&action_id, &button);
            }
            dialog.close();
        });

        if let Some(root) = self.root() {
            if let Some(window) = root.downcast_ref::<gtk4::Window>() {
                dialog.present(Some(window));
            }
        }
    }

    /// Execute an action by ID.
    fn execute_action(&self, action_id: &str, button: &gtk4::Button) {
        let page = self.clone();
        let action_id_owned = action_id.to_string();
        let button_clone = button.clone();

        // Disable button during execution
        button.set_sensitive(false);
        button.set_label("Running...");

        // Update status
        if let Some(label) = self.imp().status_label.borrow().as_ref() {
            label.set_label("⏳ Executing...");
            label.remove_css_class("success");
            label.remove_css_class("error");
            label.add_css_class("dim-label");
        }

        info!("Executing action: {}", action_id);

        glib::spawn_future_local(async move {
            let result = gtk4::gio::spawn_blocking({
                let action_id = action_id_owned.clone();
                move || {
                    let mut manager = QuickActionsManager::new();
                    manager.execute(&action_id)
                }
            })
            .await;

            match result {
                Ok(action_result) => {
                    page.handle_action_result(&action_id_owned, &action_result);
                }
                Err(e) => {
                    error!("Task execution failed: {:?}", e);
                    page.show_toast("Failed to execute action", true);
                }
            }

            // Re-enable button
            button_clone.set_sensitive(true);
            button_clone.set_label("Execute");
        });
    }

    /// Handle the result of an action execution.
    fn handle_action_result(&self, _action_id: &str, result: &AdminActionResult) {
        // Create a user-friendly message
        let message = if result.success {
            format!("✓ {}", result.message)
        } else {
            format!("✗ {}", result.message)
        };

        // Update status label with appropriate styling
        if let Some(label) = self.imp().status_label.borrow().as_ref() {
            label.set_label(&message);
            // Update styling based on success/failure
            label.remove_css_class("dim-label");
            label.remove_css_class("success");
            label.remove_css_class("error");
            if result.success {
                label.add_css_class("success");
            } else {
                label.add_css_class("error");
            }
        }

        // Trigger a global data refresh so other pages update
        if result.success {
            self.request_refresh();
        }

        // Show toast
        self.show_toast(&result.message, !result.success);
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

    /// Show a toast notification.
    fn show_toast(&self, message: &str, is_error: bool) {
        if let Some(overlay) = self.imp().toast_overlay.borrow().as_ref() {
            let toast = adw::Toast::builder()
                .title(message)
                .timeout(if is_error { 5 } else { 3 })
                .build();

            overlay.add_toast(toast);
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

mod imp {
    use super::*;

    #[derive(Default)]
    pub struct QuickActionsPage {
        pub toast_overlay: RefCell<Option<adw::ToastOverlay>>,
        pub status_label: RefCell<Option<gtk4::Label>>,
    }

    #[glib::object_subclass]
    impl ObjectSubclass for QuickActionsPage {
        const NAME: &'static str = "SecurityCenterQuickActionsPage";
        type Type = super::QuickActionsPage;
        type ParentType = gtk4::Box;
    }

    impl ObjectImpl for QuickActionsPage {}
    impl WidgetImpl for QuickActionsPage {}
    impl BoxImpl for QuickActionsPage {}
}
