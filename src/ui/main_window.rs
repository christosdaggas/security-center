// Security Center - Main Window
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: GPL-3.0-or-later

//! Main application window with navigation.

use std::cell::RefCell;
use std::rc::Rc;

use gtk4::prelude::*;
use gtk4::subclass::prelude::*;
use gtk4::{gio, glib};
use libadwaita as adw;
use libadwaita::prelude::*;
use crate::firewall::FirewallClient;
use super::{OverviewPage, ZonesPage, ServicesPage, PortsPage, SystemServicesPage,
            NetworkExposurePage, QuickActionsPage, HelpPage};

glib::wrapper! {
    /// The main application window.
    pub struct MainWindow(ObjectSubclass<imp::MainWindow>)
        @extends adw::ApplicationWindow, gtk4::ApplicationWindow, gtk4::Window, gtk4::Widget,
        @implements gio::ActionGroup, gio::ActionMap;
}

impl MainWindow {
    /// Create a new main window.
    pub fn new(app: &impl IsA<gtk4::Application>) -> Self {
        let window: Self = glib::Object::builder()
            .property("application", app)
            .property("title", "Security Center")
            .property("default-width", 1200)
            .property("default-height", 720)
            .property("icon-name", "com.chrisdaggas.security-center")
            .build();

        window.setup_ui();
        window.setup_actions();
        
        // Show window immediately, connect to firewalld after main loop starts
        window.set_visible(true);
        
        // Connect to firewalld after a short delay
        let win = window.clone();
        glib::timeout_add_seconds_local_once(2, move || {
            win.connect_to_firewalld();
        });
        
        window
    }

    /// Show a toast notification.
    pub fn show_toast(&self, message: &str) {
        let imp = self.imp();
        if let Some(toast_overlay) = imp.toast_overlay.borrow().as_ref() {
            let toast = adw::Toast::new(message);
            toast_overlay.add_toast(toast);
        }
    }

    /// Setup the main UI.
    fn setup_ui(&self) {
        let imp = self.imp();

        // Create toast overlay for notifications
        let toast_overlay = adw::ToastOverlay::new();
        imp.toast_overlay.replace(Some(toast_overlay.clone()));

        // Create content pages stack
        let stack = gtk4::Stack::builder()
            .transition_type(gtk4::StackTransitionType::Crossfade)
            .hexpand(true)
            .vexpand(true)
            .build();

        // Create pages
        let overview_page = OverviewPage::new();
        let zones_page = ZonesPage::new();
        let services_page = ServicesPage::new();
        let ports_page = PortsPage::new();
        let system_services_page = SystemServicesPage::new();
        let network_exposure_page = NetworkExposurePage::new();
        let quick_actions_page = QuickActionsPage::new();
        let help_page = HelpPage::new();

        // Wire up clients to pages
        zones_page.set_client(imp.client.clone());
        services_page.set_client(imp.client.clone());
        ports_page.set_client(imp.client.clone());

        stack.add_named(&overview_page, Some("overview"));
        stack.add_named(&zones_page, Some("zones"));
        stack.add_named(&services_page, Some("services"));
        stack.add_named(&ports_page, Some("ports"));
        stack.add_named(&system_services_page, Some("system-services"));
        stack.add_named(&network_exposure_page, Some("network-exposure"));
        stack.add_named(&quick_actions_page, Some("quick-actions"));
        stack.add_named(&help_page, Some("help"));

        // Connect the traffic switch to toggle_firewall
        if let Some(switch) = overview_page.traffic_switch() {
            let window_clone = self.clone();
            switch.connect_state_set(move |switch, state| {
                window_clone.toggle_firewall(state);
                switch.set_state(state);
                glib::Propagation::Stop
            });
        }

        // Store pages
        imp.overview_page.replace(Some(overview_page));
        imp.zones_page.replace(Some(zones_page));
        imp.services_page.replace(Some(services_page));
        imp.ports_page.replace(Some(ports_page));
        imp.system_services_page.replace(Some(system_services_page));
        imp.network_exposure_page.replace(Some(network_exposure_page));
        imp.quick_actions_page.replace(Some(quick_actions_page));
        imp.stack.replace(Some(stack.clone()));

        // === SIDEBAR ===
        let sidebar_box = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Vertical)
            .build();

        // Sidebar header with app title
        let sidebar_header = adw::HeaderBar::new();
        sidebar_header.set_show_end_title_buttons(false);

        // Sidebar collapse button (top-right of sidebar header)
        let sidebar_toggle_btn = gtk4::Button::builder()
            .icon_name("sidebar-show-symbolic")
            .tooltip_text("Hide sidebar")
            .build();
        sidebar_toggle_btn.add_css_class("flat");
        sidebar_toggle_btn.set_action_name(Some("win.toggle-sidebar"));
        sidebar_header.pack_end(&sidebar_toggle_btn);

        let sidebar_title = adw::WindowTitle::new("Security Center", "");
        sidebar_header.set_title_widget(Some(&sidebar_title));
        sidebar_box.append(&sidebar_header);

        // Navigation list with icons
        let nav_list = gtk4::ListBox::builder()
            .selection_mode(gtk4::SelectionMode::Single)
            .css_classes(vec!["navigation-sidebar".to_string()])
            .vexpand(true)
            .build();

        let items = [
            ("overview", "Overview", "view-grid-symbolic"),
            ("zones", "Zones", "network-server-symbolic"),
            ("services", "Services", "application-x-addon-symbolic"),
            ("ports", "Ports", "network-transmit-receive-symbolic"),
            ("system-services", "System Services", "system-run-symbolic"),
            ("network-exposure", "Network Exposure", "network-wired-symbolic"),
            ("quick-actions", "Quick Actions", "system-shutdown-symbolic"),
            ("help", "Help", "help-about-symbolic"),
        ];

        for (id, label, icon) in items {
            let row = adw::ActionRow::builder()
                .title(label)
                .build();
            row.add_prefix(&gtk4::Image::from_icon_name(icon));
            row.set_widget_name(id);
            nav_list.append(&row);
        }

        let stack_clone = stack.clone();
        let window_clone = self.clone();
        nav_list.connect_row_selected(move |_, row| {
            if let Some(row) = row {
                let name = row.widget_name();
                stack_clone.set_visible_child_name(&name);
                
                // Update content title
                let title = match name.as_str() {
                    "overview" => "Overview",
                    "zones" => "Zones",
                    "services" => "Services",
                    "ports" => "Ports",
                    "system-services" => "System Services",
                    "network-exposure" => "Network Exposure",
                    "quick-actions" => "Quick Actions",
                    "help" => "Help",
                    _ => "Overview",
                };
                if let Some(content_title) = window_clone.imp().content_title.borrow().as_ref() {
                    content_title.set_title(title);
                }
                
                // Refresh page when selected
                match name.as_str() {
                    "system-services" => {
                        if let Some(page) = window_clone.imp().system_services_page.borrow().as_ref() {
                            page.refresh_services();
                        }
                    }
                    "network-exposure" => {
                        if let Some(page) = window_clone.imp().network_exposure_page.borrow().as_ref() {
                            page.refresh();
                        }
                    }
                    _ => {}
                }
            }
        });

        if let Some(row) = nav_list.row_at_index(0) {
            nav_list.select_row(Some(&row));
        }

        let sidebar_scroll = gtk4::ScrolledWindow::new();
        sidebar_scroll.set_vexpand(true);
        sidebar_scroll.set_child(Some(&nav_list));
        sidebar_box.append(&sidebar_scroll);

        // Version and author info at the bottom of sidebar
        let info_box = gtk4::Box::new(gtk4::Orientation::Vertical, 2);
        info_box.set_margin_start(12);
        info_box.set_margin_end(12);
        info_box.set_margin_top(8);
        info_box.set_margin_bottom(8);
        
        let version_label = gtk4::Label::new(None);
        version_label.set_markup(&format!("<span size=\"x-small\">Version {}</span>", env!("CARGO_PKG_VERSION")));
        version_label.set_halign(gtk4::Align::Start);
        info_box.append(&version_label);
        
        let author_label = gtk4::Label::new(None);
        author_label.set_markup("<span size=\"x-small\">By Christos A. Daggas</span>");
        author_label.set_halign(gtk4::Align::Start);
        info_box.append(&author_label);
        
        sidebar_box.append(&info_box);

        // === CONTENT AREA ===
        let content_box = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
        
        let header = adw::HeaderBar::new();
        let content_title = adw::WindowTitle::new("Overview", "");
        header.set_title_widget(Some(&content_title));
        imp.content_title.replace(Some(content_title));

        // Sidebar toggle button in content header (restores sidebar after hiding)
        let content_toggle_btn = gtk4::Button::builder()
            .icon_name("sidebar-show-symbolic")
            .tooltip_text("Show sidebar")
            .build();
        content_toggle_btn.add_css_class("flat");
        content_toggle_btn.set_visible(false);
        content_toggle_btn.set_action_name(Some("win.toggle-sidebar"));
        header.pack_start(&content_toggle_btn);
        
        let menu_button = gtk4::MenuButton::builder()
            .icon_name("open-menu-symbolic")
            .build();
        
        // Create custom popover with theme selection
        let popover = self.create_menu_popover();
        menu_button.set_popover(Some(&popover));
        
        header.pack_end(&menu_button);

        let refresh_button = gtk4::Button::builder()
            .icon_name("view-refresh-symbolic")
            .action_name("win.refresh")
            .tooltip_text("Refresh (Ctrl+R)")
            .build();
        header.pack_end(&refresh_button);

        content_box.append(&header);
        
        let scrolled = gtk4::ScrolledWindow::builder()
            .hscrollbar_policy(gtk4::PolicyType::Never)
            .vscrollbar_policy(gtk4::PolicyType::Automatic)
            .vexpand(true)
            .hexpand(true)
            .child(&stack)
            .build();
        content_box.append(&scrolled);

        // === SPLIT VIEW ===
        // Use OverlaySplitView for collapsible sidebar
        let split_view = adw::OverlaySplitView::new();
        split_view.set_min_sidebar_width(220.0);
        split_view.set_max_sidebar_width(280.0);
        split_view.set_pin_sidebar(true);
        split_view.set_sidebar(Some(&sidebar_box));
        split_view.set_content(Some(&content_box));

        // Store references
        *imp.split_view.borrow_mut() = Some(split_view.clone());
        *imp.content_toggle_btn.borrow_mut() = Some(content_toggle_btn);

        toast_overlay.set_child(Some(&split_view));
        self.set_content(Some(&toast_overlay));
    }

    /// Create the menu popover with theme selection circles.
    fn create_menu_popover(&self) -> gtk4::Popover {
        let popover = gtk4::Popover::new();
        popover.add_css_class("menu");

        let main_box = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Vertical)
            .spacing(0)
            .width_request(280)
            .build();

        // Theme selector section
        let theme_box = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .spacing(18)
            .halign(gtk4::Align::Center)
            .margin_top(18)
            .margin_bottom(18)
            .build();

        // Create theme toggle buttons
        let default_btn = gtk4::ToggleButton::new();
        let light_btn = gtk4::ToggleButton::new();
        let dark_btn = gtk4::ToggleButton::new();

        // Helper to create theme button content
        fn create_theme_content(css_class: &str, is_selected: bool) -> gtk4::Overlay {
            let overlay = gtk4::Overlay::new();
            
            let icon = gtk4::Box::builder()
                .width_request(44)
                .height_request(44)
                .build();
            icon.add_css_class("theme-selector");
            icon.add_css_class(css_class);
            overlay.set_child(Some(&icon));
            
            if is_selected {
                let check = gtk4::Image::from_icon_name("object-select-symbolic");
                check.add_css_class("theme-check");
                check.set_halign(gtk4::Align::Center);
                check.set_valign(gtk4::Align::Center);
                overlay.add_overlay(&check);
            }
            
            overlay
        }

        // Set initial content
        default_btn.set_child(Some(&create_theme_content("theme-default", false)));
        default_btn.set_tooltip_text(Some("System"));
        default_btn.add_css_class("flat");
        default_btn.add_css_class("circular");
        default_btn.add_css_class("theme-button");

        light_btn.set_child(Some(&create_theme_content("theme-light", false)));
        light_btn.set_tooltip_text(Some("Light"));
        light_btn.add_css_class("flat");
        light_btn.add_css_class("circular");
        light_btn.add_css_class("theme-button");

        dark_btn.set_child(Some(&create_theme_content("theme-dark", false)));
        dark_btn.set_tooltip_text(Some("Dark"));
        dark_btn.add_css_class("flat");
        dark_btn.add_css_class("circular");
        dark_btn.add_css_class("theme-button");

        // Group the toggle buttons (radio-button behavior)
        light_btn.set_group(Some(&default_btn));
        dark_btn.set_group(Some(&default_btn));

        // Set initial state based on current theme
        let style_manager = adw::StyleManager::default();
        
        match style_manager.color_scheme() {
            adw::ColorScheme::ForceLight => {
                light_btn.set_active(true);
                light_btn.set_child(Some(&create_theme_content("theme-light", true)));
            }
            adw::ColorScheme::ForceDark => {
                dark_btn.set_active(true);
                dark_btn.set_child(Some(&create_theme_content("theme-dark", true)));
            }
            _ => {
                default_btn.set_active(true);
                default_btn.set_child(Some(&create_theme_content("theme-default", true)));
            }
        }

        // Connect theme button signals
        let light_btn_clone = light_btn.clone();
        let dark_btn_clone = dark_btn.clone();
        default_btn.connect_toggled(move |btn| {
            if btn.is_active() {
                let style_manager = adw::StyleManager::default();
                style_manager.set_color_scheme(adw::ColorScheme::Default);
                let mut settings = crate::config::Settings::new();
                settings.set_theme("system");
                btn.set_child(Some(&create_theme_content("theme-default", true)));
                light_btn_clone.set_child(Some(&create_theme_content("theme-light", false)));
                dark_btn_clone.set_child(Some(&create_theme_content("theme-dark", false)));
            }
        });

        let default_btn_clone = default_btn.clone();
        let dark_btn_clone2 = dark_btn.clone();
        light_btn.connect_toggled(move |btn| {
            if btn.is_active() {
                let style_manager = adw::StyleManager::default();
                style_manager.set_color_scheme(adw::ColorScheme::ForceLight);
                let mut settings = crate::config::Settings::new();
                settings.set_theme("light");
                btn.set_child(Some(&create_theme_content("theme-light", true)));
                default_btn_clone.set_child(Some(&create_theme_content("theme-default", false)));
                dark_btn_clone2.set_child(Some(&create_theme_content("theme-dark", false)));
            }
        });

        let default_btn_clone2 = default_btn.clone();
        let light_btn_clone2 = light_btn.clone();
        dark_btn.connect_toggled(move |btn| {
            if btn.is_active() {
                let style_manager = adw::StyleManager::default();
                style_manager.set_color_scheme(adw::ColorScheme::ForceDark);
                let mut settings = crate::config::Settings::new();
                settings.set_theme("dark");
                btn.set_child(Some(&create_theme_content("theme-dark", true)));
                default_btn_clone2.set_child(Some(&create_theme_content("theme-default", false)));
                light_btn_clone2.set_child(Some(&create_theme_content("theme-light", false)));
            }
        });

        theme_box.append(&default_btn);
        theme_box.append(&light_btn);
        theme_box.append(&dark_btn);
        main_box.append(&theme_box);

        // Separator
        let separator = gtk4::Separator::new(gtk4::Orientation::Horizontal);
        separator.set_margin_start(12);
        separator.set_margin_end(12);
        main_box.append(&separator);

        // Menu items
        let menu_list = gtk4::Box::new(gtk4::Orientation::Vertical, 2);
        menu_list.set_margin_top(6);
        menu_list.set_margin_bottom(6);
        menu_list.set_margin_start(6);
        menu_list.set_margin_end(6);

        // About button
        let about_btn = gtk4::Button::new();
        let about_box = gtk4::Box::new(gtk4::Orientation::Horizontal, 12);
        about_box.set_margin_start(6);
        about_box.set_margin_end(6);
        about_box.set_margin_top(8);
        about_box.set_margin_bottom(8);
        let about_icon = gtk4::Image::from_icon_name("help-about-symbolic");
        let about_label = gtk4::Label::new(Some("About"));
        about_label.set_halign(gtk4::Align::Start);
        about_label.set_hexpand(true);
        about_box.append(&about_icon);
        about_box.append(&about_label);
        about_btn.set_child(Some(&about_box));
        about_btn.add_css_class("flat");
        about_btn.add_css_class("menu-item");
        about_btn.set_action_name(Some("app.about"));
        menu_list.append(&about_btn);

        // Quit button
        let quit_btn = gtk4::Button::new();
        let quit_box = gtk4::Box::new(gtk4::Orientation::Horizontal, 12);
        quit_box.set_margin_start(6);
        quit_box.set_margin_end(6);
        quit_box.set_margin_top(8);
        quit_box.set_margin_bottom(8);
        let quit_icon = gtk4::Image::from_icon_name("application-exit-symbolic");
        let quit_label = gtk4::Label::new(Some("Quit"));
        quit_label.set_halign(gtk4::Align::Start);
        quit_label.set_hexpand(true);
        quit_box.append(&quit_icon);
        quit_box.append(&quit_label);
        quit_btn.set_child(Some(&quit_box));
        quit_btn.add_css_class("flat");
        quit_btn.add_css_class("menu-item");
        quit_btn.set_action_name(Some("app.quit"));
        menu_list.append(&quit_btn);

        main_box.append(&menu_list);

        popover.set_child(Some(&main_box));
        popover
    }

    /// Setup window actions.
    fn setup_actions(&self) {
        // Refresh action
        let window = self.clone();
        let refresh = gio::ActionEntry::builder("refresh")
            .activate(move |_: &Self, _, _| {
                window.refresh_data();
            })
            .build();

        // Toggle sidebar action
        let action_toggle_sidebar = gio::ActionEntry::builder("toggle-sidebar")
            .activate(|window: &Self, _, _| {
                window.toggle_sidebar();
            })
            .build();

        self.add_action_entries([refresh, action_toggle_sidebar]);
    }

    /// Toggle the sidebar visibility.
    fn toggle_sidebar(&self) {
        let imp = self.imp();

        let split_view_borrow = imp.split_view.borrow();
        let Some(split_view) = split_view_borrow.as_ref() else {
            return;
        };

        // Toggle the sidebar visibility using OverlaySplitView's show_sidebar property
        let currently_shown = split_view.shows_sidebar();
        split_view.set_show_sidebar(!currently_shown);

        // Update button visibility: show content toggle when sidebar is hidden
        if let Some(btn) = imp.content_toggle_btn.borrow().as_ref() {
            btn.set_visible(currently_shown); // will be hidden after toggle
        }
    }

    /// Connect to firewalld (non-blocking).
    fn connect_to_firewalld(&self) {
        // Trigger a refresh - the refresh_data method handles connection
        self.refresh_data();
    }

    /// Refresh all data from firewalld without blocking the UI.
    pub fn refresh_data(&self) {
        let window = self.clone();
        
        // Run D-Bus calls in a background thread to avoid freezing the UI
        glib::spawn_future_local(async move {
            let data = gio::spawn_blocking(move || {
                // This runs in a background thread
                let client = crate::firewall::FirewallClient::new();
                let mut client = client;
                
                if client.connect().is_err() {
                    return None;
                }
                
                let zones = client.get_zones().ok();
                let services = client.get_services().ok();
                let default_zone = client.get_default_zone().ok();
                
                let ports: Vec<crate::models::Port> = zones.as_ref()
                    .map(|zones| {
                        zones.iter()
                            .flat_map(|zone| {
                                zone.ports.iter()
                                    .filter_map(|port_str| {
                                        crate::models::Port::parse_with_zone(port_str, &zone.name)
                                    })
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                
                // Collect blocked ports from rich rules
                let blocked_ports: Vec<crate::models::Port> = zones.as_ref()
                    .map(|zones| {
                        zones.iter()
                            .flat_map(|zone| {
                                zone.rich_rules.iter()
                                    .filter_map(|rule| {
                                        crate::models::Port::parse_from_rich_rule(rule, &zone.name)
                                    })
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                
                Some((zones, services, default_zone, ports, blocked_ports))
            }).await;
            
            // Back on the main thread - update UI
            if let Ok(Some((zones, services, _default_zone, ports, blocked_ports))) = data {
                let imp = window.imp();
                
                // Update zones page
                if let Some(ref zones) = zones {
                    if let Some(page) = imp.zones_page.borrow().as_ref() {
                        page.set_zones(zones);
                    }
                }
                
                // Update services page
                if let Some(ref services) = services {
                    if let Some(page) = imp.services_page.borrow().as_ref() {
                        page.set_services(services);
                    }
                }
                
                // Update ports page with both open and blocked ports
                if let Some(page) = imp.ports_page.borrow().as_ref() {
                    // Pass available zone names for the dropdown
                    if let Some(ref zones) = zones {
                        let zone_names: Vec<String> = zones.iter().map(|z| z.name.clone()).collect();
                        page.set_available_zones(&zone_names);
                    }
                    page.set_ports(&ports);
                    page.set_blocked_ports(&blocked_ports);
                }

                // Update overview page quick stats and blocked ports
                if let Some(ref zones) = zones {
                    if let Some(page) = imp.overview_page.borrow().as_ref() {
                        page.set_zones(zones);
                        page.set_blocked_ports(&blocked_ports);
                    }
                }
                
                window.update_status(true, false);
            }
        });
    }

    /// Toggle the firewall on/off using panic mode.
    fn toggle_firewall(&self, enable: bool) {
        let window = self.clone();

        glib::spawn_future_local(async move {
            let result = gtk4::gio::spawn_blocking(move || {
                // Create a new client in the background thread
                let mut client = FirewallClient::new();
                if let Err(e) = client.connect() {
                    return Err(format!("Failed to connect: {}", e));
                }
                
                if enable {
                    // Disable panic mode to re-enable firewall
                    client.disable_panic_mode().map_err(|e| e.to_string())
                } else {
                    // Enable panic mode to disable firewall (blocks all traffic)
                    client.enable_panic_mode().map_err(|e| e.to_string())
                }
            }).await;

            match result {
                Ok(Ok(())) => {
                    if enable {
                        window.show_toast("Firewall enabled");
                        window.update_status(true, false);
                    } else {
                        window.show_toast("Firewall disabled (panic mode)");
                        window.update_status(true, true);
                    }
                }
                Ok(Err(e)) => {
                    window.show_toast(&format!("Error: {}", e));
                    // Reset switch state via overview page
                    if let Some(page) = window.imp().overview_page.borrow().as_ref() {
                        page.set_traffic_enabled(!enable);
                    }
                }
                Err(e) => {
                    window.show_toast(&format!("Error: {:?}", e));
                    // Reset switch state via overview page
                    if let Some(page) = window.imp().overview_page.borrow().as_ref() {
                        page.set_traffic_enabled(!enable);
                    }
                }
            }
        });
    }

    /// Update the firewall status display.
    fn update_status(&self, connected: bool, panic_mode: bool) {
        let imp = self.imp();
        
        let active = connected && !panic_mode;
        
        // Update via overview page
        if let Some(page) = imp.overview_page.borrow().as_ref() {
            page.set_traffic_enabled(active);
        }
    }

    /// Show an error message.
    #[allow(dead_code)]
    fn show_error(&self, message: &str) {
        let dialog = adw::AlertDialog::builder()
            .heading("Error")
            .body(message)
            .build();

        dialog.add_response("ok", "_OK");
        dialog.present(Some(self));
    }

    /// Get the firewall client.
    pub fn client(&self) -> Rc<RefCell<FirewallClient>> {
        self.imp().client.clone()
    }
}

mod imp {
    use super::*;
    use libadwaita::subclass::prelude::*;

    #[derive(Default)]
    pub struct MainWindow {
        pub client: Rc<RefCell<FirewallClient>>,
        pub stack: RefCell<Option<gtk4::Stack>>,
        pub toast_overlay: RefCell<Option<adw::ToastOverlay>>,
        pub content_title: RefCell<Option<adw::WindowTitle>>,
        pub split_view: RefCell<Option<adw::OverlaySplitView>>,
        pub content_toggle_btn: RefCell<Option<gtk4::Button>>,
        pub overview_page: RefCell<Option<OverviewPage>>,
        pub zones_page: RefCell<Option<ZonesPage>>,
        pub services_page: RefCell<Option<ServicesPage>>,
        pub ports_page: RefCell<Option<PortsPage>>,
        pub system_services_page: RefCell<Option<SystemServicesPage>>,
        pub network_exposure_page: RefCell<Option<NetworkExposurePage>>,
        pub quick_actions_page: RefCell<Option<QuickActionsPage>>,
    }

    #[glib::object_subclass]
    impl ObjectSubclass for MainWindow {
        const NAME: &'static str = "GnomeFirewallMainWindow";
        type Type = super::MainWindow;
        type ParentType = adw::ApplicationWindow;
    }

    impl ObjectImpl for MainWindow {}
    impl WidgetImpl for MainWindow {}
    impl WindowImpl for MainWindow {}
    impl ApplicationWindowImpl for MainWindow {}
    impl AdwApplicationWindowImpl for MainWindow {}
}

