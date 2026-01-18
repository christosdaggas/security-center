// Security Center - Application
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: MIT

//! Main application struct and lifecycle management.

use std::cell::RefCell;

use gtk4::prelude::*;
use gtk4::subclass::prelude::*;
use gtk4::{gio, glib};
use libadwaita as adw;
use libadwaita::prelude::*;
use tracing::info;

use crate::config::Settings;
use crate::ui::MainWindow;

glib::wrapper! {
    /// The main application object.
    pub struct Application(ObjectSubclass<imp::Application>)
        @extends adw::Application, gtk4::Application, gio::Application,
        @implements gio::ActionGroup, gio::ActionMap;
}

impl Application {
    /// Create a new application instance.
    pub fn new(app_id: &str) -> Self {
        glib::Object::builder()
            .property("application-id", app_id)
            .property("flags", gio::ApplicationFlags::FLAGS_NONE)
            .build()
    }

    /// Setup application actions.
    fn setup_actions(&self) {
        // Quit action
        let quit_action = gio::ActionEntry::builder("quit")
            .activate(|app: &Self, _, _| {
                app.quit();
            })
            .build();

        // About action
        let about_action = gio::ActionEntry::builder("about")
            .activate(|app: &Self, _, _| {
                app.show_about_dialog();
            })
            .build();

        // Preferences action
        let preferences_action = gio::ActionEntry::builder("preferences")
            .activate(|app: &Self, _, _| {
                app.show_preferences_dialog();
            })
            .build();

        self.add_action_entries([quit_action, about_action, preferences_action]);
    }

    /// Show preferences dialog with theme selection.
    fn show_preferences_dialog(&self) {
        let dialog = adw::PreferencesDialog::builder()
            .title("Preferences")
            .build();

        let page = adw::PreferencesPage::new();
        
        // Appearance group
        let appearance_group = adw::PreferencesGroup::builder()
            .title("Appearance")
            .build();

        // Theme selection
        let theme_row = adw::ComboRow::builder()
            .title("Theme")
            .subtitle("Choose the application color scheme")
            .model(&gtk4::StringList::new(&["System", "Light", "Dark"]))
            .build();

        // Set current theme
        let settings = self.imp().settings.borrow();
        let current = match settings.theme() {
            "light" => 1,
            "dark" => 2,
            _ => 0,
        };
        drop(settings);
        theme_row.set_selected(current);

        // Connect theme change
        let app = self.clone();
        theme_row.connect_selected_notify(move |row| {
            let theme = match row.selected() {
                1 => "light",
                2 => "dark",
                _ => "system",
            };
            app.set_theme(theme);
        });

        appearance_group.add(&theme_row);
        page.add(&appearance_group);

        // Behavior group
        let behavior_group = adw::PreferencesGroup::builder()
            .title("Behavior")
            .description("Startup and system integration options")
            .build();

        // Check actual autostart state
        let autostart_enabled = crate::autostart::is_autostart_enabled();

        let autostart_row = adw::SwitchRow::builder()
            .title("Start on Login")
            .subtitle("Automatically start Security Center when you log in")
            .active(autostart_enabled)
            .build();

        autostart_row.connect_active_notify(|row| {
            let enabled = row.is_active();
            if let Err(e) = crate::autostart::set_autostart(enabled) {
                tracing::error!("Failed to set autostart: {}", e);
            }
        });

        behavior_group.add(&autostart_row);

        let tray_row = adw::SwitchRow::builder()
            .title("Show System Tray Icon")
            .subtitle("Display an icon in the system tray")
            .active(false)
            .build();

        tray_row.connect_active_notify(|row| {
            let enabled = row.is_active();
            // TODO: Show/hide tray icon dynamically
            tracing::info!("System tray icon setting changed to: {}", enabled);
        });

        behavior_group.add(&tray_row);
        page.add(&behavior_group);

        dialog.add(&page);

        if let Some(window) = self.active_window() {
            dialog.present(Some(&window));
        }
    }

    /// Set and apply the theme.
    pub fn set_theme(&self, theme: &str) {
        // Save to settings
        self.imp().settings.borrow_mut().set_theme(theme);
        
        // Apply theme
        self.apply_theme(theme);
    }

    /// Apply the theme to the application.
    fn apply_theme(&self, theme: &str) {
        let style_manager = adw::StyleManager::default();
        match theme {
            "light" => style_manager.set_color_scheme(adw::ColorScheme::ForceLight),
            "dark" => style_manager.set_color_scheme(adw::ColorScheme::ForceDark),
            _ => style_manager.set_color_scheme(adw::ColorScheme::Default),
        }
    }

    /// Setup keyboard shortcuts.
    fn setup_shortcuts(&self) {
        self.set_accels_for_action("app.quit", &["<Control>q"]);
        self.set_accels_for_action("win.refresh", &["<Control>r", "F5"]);
    }

    /// Show the about dialog.
    fn show_about_dialog(&self) {
        let dialog = adw::AboutDialog::builder()
            .application_name("Security Center")
            .application_icon("com.chrisdaggas.security-center")
            .developer_name("Christos A. Daggas")
            .version(env!("CARGO_PKG_VERSION"))
            .website("https://chrisdaggas.com")
            .issue_url("https://github.com/christosdaggas/security-center/issues")
            .license_type(gtk4::License::MitX11)
            .copyright("© 2024-2026 Christos A. Daggas")
            .developers(vec!["Christos A. Daggas".to_string()])
            .comments("Manage your system security, firewall and services")
            .build();

        if let Some(window) = self.active_window() {
            dialog.present(Some(&window));
        }
    }

    /// Register icon search paths so the app icon can be found.
    fn register_icon_paths(&self) {
        // Add icon search paths for development mode
        // When installed, icons should be in /usr/share/icons/hicolor (default search path)
        if let Some(display) = gtk4::gdk::Display::default() {
            let icon_theme = gtk4::IconTheme::for_display(&display);
            
            // Try to find icons relative to the executable (for development/portable use)
            if let Ok(exe_path) = std::env::current_exe() {
                if let Some(exe_dir) = exe_path.parent() {
                    // Check for icons relative to executable: ../../data/icons (from target/release/)
                    let dev_icons = exe_dir.join("../../data/icons");
                    if dev_icons.exists() {
                        if let Some(path_str) = dev_icons.canonicalize().ok().and_then(|p| p.to_str().map(String::from)) {
                            icon_theme.add_search_path(&path_str);
                        }
                    }
                }
            }
            
            // Also check current working directory (for cargo run)
            icon_theme.add_search_path("data/icons");
        }
    }

    /// Load and apply CSS styles with GNOME accent color support.
    fn load_css(&self) {
        let provider = gtk4::CssProvider::new();
        
        if let Some(display) = gtk4::gdk::Display::default() {
            // Get accent color from GNOME settings with fallback
            let accent_color = self.get_accent_color();
            
            let css = format!(r#"
                /* Define accent color with fallback */
                @define-color firewall_accent {accent_color};
                
                .stat-card {{
                    padding: 16px;
                    border-radius: 12px;
                    background: alpha(@card_bg_color, 0.8);
                }}
                .stat-value {{
                    font-size: 28px;
                    font-weight: bold;
                }}
                .stat-label {{
                    font-size: 12px;
                    opacity: 0.7;
                }}
                .zone-active {{
                    background: alpha(@success_color, 0.1);
                    border-left: 3px solid @success_color;
                }}
                .service-enabled {{
                    color: @success_color;
                }}
                .service-disabled {{
                    color: @warning_color;
                }}
                .risk-low {{ color: @success_color; }}
                .risk-medium {{ color: @warning_color; }}
                .risk-high {{ color: @error_color; }}
                
                /* Accent color styling */
                .accent-bg {{
                    background-color: alpha(@firewall_accent, 0.15);
                }}
                .accent-text {{
                    color: @firewall_accent;
                }}
                .accent-border {{
                    border: 1px solid alpha(@firewall_accent, 0.5);
                    border-radius: 6px;
                }}
                
                /* Protocol badges with accent */
                .protocol-tcp {{
                    background: alpha(@firewall_accent, 0.2);
                    color: @firewall_accent;
                    padding: 2px 8px;
                    border-radius: 4px;
                    font-weight: bold;
                    font-size: 10px;
                }}
                .protocol-udp {{
                    background: alpha(@warning_color, 0.2);
                    color: @warning_color;
                    padding: 2px 8px;
                    border-radius: 4px;
                    font-weight: bold;
                    font-size: 10px;
                }}
            "#);
            
            provider.load_from_string(&css);
            gtk4::style_context_add_provider_for_display(
                &display,
                &provider,
                gtk4::STYLE_PROVIDER_PRIORITY_APPLICATION,
            );
        }
    }

    /// Get the GNOME accent color, falling back to a default blue if not available.
    fn get_accent_color(&self) -> String {
        // Try to get accent color from GNOME settings using gio::Settings
        // This is safer than spawning a shell command
        let accent_color = gtk4::gio::Settings::new("org.gnome.desktop.interface")
            .string("accent-color");
        
        // Map GNOME accent color names to actual colors
        match accent_color.as_str() {
            "blue" => return "#3584e4".to_string(),
            "teal" => return "#2190a4".to_string(),
            "green" => return "#3a944a".to_string(),
            "yellow" => return "#c88800".to_string(),
            "orange" => return "#ed5b00".to_string(),
            "red" => return "#e62d42".to_string(),
            "pink" => return "#d56199".to_string(),
            "purple" => return "#9141ac".to_string(),
            "slate" => return "#6f8396".to_string(),
            _ => {}
        }
        
        // Fallback: Use a nice default blue that works well with both light and dark themes
        let style_manager = adw::StyleManager::default();
        let is_dark = style_manager.is_dark();
        if is_dark {
            "#62a0ea".to_string() // Lighter blue for dark theme
        } else {
            "#3584e4".to_string() // Standard GNOME blue for light theme
        }
    }
}

mod imp {
    use super::*;
    use std::cell::OnceCell;
    use libadwaita::subclass::prelude::*;

    #[derive(Default)]
    pub struct Application {
        pub window: OnceCell<MainWindow>,
        pub settings: RefCell<Settings>,
    }

    #[glib::object_subclass]
    impl ObjectSubclass for Application {
        const NAME: &'static str = "SecurityCenterApplication";
        type Type = super::Application;
        type ParentType = adw::Application;
    }

    impl ObjectImpl for Application {
        fn constructed(&self) {
            self.parent_constructed();
            // Initialize settings
            self.settings.replace(Settings::new());
        }
    }

    impl ApplicationImpl for Application {
        fn activate(&self) {
            let app = self.obj();
            
            // Load CSS
            app.load_css();
            
            // Apply saved theme
            let theme = self.settings.borrow().theme().to_string();
            app.apply_theme(&theme);
            
            // Setup actions and shortcuts
            app.setup_actions();
            app.setup_shortcuts();

            // Get or create window
            let window = self.window.get_or_init(|| {
                MainWindow::new(&*app)
            });

            window.present();
        }

        fn startup(&self) {
            self.parent_startup();
            info!("Application starting up");
            
            // Register icon search paths early so icons are available for windows
            self.obj().register_icon_paths();
            
            // Set the default icon for all windows in the application
            gtk4::Window::set_default_icon_name("com.chrisdaggas.security-center");
        }
    }

    impl GtkApplicationImpl for Application {}
    impl AdwApplicationImpl for Application {}
}
