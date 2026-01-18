// Security Center - Main Entry Point
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: MIT

//! Security Center - A GTK4/Libadwaita security management application.

use gtk4::prelude::*;
use gtk4::{gio, gdk, glib};
use libadwaita as adw;

// Re-export gtk4 as gtk for consistency
use gtk4 as gtk;

mod admin;
mod application;
mod autostart;
mod config;
mod firewall;
mod models;
mod stats;
mod storage;
mod systemd;
mod ui;

use application::Application;

/// Application ID for the security center.
const APP_ID: &str = "com.chrisdaggas.security-center";

fn main() -> glib::ExitCode {
    // Set the program name to match StartupWMClass in the .desktop file
    // This is critical for Wayland/GNOME Shell to match the window to the correct icon
    glib::set_prgname(Some(APP_ID));
    glib::set_application_name("Security Center");
    
    // Initialize logging
    tracing_subscriber::fmt::init();

    // Register resources
    let resource_bytes = include_bytes!(concat!(env!("OUT_DIR"), "/security-center.gresource"));
    let resource_data = glib::Bytes::from_static(resource_bytes);
    if let Ok(resource) = gio::Resource::from_data(&resource_data) {
        gio::resources_register(&resource);
    }

    // Load CSS
    load_css();

    // Create and run the application
    let app = Application::new(APP_ID);
    app.run()
}

fn load_css() {
    // Check for display availability (may fail in headless environments)
    let display = match gdk::Display::default() {
        Some(display) => display,
        None => {
            eprintln!("Security Center: Could not connect to a display. Are you running in a graphical environment?");
            return;
        }
    };

    let provider = gtk::CssProvider::new();
    provider.load_from_resource("/org/gnome/SecurityCenterCosmic/style.css");

    gtk::style_context_add_provider_for_display(
        &display,
        &provider,
        gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
    );

    // Get the style manager for theme change detection
    let style_manager = adw::StyleManager::default();

    // Clone provider for closures
    let provider_weak = provider.downgrade();

    // Reload CSS on color scheme changes (light/dark mode)
    let provider_clone = provider_weak.clone();
    style_manager.connect_color_scheme_notify(move |_| {
        if let Some(provider) = provider_clone.upgrade() {
            reload_css_provider(&provider);
        }
    });

    // Reload CSS on dark mode toggle
    let provider_clone = provider_weak.clone();
    style_manager.connect_dark_notify(move |_| {
        if let Some(provider) = provider_clone.upgrade() {
            reload_css_provider(&provider);
        }
    });

    // Reload CSS on high contrast changes
    let provider_clone = provider_weak.clone();
    style_manager.connect_high_contrast_notify(move |_| {
        if let Some(provider) = provider_clone.upgrade() {
            reload_css_provider(&provider);
        }
    });

    // Listen to GTK settings for additional theme changes
    if let Some(settings) = gtk::Settings::default() {
        let provider_clone = provider_weak.clone();
        settings.connect_gtk_theme_name_notify(move |_| {
            if let Some(provider) = provider_clone.upgrade() {
                reload_css_provider(&provider);
            }
        });

        let provider_clone = provider_weak.clone();
        settings.connect_gtk_application_prefer_dark_theme_notify(move |_| {
            if let Some(provider) = provider_clone.upgrade() {
                reload_css_provider(&provider);
            }
        });
    }
}

fn reload_css_provider(provider: &gtk::CssProvider) {
    provider.load_from_resource("/org/gnome/SecurityCenterCosmic/style.css");
}
