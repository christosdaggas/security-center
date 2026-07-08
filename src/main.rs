// Security Center - Main Entry Point
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: MIT

//! Security Center - A GTK4/Libadwaita security management application.

use gtk4::prelude::*;
use gtk4::{gio, glib};

mod admin;
mod application;
mod autostart;
mod config;
mod firewall;
mod i18n;
mod models;
mod stats;
mod storage;
mod systemd;
mod ui;
mod validation;
mod version_check;

use application::Application;

const APP_ID: &str = "com.chrisdaggas.security-center";

/// Translation domain — must match the installed `<domain>.mo` files.
const GETTEXT_DOMAIN: &str = "security-center";

fn main() -> glib::ExitCode {
    glib::set_prgname(Some("security-center"));

    // Wire up gettext so translated .mo catalogs load for the user's locale.
    // Must run before any translatable string is built.
    i18n::init(GETTEXT_DOMAIN);

    glib::set_application_name(&i18n::gettext("Security Center"));

    // Initialize tracing with a safe default filter.
    // RUST_LOG=trace may log sensitive system information.
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_target(false))
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let resource_bytes = include_bytes!(concat!(env!("OUT_DIR"), "/security-center.gresource"));
    let resource_data = glib::Bytes::from_static(resource_bytes);
    if let Ok(resource) = gio::Resource::from_data(&resource_data) {
        gio::resources_register(&resource);
    }

    let app = Application::new(APP_ID);
    app.run()
}
