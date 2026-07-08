// Security Center - Internationalization
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: MIT

//! Thin gettext wrapper so UI code can call `gettext("...")` uniformly.
//!
//! Translation catalogs are installed as `<prefix>/share/locale/<lang>/
//! LC_MESSAGES/security-center.mo`. When running uninstalled, set
//! `TEXTDOMAINDIR` to a directory with that layout to test translations.

use std::path::Path;

/// Initialize the gettext text domain and bind the locale directory.
pub fn init(domain: &str) {
    // Adopt the user's locale from the environment.
    gettextrs::setlocale(gettextrs::LocaleCategory::LcAll, "");

    // Allow overriding the catalog location for uninstalled/dev runs.
    let locale_dir = std::env::var("TEXTDOMAINDIR")
        .ok()
        .filter(|d| Path::new(d).is_dir())
        .unwrap_or_else(default_locale_dir);

    if let Err(e) = gettextrs::bindtextdomain(domain, &locale_dir) {
        tracing::warn!("bindtextdomain failed: {}", e);
    }
    // Catalogs are UTF-8.
    let _ = gettextrs::bind_textdomain_codeset(domain, "UTF-8");
    if let Err(e) = gettextrs::textdomain(domain) {
        tracing::warn!("textdomain failed: {}", e);
    }
}

/// Best-effort default catalog directory next to the running binary's prefix.
///
/// Installed layouts put the binary in `<prefix>/bin`, so locales live in
/// `<prefix>/share/locale`. Falls back to the system directory.
fn default_locale_dir() -> String {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(prefix) = exe.parent().and_then(|bin| bin.parent()) {
            let candidate = prefix.join("share").join("locale");
            if candidate.is_dir() {
                return candidate.to_string_lossy().into_owned();
            }
        }
    }
    "/usr/share/locale".to_string()
}

/// Translate a message via the bound text domain.
///
/// Returns the original string when no translation exists, so it is always
/// safe to wrap a literal.
pub fn gettext(msgid: &str) -> String {
    gettextrs::gettext(msgid)
}
