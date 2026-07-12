// Security Center - Application icon & label helpers
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: MIT

//! Shared helpers for turning a process name + remote port into a themed icon
//! and a friendly display label. Used by both the dashboard overview and the
//! full Connections page so the two views stay visually consistent.

/// The default display's icon theme, if a display is available.
pub fn icon_theme() -> Option<gtk4::IconTheme> {
    gtk4::gdk::Display::default().map(|d| gtk4::IconTheme::for_display(&d))
}

/// Make Flatpak-exported application icons resolvable by name. Safe to call
/// more than once — adding an existing search path is a no-op.
pub fn register_flatpak_icon_paths() {
    if let Some(theme) = icon_theme() {
        theme.add_search_path("/var/lib/flatpak/exports/share/icons");
        if let Some(home) = std::env::var_os("HOME") {
            let mut p = std::path::PathBuf::from(home);
            p.push(".local/share/flatpak/exports/share/icons");
            theme.add_search_path(&p);
        }
    }
}

/// Bucket a remote port into a coarse protocol name.
pub fn protocol_of(port: u16) -> &'static str {
    match port {
        443 | 8443 => "HTTPS",
        80 | 8080 | 8000 => "HTTP",
        53 => "DNS",
        22 => "SSH",
        25 | 110 | 143 | 465 | 587 | 993 | 995 => "Mail",
        _ => "Other",
    }
}

/// A symbolic fallback icon based on the connection's port category.
pub fn category_icon(port: u16) -> &'static str {
    match protocol_of(port) {
        "HTTPS" | "HTTP" => "web-browser-symbolic",
        "DNS" => "network-workgroup-symbolic",
        "SSH" => "utilities-terminal-symbolic",
        "Mail" => "mail-unread-symbolic",
        _ => "application-x-executable-symbolic",
    }
}

/// Resolve the best themed icon name for a process: a real application icon
/// when one is installed, otherwise a symbolic category icon based on the port.
pub fn icon_for_process(process: &str, port: u16) -> String {
    let p = process.to_ascii_lowercase();

    let candidates: &[&str] = if p.contains("firefox") {
        &["firefox", "org.mozilla.firefox"]
    } else if p.contains("chromium") {
        &["chromium", "chromium-browser"]
    } else if p.contains("chrome") {
        &["google-chrome", "google-chrome-stable"]
    } else if p.contains("signal") {
        &["org.signal.Signal", "signal-desktop", "signal"]
    } else if p.contains("gnome-software") || p.contains("packagekit") {
        &["org.gnome.Software", "system-software-install"]
    } else if p.contains("vscod") || p.contains("code") {
        &[
            "vscode",
            "visual-studio-code",
            "code",
            "com.visualstudio.code",
        ]
    } else if p.contains("thunder") {
        &["thunderbird", "org.mozilla.Thunderbird"]
    } else if p.contains("discord") {
        &["discord", "com.discordapp.Discord"]
    } else if p.contains("steam") {
        &["steam"]
    } else if p.contains("spotify") {
        &["spotify", "com.spotify.Client"]
    } else if p.contains("telegram") {
        &["org.telegram.desktop", "telegram"]
    } else if p.contains("slack") {
        &["slack", "com.slack.Slack"]
    } else if p.contains("evolution") {
        &["org.gnome.Evolution", "evolution"]
    } else if p.contains("nautilus") {
        &["org.gnome.Nautilus"]
    } else if p.contains("curl") || p.contains("wget") {
        &["folder-download-symbolic"]
    } else {
        &[]
    };

    if let Some(theme) = icon_theme() {
        for name in candidates {
            if theme.has_icon(name) {
                return (*name).to_string();
            }
        }
        // Fall back to trying the raw process name as an icon.
        if !p.is_empty() && theme.has_icon(&p) {
            return p;
        }
    }
    category_icon(port).to_string()
}

/// Convert process executable names into friendlier card titles.
pub fn display_process_name(process: &str) -> String {
    process
        .split(['-', '_', ' '])
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().chain(chars).collect::<String>(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}
