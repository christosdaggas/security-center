// Security Center - Autostart Management
// Copyright (C) 2026 Christos A. Daggas
// SPDX-License-Identifier: MIT

//! Manages the autostart .desktop file for starting the application on login.

use std::fs;
use std::io::Write;
use std::path::PathBuf;

const APP_ID: &str = "com.chrisdaggas.security-center";
const APP_NAME: &str = "Security Center";

/// Get the path to the autostart directory.
fn autostart_dir() -> Option<PathBuf> {
    dirs::config_dir().map(|p| p.join("autostart"))
}

/// Get the path to the autostart .desktop file.
fn autostart_file_path() -> Option<PathBuf> {
    autostart_dir().map(|p| p.join(format!("{}.desktop", APP_ID)))
}

/// Check if autostart is currently enabled.
/// A file with `Hidden=true` counts as disabled (per Desktop Entry spec).
pub fn is_autostart_enabled() -> bool {
    let Some(path) = autostart_file_path() else {
        return false;
    };
    if !path.exists() {
        return false;
    }
    // Hidden=true means "present but disabled" — respect it.
    match std::fs::read_to_string(&path) {
        Ok(content) => !content.lines().any(|l| {
            let t = l.trim();
            t.eq_ignore_ascii_case("Hidden=true")
        }),
        Err(_) => false,
    }
}

/// Enable autostart by creating the .desktop file.
pub fn enable_autostart() -> Result<(), String> {
    let dir = autostart_dir().ok_or("Could not determine autostart directory")?;
    let path = autostart_file_path().ok_or("Could not determine autostart file path")?;

    // Create autostart directory if it doesn't exist
    if !dir.exists() {
        fs::create_dir_all(&dir)
            .map_err(|e| format!("Failed to create autostart directory: {}", e))?;
    }

    // Create the .desktop file content. No custom flags: the app takes no
    // CLI options today, so `Exec=security-center --minimized` would fail on
    // every login. (A `--minimized` handler is added in application.rs for
    // backward compatibility with entries written by older releases.)
    let desktop_content = format!(
        r#"[Desktop Entry]
Name={}
Comment=Manage system security and firewall
Exec=security-center
Icon={}
Terminal=false
Type=Application
Categories=System;Security;Settings;
X-GNOME-Autostart-enabled=true
"#,
        APP_NAME, APP_ID
    );

    let mut file =
        fs::File::create(&path).map_err(|e| format!("Failed to create autostart file: {}", e))?;
    file.write_all(desktop_content.as_bytes())
        .map_err(|e| format!("Failed to write autostart file: {}", e))?;

    tracing::info!("Autostart enabled for {}", APP_ID);
    Ok(())
}

/// Disable autostart by removing the .desktop file.
pub fn disable_autostart() -> Result<(), String> {
    if let Some(path) = autostart_file_path() {
        if path.exists() {
            fs::remove_file(&path)
                .map_err(|e| format!("Failed to remove autostart file: {}", e))?;
            tracing::info!("Autostart disabled for {}", APP_ID);
        }
    }
    Ok(())
}

/// Set autostart state.
pub fn set_autostart(enabled: bool) -> Result<(), String> {
    if enabled {
        enable_autostart()
    } else {
        disable_autostart()
    }
}
