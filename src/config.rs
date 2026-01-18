// Security Center - Configuration
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: MIT

//! Application settings management using a local JSON file.

use std::fs;
use std::path::PathBuf;
use serde::{Deserialize, Serialize};
use tracing::warn;

/// Application settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    /// Window width.
    #[serde(default = "default_width")]
    pub window_width: i32,
    /// Window height.
    #[serde(default = "default_height")]
    pub window_height: i32,
    /// Whether window is maximized.
    #[serde(default)]
    pub is_maximized: bool,
    /// Theme preference: "system", "light", or "dark".
    #[serde(default = "default_theme")]
    pub theme: String,
    /// Start the application on login.
    #[serde(default)]
    pub autostart_on_login: bool,
    /// Show system tray icon.
    #[serde(default)]
    pub show_tray_icon: bool,
}

fn default_width() -> i32 { 1386 }
fn default_height() -> i32 { 924 }
fn default_theme() -> String { "system".to_string() }

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            window_width: default_width(),
            window_height: default_height(),
            is_maximized: false,
            theme: default_theme(),
            autostart_on_login: false,
            show_tray_icon: false,
        }
    }
}

/// Settings manager that persists to a JSON file.
#[derive(Debug)]
pub struct Settings {
    settings: AppSettings,
    path: PathBuf,
}

impl Default for Settings {
    fn default() -> Self {
        Self::new()
    }
}

impl Settings {
    /// Create a new Settings instance, loading from disk.
    pub fn new() -> Self {
        let path = dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("gnome-security-center")
            .join("settings.json");

        let settings = if path.exists() {
            match fs::read_to_string(&path) {
                Ok(content) => {
                    match serde_json::from_str(&content) {
                        Ok(s) => s,
                        Err(e) => {
                            warn!("Failed to parse settings: {}", e);
                            AppSettings::default()
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to read settings: {}", e);
                    AppSettings::default()
                }
            }
        } else {
            AppSettings::default()
        };

        Self { settings, path }
    }

    /// Save settings to disk.
    pub fn save(&self) {
        if let Some(parent) = self.path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        match serde_json::to_string_pretty(&self.settings) {
            Ok(content) => {
                if let Err(e) = fs::write(&self.path, content) {
                    warn!("Failed to save settings: {}", e);
                }
            }
            Err(e) => {
                warn!("Failed to serialize settings: {}", e);
            }
        }
    }

    /// Get the window width.
    pub fn window_width(&self) -> i32 {
        self.settings.window_width
    }

    /// Set the window width.
    pub fn set_window_width(&mut self, width: i32) {
        self.settings.window_width = width;
        self.save();
    }

    /// Get the window height.
    pub fn window_height(&self) -> i32 {
        self.settings.window_height
    }

    /// Set the window height.
    pub fn set_window_height(&mut self, height: i32) {
        self.settings.window_height = height;
        self.save();
    }

    /// Get whether the window is maximized.
    pub fn is_maximized(&self) -> bool {
        self.settings.is_maximized
    }

    /// Set whether the window is maximized.
    pub fn set_maximized(&mut self, maximized: bool) {
        self.settings.is_maximized = maximized;
        self.save();
    }

    /// Get the theme preference.
    pub fn theme(&self) -> &str {
        &self.settings.theme
    }

    /// Set the theme preference.
    pub fn set_theme(&mut self, theme: &str) {
        self.settings.theme = theme.to_string();
        self.save();
    }

    /// Get autostart on login setting.
    pub fn autostart_on_login(&self) -> bool {
        self.settings.autostart_on_login
    }

    /// Set autostart on login.
    pub fn set_autostart_on_login(&mut self, enabled: bool) {
        self.settings.autostart_on_login = enabled;
        self.save();
    }

    /// Get show tray icon setting.
    pub fn show_tray_icon(&self) -> bool {
        self.settings.show_tray_icon
    }

    /// Set show tray icon.
    pub fn set_show_tray_icon(&mut self, enabled: bool) {
        self.settings.show_tray_icon = enabled;
        self.save();
    }
}
