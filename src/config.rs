// Security Center - Configuration
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: MIT

//! Application settings management using a local JSON file.

use std::fs;
use std::path::PathBuf;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::validation::{clamp_window_dimension, validate_theme};

const MAX_CONFIG_FILE_SIZE: u64 = 1_048_576; // 1 MB

/// Application settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
    pub fn new() -> Self {
        let config_base = dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."));

        let new_dir = config_base.join("security-center");
        let path = new_dir.join("settings.json");

        // Migrate from old "gnome-security-center" directory if it exists
        let old_dir = config_base.join("gnome-security-center");
        if old_dir.exists() && !new_dir.exists() {
            if let Err(e) = fs::rename(&old_dir, &new_dir) {
                warn!("Failed to migrate config directory: {}", e);
            }
        }

        let settings = if path.exists() {
            let metadata = fs::metadata(&path);
            if let Ok(m) = metadata {
                if m.len() > MAX_CONFIG_FILE_SIZE {
                    warn!("Settings file too large ({} bytes), using defaults", m.len());
                    AppSettings::default()
                } else {
                    match fs::read_to_string(&path) {
                        Ok(content) => {
                            match serde_json::from_str::<AppSettings>(&content) {
                                Ok(mut s) => {
                                    // Validate fields
                                    if validate_theme(&s.theme).is_none() {
                                        warn!("Invalid theme '{}' in settings, resetting to system", s.theme);
                                        s.theme = "system".to_string();
                                    }
                                    s.window_width = clamp_window_dimension(s.window_width);
                                    s.window_height = clamp_window_dimension(s.window_height);
                                    s
                                }
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
                }
            } else {
                AppSettings::default()
            }
        } else {
            AppSettings::default()
        };

        Self { settings, path }
    }

    pub fn save(&self) {
        use std::io::Write;
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;

        if let Some(parent) = self.path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        match serde_json::to_string_pretty(&self.settings) {
            Ok(content) => {
                match fs::File::create(&self.path) {
                    Ok(mut file) => {
                        #[cfg(unix)]
                        {
                            if let Err(e) = file.set_permissions(fs::Permissions::from_mode(0o600)) {
                                warn!("Failed to set file permissions: {}", e);
                            }
                        }
                        if let Err(e) = file.write_all(content.as_bytes()) {
                            warn!("Failed to save settings: {}", e);
                        }
                    }
                    Err(e) => {
                        warn!("Failed to create settings file: {}", e);
                    }
                }
            }
            Err(e) => {
                warn!("Failed to serialize settings: {}", e);
            }
        }
    }

    pub fn window_width(&self) -> i32 {
        self.settings.window_width
    }

    pub fn set_window_width(&mut self, width: i32) {
        self.settings.window_width = width;
        self.save();
    }

    pub fn window_height(&self) -> i32 {
        self.settings.window_height
    }

    pub fn set_window_height(&mut self, height: i32) {
        self.settings.window_height = height;
        self.save();
    }

    pub fn is_maximized(&self) -> bool {
        self.settings.is_maximized
    }

    pub fn set_maximized(&mut self, maximized: bool) {
        self.settings.is_maximized = maximized;
        self.save();
    }

    pub fn theme(&self) -> &str {
        &self.settings.theme
    }

    pub fn set_theme(&mut self, theme: &str) {
        self.settings.theme = theme.to_string();
        self.save();
    }

    pub fn autostart_on_login(&self) -> bool {
        self.settings.autostart_on_login
    }

    pub fn set_autostart_on_login(&mut self, enabled: bool) {
        self.settings.autostart_on_login = enabled;
        self.save();
    }

    pub fn show_tray_icon(&self) -> bool {
        self.settings.show_tray_icon
    }

    pub fn set_show_tray_icon(&mut self, enabled: bool) {
        self.settings.show_tray_icon = enabled;
        self.save();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clamp_window_dimension() {
        assert_eq!(clamp_window_dimension(50), 100);
        assert_eq!(clamp_window_dimension(500), 500);
        assert_eq!(clamp_window_dimension(20000), 10000);
    }

    #[test]
    fn test_validate_theme() {
        assert_eq!(validate_theme("system"), Some("system"));
        assert_eq!(validate_theme("light"), Some("light"));
        assert_eq!(validate_theme("dark"), Some("dark"));
        assert_eq!(validate_theme("hacked"), None);
    }
}
