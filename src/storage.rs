// Security Center - Storage
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: MIT

//! Persistent storage for port metadata.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::validation::validate_protocol;

const MAX_STORAGE_FILE_SIZE: u64 = 1_048_576; // 1 MB

/// Metadata about a port rule.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct PortMetadata {
    pub name: String,
    pub description: String,
    pub created_at: String,
    #[serde(default)]
    pub incoming_action: String,  // "allow", "deny", or ""
    #[serde(default)]
    pub outgoing_action: String,  // "allow", "deny", or ""
    #[serde(default)]
    pub zone: String,
    #[serde(default)]
    pub protocol: String,
    #[serde(default)]
    pub port: u16,
}

impl PortMetadata {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            description: String::new(),
            created_at: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            incoming_action: String::new(),
            outgoing_action: String::new(),
            zone: String::new(),
            protocol: String::new(),
            port: 0,
        }
    }

    pub fn with_description(name: &str, description: &str) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            created_at: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            incoming_action: String::new(),
            outgoing_action: String::new(),
            zone: String::new(),
            protocol: String::new(),
            port: 0,
        }
    }
    
    pub fn deny_rule(port: u16, protocol: &str, zone: &str, incoming: &str, outgoing: &str, name: &str) -> Self {
        Self {
            name: name.to_string(),
            description: String::new(),
            created_at: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            incoming_action: incoming.to_string(),
            outgoing_action: outgoing.to_string(),
            zone: zone.to_string(),
            protocol: protocol.to_string(),
            port,
        }
    }
}

/// Storage for port metadata.
#[derive(Debug, Default)]
pub struct PortStorage {
    data: HashMap<String, PortMetadata>,
    path: PathBuf,
    loaded: bool,
    dirty: bool,
}

impl PortStorage {
    pub fn new() -> Self {
        let path = dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("security-center")
            .join("port_metadata.json");

        Self {
            data: HashMap::new(),
            path,
            loaded: false,
            dirty: false,
        }
    }

    fn ensure_loaded(&mut self) {
        if !self.loaded {
            self.load();
            self.loaded = true;
        }
    }

    fn load(&mut self) {
        let metadata = fs::metadata(&self.path);
        if let Ok(m) = metadata {
            if m.len() > MAX_STORAGE_FILE_SIZE {
                warn!("Port metadata file too large ({} bytes), ignoring", m.len());
                self.dirty = false;
                return;
            }
        }

        if let Ok(content) = fs::read_to_string(&self.path) {
            match serde_json::from_str::<HashMap<String, PortMetadata>>(&content) {
                Ok(data) => {
                    self.data = Self::sanitize_data(data);
                }
                Err(e) => {
                    warn!("Failed to parse port metadata: {}", e);
                }
            }
        }
        self.dirty = false;
    }

    fn sanitize_data(data: HashMap<String, PortMetadata>) -> HashMap<String, PortMetadata> {
        let mut sanitized = HashMap::new();
        for (key, mut meta) in data {
            // Validate protocol
            if !meta.protocol.is_empty() && validate_protocol(&meta.protocol).is_none() {
                warn!("Discarding port metadata entry with invalid protocol: {}", meta.protocol);
                continue;
            }
            // Validate port number (must be > 0 if protocol is set)
            if meta.port == 0 && !meta.protocol.is_empty() {
                warn!("Discarding port metadata entry with port 0 and non-empty protocol");
                continue;
            }
            // Sanitize name length
            if meta.name.len() > 64 {
                meta.name.truncate(64);
            }
            sanitized.insert(key, meta);
        }
        sanitized
    }

    pub fn save(&mut self) {
        use std::io::Write;
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;

        if !self.dirty {
            return;
        }
        
        if let Some(parent) = self.path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        match serde_json::to_string_pretty(&self.data) {
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
                            warn!("Failed to save port metadata: {}", e);
                        } else {
                            self.dirty = false;
                        }
                    }
                    Err(e) => {
                        warn!("Failed to create port metadata file: {}", e);
                    }
                }
            }
            Err(e) => {
                warn!("Failed to serialize port metadata: {}", e);
            }
        }
    }

    pub fn get(&mut self, key: &str) -> Option<PortMetadata> {
        self.ensure_loaded();
        self.data.get(key).cloned()
    }

    pub fn set(&mut self, key: String, metadata: PortMetadata) {
        self.ensure_loaded();
        self.data.insert(key, metadata);
        self.dirty = true;
        self.save();
    }

    pub fn remove(&mut self, key: &str) {
        self.ensure_loaded();
        if self.data.remove(key).is_some() {
            self.dirty = true;
            self.save();
        }
    }

    pub fn has(&mut self, key: &str) -> bool {
        self.ensure_loaded();
        self.data.contains_key(key)
    }

    pub fn keys(&mut self) -> Vec<String> {
        self.ensure_loaded();
        self.data.keys().cloned().collect()
    }

    pub fn get_deny_rules(&mut self) -> Vec<PortMetadata> {
        self.ensure_loaded();
        self.data.values()
            .filter(|m| m.incoming_action == "deny" || m.outgoing_action == "deny")
            .cloned()
            .collect()
    }

    pub fn get_all(&mut self) -> Vec<PortMetadata> {
        self.ensure_loaded();
        self.data.values().cloned().collect()
    }

    pub fn make_key(port: u16, protocol: &str, zone: &str) -> String {
        format!("{}/{}/{}", port, protocol, zone)
    }

    pub fn make_simple_key(port: u16, protocol: &str) -> String {
        format!("{}/{}", port, protocol)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn test_sanitize_data_discards_invalid_protocol() {
        let mut data = HashMap::new();
        data.insert(
            "80/tcp/public".to_string(),
            PortMetadata {
                name: "HTTP".to_string(),
                description: "".to_string(),
                created_at: "".to_string(),
                incoming_action: "allow".to_string(),
                outgoing_action: "".to_string(),
                zone: "public".to_string(),
                protocol: "tcp\" reject".to_string(),
                port: 80,
            },
        );
        let sanitized = PortStorage::sanitize_data(data);
        assert!(sanitized.is_empty());
    }

    #[test]
    fn test_sanitize_data_keeps_valid_entry() {
        let mut data = HashMap::new();
        data.insert(
            "80/tcp/public".to_string(),
            PortMetadata {
                name: "HTTP".to_string(),
                description: "".to_string(),
                created_at: "".to_string(),
                incoming_action: "allow".to_string(),
                outgoing_action: "".to_string(),
                zone: "public".to_string(),
                protocol: "tcp".to_string(),
                port: 80,
            },
        );
        let sanitized = PortStorage::sanitize_data(data);
        assert_eq!(sanitized.len(), 1);
        assert_eq!(sanitized["80/tcp/public"].protocol, "tcp");
    }

    #[test]
    fn test_sanitize_data_discards_port_zero_with_protocol() {
        let mut data = HashMap::new();
        data.insert(
            "0/tcp/public".to_string(),
            PortMetadata {
                name: "".to_string(),
                description: "".to_string(),
                created_at: "".to_string(),
                incoming_action: "".to_string(),
                outgoing_action: "".to_string(),
                zone: "public".to_string(),
                protocol: "tcp".to_string(),
                port: 0,
            },
        );
        let sanitized = PortStorage::sanitize_data(data);
        assert!(sanitized.is_empty());
    }

    #[test]
    fn test_sanitize_data_truncates_long_name() {
        let mut data = HashMap::new();
        let long_name = "a".repeat(100);
        data.insert(
            "80/tcp/public".to_string(),
            PortMetadata {
                name: long_name.clone(),
                description: "".to_string(),
                created_at: "".to_string(),
                incoming_action: "allow".to_string(),
                outgoing_action: "".to_string(),
                zone: "public".to_string(),
                protocol: "tcp".to_string(),
                port: 80,
            },
        );
        let sanitized = PortStorage::sanitize_data(data);
        assert_eq!(sanitized["80/tcp/public"].name.len(), 64);
    }

    #[test]
    #[cfg(unix)]
    fn test_save_sets_permissions() {
        let tmp = std::env::temp_dir().join(format!(
            "security-center-test-{}.json",
            std::process::id()
        ));
        let mut storage = PortStorage {
            data: HashMap::new(),
            path: tmp.clone(),
            loaded: true,
            dirty: true,
        };
        storage.save();

        let metadata = std::fs::metadata(&tmp).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        // Cleanup
        let _ = std::fs::remove_file(&tmp);
    }
}
