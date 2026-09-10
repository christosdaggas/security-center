// Security Center - Storage
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: MIT

//! Persistent storage for port metadata.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::validation::{validate_port_name, validate_protocol};

const MAX_STORAGE_FILE_SIZE: u64 = 1_048_576; // 1 MB

/// Metadata about a port rule.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct PortMetadata {
    pub name: String,
    pub description: String,
    pub created_at: String,
    #[serde(default)]
    pub incoming_action: String, // "allow", "deny", or ""
    #[serde(default)]
    pub outgoing_action: String, // "allow", "deny", or ""
    #[serde(default)]
    pub zone: String,
    #[serde(default)]
    pub protocol: String,
    #[serde(default)]
    pub port: u16,
    /// End of a port range (inclusive); 0 for a single port.
    /// Skipped when 0 so files without ranges stay readable by older
    /// releases, whose `deny_unknown_fields` rejects unknown keys.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub end_port: u16,
}

fn is_zero(value: &u16) -> bool {
    *value == 0
}

/// Storage keys are "port-spec/proto/zone" (e.g. "80/tcp/public",
/// "10-20/udp/home"). Reject anything else so corrupt files fail closed.
fn is_valid_storage_key(key: &str) -> bool {
    let parts: Vec<&str> = key.split('/').collect();
    if parts.len() != 3 {
        return false;
    }
    if crate::validation::parse_port_spec(parts[0]).is_none() {
        return false;
    }
    if crate::validation::validate_protocol(parts[1]).is_none() {
        return false;
    }
    if crate::validation::validate_zone_name(parts[2]).is_none() {
        return false;
    }
    if key.len() > 128 {
        return false;
    }
    true
}

/// Atomic 0600 write shared with config.rs (duplicated to avoid a new module).
fn atomic_write_0600(path: &PathBuf, content: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("json.tmp");
    {
        #[cfg(unix)]
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        #[cfg(not(unix))]
        let mut file = fs::File::create(&tmp)?;
        file.write_all(content)?;
        file.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    #[cfg(unix)]
    {
        if let Some(parent) = path.parent() {
            if let Ok(dir) = fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
    }
    Ok(())
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
            end_port: 0,
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
            end_port: 0,
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
            .or_else(dirs::home_dir)
            .map(|b| b.join("security-center").join("port_metadata.json"))
            .unwrap_or_else(|| std::env::temp_dir().join("security-center-port_metadata.json"));

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
        let Ok(content) = fs::read_to_string(&self.path) else {
            self.dirty = false;
            return;
        };
        // Size checked after read so a concurrent writer cannot bypass it.
        if content.len() as u64 > MAX_STORAGE_FILE_SIZE {
            warn!(
                "Port metadata file too large ({} bytes), ignoring",
                content.len()
            );
            self.dirty = false;
            return;
        }

        match serde_json::from_str::<HashMap<String, PortMetadata>>(&content) {
            Ok(data) => {
                self.data = Self::sanitize_data(data);
            }
            Err(e) => {
                warn!("Failed to parse port metadata: {}", e);
            }
        }
        self.dirty = false;
    }

    fn sanitize_data(data: HashMap<String, PortMetadata>) -> HashMap<String, PortMetadata> {
        let mut sanitized = HashMap::new();
        for (key, mut meta) in data {
            // Keys are "port/proto/zone" — reject anything malformed so a
            // hand-edited file cannot inject unexpected rows.
            if !is_valid_storage_key(&key) {
                warn!("Discarding port metadata entry with invalid key: {}", key);
                continue;
            }
            // Validate protocol
            if !meta.protocol.is_empty() && validate_protocol(&meta.protocol).is_none() {
                warn!(
                    "Discarding port metadata entry with invalid protocol: {}",
                    meta.protocol
                );
                continue;
            }
            // Validate port number (must be > 0 if protocol is set)
            if meta.port == 0 && !meta.protocol.is_empty() {
                warn!("Discarding port metadata entry with port 0 and non-empty protocol");
                continue;
            }
            // Normalize a nonsensical range end (must be greater than start)
            if meta.end_port != 0 && meta.end_port <= meta.port {
                meta.end_port = 0;
            }
            // Sanitize the name through the same charset rules as user input.
            // The metadata file is untrusted (SECURITY.md), and names are shown
            // in row titles; an unsanitized name could inject Pango markup.
            // Truncate over-long names first so only the charset can reject.
            // Cut on a char boundary so multibyte names cannot panic.
            if meta.name.chars().count() > 64 {
                meta.name = meta.name.chars().take(64).collect();
            }
            match validate_port_name(&meta.name) {
                Some(clean) => meta.name = clean,
                None => {
                    warn!("Discarding port metadata entry with unsafe name");
                    continue;
                }
            }
            sanitized.insert(key, meta);
        }
        sanitized
    }

    pub fn save(&mut self) {
        if !self.dirty {
            return;
        }

        match serde_json::to_string_pretty(&self.data) {
            Ok(content) => match atomic_write_0600(&self.path, content.as_bytes()) {
                Ok(()) => self.dirty = false,
                Err(e) => warn!("Failed to save port metadata: {}", e),
            },
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

    pub fn get_all(&mut self) -> Vec<PortMetadata> {
        self.ensure_loaded();
        self.data.values().cloned().collect()
    }

    /// Build a storage key from a port spec ("80" or "10-20"), protocol and zone.
    /// Single-port keys keep the historical "80/tcp/public" format.
    pub fn make_key(port_spec: &str, protocol: &str, zone: &str) -> String {
        format!("{}/{}/{}", port_spec, protocol, zone)
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
                end_port: 0,
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
                end_port: 0,
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
                end_port: 0,
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
                end_port: 0,
            },
        );
        let sanitized = PortStorage::sanitize_data(data);
        assert_eq!(sanitized["80/tcp/public"].name.len(), 64);
    }

    #[test]
    #[cfg(unix)]
    fn test_save_sets_permissions() {
        let tmp =
            std::env::temp_dir().join(format!("security-center-test-{}.json", std::process::id()));
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
