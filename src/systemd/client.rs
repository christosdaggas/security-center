// Security Center - Systemd D-Bus Client
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: MIT

//! Systemd D-Bus client implementation for service management.

use anyhow::{anyhow, Context, Result};
use tracing::info;
use zbus::blocking::Connection;
use zbus::zvariant::OwnedObjectPath;

const SYSTEMD_BUS: &str = "org.freedesktop.systemd1";
const SYSTEMD_PATH: &str = "/org/freedesktop/systemd1";
const MANAGER_INTERFACE: &str = "org.freedesktop.systemd1.Manager";
const UNIT_INTERFACE: &str = "org.freedesktop.systemd1.Unit";

/// Service state enumeration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceState {
    Running,
    Stopped,
    Failed,
    Unknown,
}

impl ServiceState {
    pub fn from_str(s: &str) -> Self {
        match s {
            "running" => ServiceState::Running,
            "exited" | "dead" | "inactive" => ServiceState::Stopped,
            "failed" => ServiceState::Failed,
            _ => ServiceState::Unknown,
        }
    }

    pub fn css_class(&self) -> &'static str {
        match self {
            ServiceState::Running => "success",
            ServiceState::Stopped => "dim-label",
            ServiceState::Failed => "error",
            ServiceState::Unknown => "warning",
        }
    }
}

/// Information about a systemd service.
#[derive(Debug, Clone)]
pub struct ServiceInfo {
    pub name: String,
    pub display_name: String,
    pub description: String,
    pub state: ServiceState,
    pub is_enabled: bool,
    pub unit_path: String,
    pub main_pid: u32,
    pub memory_current: Option<u64>,
}

impl ServiceInfo {
    pub fn new(name: &str) -> Self {
        let display_name = name.trim_end_matches(".service").to_string();
        Self {
            name: name.to_string(),
            display_name,
            description: String::new(),
            state: ServiceState::Unknown,
            is_enabled: false,
            unit_path: String::new(),
            main_pid: 0,
            memory_current: None,
        }
    }

    /// Format memory as human-readable string.
    pub fn memory_display(&self) -> Option<String> {
        self.memory_current.map(|bytes| {
            if bytes >= 1024 * 1024 * 1024 {
                format!("{:.1} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
            } else if bytes >= 1024 * 1024 {
                format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
            } else if bytes >= 1024 {
                format!("{:.1} KB", bytes as f64 / 1024.0)
            } else {
                format!("{} B", bytes)
            }
        })
    }
}

/// Client for interacting with systemd via D-Bus.
pub struct SystemdClient {
    connection: Option<Connection>,
}

impl SystemdClient {
    /// Create a new systemd client.
    pub fn new() -> Self {
        Self { connection: None }
    }

    /// Connect to systemd.
    pub fn connect(&mut self) -> Result<()> {
        info!("Connecting to systemd...");

        let conn = Connection::system()
            .context("Failed to connect to system D-Bus")?;

        // Test connection by getting systemd version
        let value: zbus::zvariant::OwnedValue = conn
            .call_method(
                Some(SYSTEMD_BUS),
                SYSTEMD_PATH,
                Some("org.freedesktop.DBus.Properties"),
                "Get",
                &(MANAGER_INTERFACE, "Version"),
            )?
            .body()
            .deserialize()?;
        
        // Value is a variant containing a string
        let _version: String = value.try_into().unwrap_or_default();

        self.connection = Some(conn);
        info!("Connected to systemd");
        Ok(())
    }

    /// List important security-related services.
    pub fn list_security_services(&self) -> Result<Vec<ServiceInfo>> {
        // Pre-defined list of security-related services to show
        let security_services = [
            "firewalld.service",
            "sshd.service",
            "fail2ban.service",
            "ufw.service",
            "apparmor.service",
            "selinux-autorelabel.service",
            "auditd.service",
            "cups.service",
            "bluetooth.service",
            "avahi-daemon.service",
            "NetworkManager.service",
            "wpa_supplicant.service",
            "gdm.service",
            "lightdm.service",
            "sddm.service",
            "docker.service",
            "containerd.service",
            "libvirtd.service",
            "named.service",
            "httpd.service",
            "nginx.service",
            "apache2.service",
            "mariadb.service",
            "mysql.service",
            "postgresql.service",
            "redis.service",
            "mongodb.service",
            "smb.service",
            "nfs-server.service",
            "chronyd.service",
            "ntpd.service",
            "systemd-resolved.service",
            "polkit.service",
            "dbus.service",
        ];

        let mut services = Vec::new();
        
        for service_name in security_services {
            if let Ok(info) = self.get_service_info(service_name) {
                services.push(info);
            }
        }

        // Sort by state (running first) then by name
        services.sort_by(|a, b| {
            let state_order = |s: &ServiceState| match s {
                ServiceState::Running => 0,
                ServiceState::Failed => 1,
                ServiceState::Stopped => 2,
                ServiceState::Unknown => 3,
            };
            state_order(&a.state).cmp(&state_order(&b.state))
                .then(a.display_name.cmp(&b.display_name))
        });

        Ok(services)
    }

    /// Get information about a specific service.
    pub fn get_service_info(&self, name: &str) -> Result<ServiceInfo> {
        let conn = self.connection.as_ref()
            .ok_or_else(|| anyhow!("Not connected to systemd"))?;

        // Get unit path
        let unit_path: OwnedObjectPath = conn
            .call_method(
                Some(SYSTEMD_BUS),
                SYSTEMD_PATH,
                Some(MANAGER_INTERFACE),
                "GetUnit",
                &(name,),
            )
            .or_else(|_| {
                // Try LoadUnit if GetUnit fails (unit not loaded)
                conn.call_method(
                    Some(SYSTEMD_BUS),
                    SYSTEMD_PATH,
                    Some(MANAGER_INTERFACE),
                    "LoadUnit",
                    &(name,),
                )
            })?
            .body()
            .deserialize()?;

        let mut info = ServiceInfo::new(name);
        info.unit_path = unit_path.to_string();

        // Get description
        if let Ok(desc) = self.get_unit_property(&unit_path, "Description") {
            info.description = desc;
        }

        // Get active state (SubState is more specific: running, exited, dead, failed)
        if let Ok(sub_state) = self.get_unit_property(&unit_path, "SubState") {
            info.state = ServiceState::from_str(&sub_state);
        }

        // Get enabled state
        if let Ok(unit_file_state) = self.get_unit_property(&unit_path, "UnitFileState") {
            info.is_enabled = unit_file_state == "enabled" || unit_file_state == "static";
        }

        // Get MainPID (only for running services)
        if info.state == ServiceState::Running {
            if let Ok(pid) = self.get_unit_property_u32(&unit_path, "MainPID") {
                info.main_pid = pid;
            }
            
            // Get MemoryCurrent
            if let Ok(mem) = self.get_unit_property_u64(&unit_path, "MemoryCurrent") {
                // u64::MAX means not available
                if mem != u64::MAX {
                    info.memory_current = Some(mem);
                }
            }
        }

        Ok(info)
    }

    /// Get a property from a unit.
    fn get_unit_property(&self, unit_path: &OwnedObjectPath, property: &str) -> Result<String> {
        let conn = self.connection.as_ref()
            .ok_or_else(|| anyhow!("Not connected to systemd"))?;

        let value: zbus::zvariant::OwnedValue = conn
            .call_method(
                Some(SYSTEMD_BUS),
                unit_path.as_ref(),
                Some("org.freedesktop.DBus.Properties"),
                "Get",
                &(UNIT_INTERFACE, property),
            )?
            .body()
            .deserialize()?;

        // Try to extract string value from the variant
        let s: String = value.try_into()
            .map_err(|_| anyhow!("Property is not a string"))?;
        Ok(s)
    }

    /// Get a u32 property from a unit (for MainPID).
    fn get_unit_property_u32(&self, unit_path: &OwnedObjectPath, property: &str) -> Result<u32> {
        let conn = self.connection.as_ref()
            .ok_or_else(|| anyhow!("Not connected to systemd"))?;

        let value: zbus::zvariant::OwnedValue = conn
            .call_method(
                Some(SYSTEMD_BUS),
                unit_path.as_ref(),
                Some("org.freedesktop.DBus.Properties"),
                "Get",
                &("org.freedesktop.systemd1.Service", property),
            )?
            .body()
            .deserialize()?;

        let v: u32 = value.try_into()
            .map_err(|_| anyhow!("Property is not a u32"))?;
        Ok(v)
    }

    /// Get a u64 property from a unit (for MemoryCurrent).
    fn get_unit_property_u64(&self, unit_path: &OwnedObjectPath, property: &str) -> Result<u64> {
        let conn = self.connection.as_ref()
            .ok_or_else(|| anyhow!("Not connected to systemd"))?;

        let value: zbus::zvariant::OwnedValue = conn
            .call_method(
                Some(SYSTEMD_BUS),
                unit_path.as_ref(),
                Some("org.freedesktop.DBus.Properties"),
                "Get",
                &("org.freedesktop.systemd1.Service", property),
            )?
            .body()
            .deserialize()?;

        let v: u64 = value.try_into()
            .map_err(|_| anyhow!("Property is not a u64"))?;
        Ok(v)
    }

    /// Start a service (uses pkexec for authentication).
    pub fn start_service(&self, name: &str) -> Result<()> {
        run_systemctl_command("start", name)?;
        info!("Started service: {}", name);
        Ok(())
    }

    /// Stop a service (uses pkexec for authentication).
    pub fn stop_service(&self, name: &str) -> Result<()> {
        run_systemctl_command("stop", name)?;
        info!("Stopped service: {}", name);
        Ok(())
    }

    /// Restart a service (uses pkexec for authentication).
    pub fn restart_service(&self, name: &str) -> Result<()> {
        run_systemctl_command("restart", name)?;
        info!("Restarted service: {}", name);
        Ok(())
    }

    /// Enable a service (start on boot, uses pkexec for authentication).
    pub fn enable_service(&self, name: &str) -> Result<()> {
        run_systemctl_command("enable", name)?;
        info!("Enabled service: {}", name);
        Ok(())
    }

    /// Disable a service (don't start on boot, uses pkexec for authentication).
    pub fn disable_service(&self, name: &str) -> Result<()> {
        run_systemctl_command("disable", name)?;
        info!("Disabled service: {}", name);
        Ok(())
    }
}

/// Run a systemctl command with pkexec for authentication.
fn run_systemctl_command(action: &str, service: &str) -> Result<()> {
    let output = std::process::Command::new("pkexec")
        .args(["systemctl", action, service])
        .output()
        .context(format!("Failed to execute pkexec systemctl {} {}", action, service))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Check if user cancelled the authentication dialog
        if stderr.contains("dismissed") || stderr.contains("cancelled") || output.status.code() == Some(126) {
            return Err(anyhow!("Authentication cancelled"));
        }
        return Err(anyhow!("Failed to {} service {}: {}", action, service, stderr));
    }

    Ok(())
}

impl Default for SystemdClient {
    fn default() -> Self {
        Self::new()
    }
}
