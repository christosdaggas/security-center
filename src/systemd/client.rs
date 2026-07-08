// Security Center - Systemd D-Bus Client
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: MIT

//! Systemd D-Bus client implementation for service management.

use anyhow::{anyhow, Context, Result};
use tracing::info;
use zbus::blocking::{Connection, Proxy};
use zbus::proxy::MethodFlags;
use zbus::zvariant::OwnedObjectPath;

use crate::validation::{validate_service_name, validate_systemctl_action};

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

    /// Start a service (polkit prompts for authorization via D-Bus).
    pub fn start_service(&self, name: &str) -> Result<()> {
        self.run_unit_action("start", name)?;
        info!("Started service: {}", name);
        Ok(())
    }

    /// Stop a service (polkit prompts for authorization via D-Bus).
    pub fn stop_service(&self, name: &str) -> Result<()> {
        self.run_unit_action("stop", name)?;
        info!("Stopped service: {}", name);
        Ok(())
    }

    /// Restart a service (polkit prompts for authorization via D-Bus).
    pub fn restart_service(&self, name: &str) -> Result<()> {
        self.run_unit_action("restart", name)?;
        info!("Restarted service: {}", name);
        Ok(())
    }

    /// Enable a service (start on boot, polkit prompts for authorization via D-Bus).
    pub fn enable_service(&self, name: &str) -> Result<()> {
        self.run_unit_action("enable", name)?;
        info!("Enabled service: {}", name);
        Ok(())
    }

    /// Disable a service (don't start on boot, polkit prompts for authorization via D-Bus).
    pub fn disable_service(&self, name: &str) -> Result<()> {
        self.run_unit_action("disable", name)?;
        info!("Disabled service: {}", name);
        Ok(())
    }

    /// Reload the systemd daemon configuration (equivalent of `systemctl daemon-reload`).
    pub fn daemon_reload(&self) -> Result<()> {
        self.run_unit_action("daemon-reload", "")?;
        info!("Reloaded systemd daemon configuration");
        Ok(())
    }

    /// Perform a privileged unit operation via the systemd Manager D-Bus API.
    ///
    /// This is the single entry point for all privileged systemd operations.
    /// Authorization is handled by polkit: every call sets the D-Bus
    /// `ALLOW_INTERACTIVE_AUTHORIZATION` flag so the polkit agent can prompt
    /// the user for credentials when needed.
    ///
    /// Supported actions: `start`, `stop`, `restart`, `enable`, `disable`,
    /// and `daemon-reload` (which ignores `unit`).
    pub fn run_unit_action(&self, action: &str, unit: &str) -> Result<()> {
        // Validate parameters before invoking privileged operations
        validate_systemctl_action(action)?;
        validate_service_name(unit)?;

        if action != "daemon-reload" && unit.is_empty() {
            return Err(anyhow!("A unit name is required for '{}'", action));
        }

        match action {
            "start" => {
                let _job: OwnedObjectPath =
                    self.call_manager_interactive("StartUnit", &(unit, "replace"))?;
            }
            "stop" => {
                let _job: OwnedObjectPath =
                    self.call_manager_interactive("StopUnit", &(unit, "replace"))?;
            }
            "restart" => {
                let _job: OwnedObjectPath =
                    self.call_manager_interactive("RestartUnit", &(unit, "replace"))?;
            }
            "enable" => {
                // EnableUnitFiles(files, runtime, force) -> (carries_install_info, changes)
                let _changes: (bool, Vec<(String, String, String)>) = self
                    .call_manager_interactive(
                        "EnableUnitFiles",
                        &(&[unit] as &[&str], false, true),
                    )?;
                // Make systemd pick up the changed unit files
                let _: () = self.call_manager_interactive("Reload", &())?;
            }
            "disable" => {
                // DisableUnitFiles(files, runtime) -> changes
                let _changes: Vec<(String, String, String)> = self
                    .call_manager_interactive("DisableUnitFiles", &(&[unit] as &[&str], false))?;
                // Make systemd pick up the changed unit files
                let _: () = self.call_manager_interactive("Reload", &())?;
            }
            "daemon-reload" => {
                let _: () = self.call_manager_interactive("Reload", &())?;
            }
            // validate_systemctl_action() only accepts the actions above
            _ => unreachable!("validated action"),
        }

        Ok(())
    }

    /// Get a proxy for the systemd Manager interface.
    fn manager_proxy(&self) -> Result<Proxy<'_>> {
        let conn = self.connection.as_ref()
            .ok_or_else(|| anyhow!("Not connected to systemd"))?;

        Proxy::new(conn, SYSTEMD_BUS, SYSTEMD_PATH, MANAGER_INTERFACE)
            .context("Failed to create systemd manager proxy")
    }

    /// Call a method on the systemd Manager interface with the
    /// `ALLOW_INTERACTIVE_AUTHORIZATION` flag set, so polkit can prompt the
    /// user for credentials if the operation requires privileges.
    fn call_manager_interactive<B, R>(&self, method: &str, body: &B) -> Result<R>
    where
        B: serde::ser::Serialize + zbus::zvariant::DynamicType,
        R: for<'d> zbus::zvariant::DynamicDeserialize<'d>,
    {
        let proxy = self.manager_proxy()?;

        let reply: Option<R> = proxy
            .call_with_flags(method, MethodFlags::AllowInteractiveAuth.into(), body)
            .map_err(|e| map_dbus_error(e, method))?;

        reply.ok_or_else(|| anyhow!("No reply received for systemd {} call", method))
    }
}

/// Map a zbus error to a user-friendly anyhow error.
fn map_dbus_error(err: zbus::Error, method: &str) -> anyhow::Error {
    if let zbus::Error::MethodError(ref name, ref detail, _) = err {
        let detail = detail.as_deref().unwrap_or("no details");
        match name.as_str() {
            "org.freedesktop.DBus.Error.InteractiveAuthorizationRequired" => {
                return anyhow!(
                    "Authorization is required for this action, but no polkit \
                     authentication agent is available to prompt for credentials ({})",
                    detail
                );
            }
            "org.freedesktop.DBus.Error.AccessDenied" => {
                return anyhow!(
                    "Access denied: authorization was not granted \
                     (the authentication dialog may have been cancelled) ({})",
                    detail
                );
            }
            _ => {}
        }
    }

    anyhow::Error::new(err).context(format!("systemd {} call failed", method))
}

impl Default for SystemdClient {
    fn default() -> Self {
        Self::new()
    }
}
