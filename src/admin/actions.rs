// Security Center - Quick Admin Actions
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: MIT

//! Coordinated administrative actions using D-Bus.
//!
//! This module provides a unified interface for common administrative
//! operations, coordinating between systemd and firewalld.
//!
//! # Design Principles
//!
//! - All actions are explicit and user-triggered
//! - Each action has a clear description
//! - Polkit authorization is handled by the D-Bus services
//! - No automatic or background execution

use anyhow::{anyhow, Context, Result};
use tracing::info;
use zbus::blocking::{Connection, Proxy};
use zbus::proxy::MethodFlags;

use crate::systemd::SystemdClient;

/// D-Bus constants for firewalld
const FIREWALLD_BUS: &str = "org.fedoraproject.FirewallD1";
const FIREWALLD_PATH: &str = "/org/fedoraproject/FirewallD1";
const FIREWALLD_INTERFACE: &str = "org.fedoraproject.FirewallD1";

/// An administrative action that can be performed.
#[derive(Debug, Clone)]
pub struct AdminAction {
    /// Unique identifier for this action
    pub id: &'static str,
    /// Human-readable title
    pub title: &'static str,
    /// Detailed description of what this action does
    pub description: &'static str,
    /// Icon name for UI display
    pub icon: &'static str,
    /// Whether this action is potentially destructive
    pub destructive: bool,
    /// Category for grouping
    pub category: ActionCategory,
}

/// Category of admin action for UI grouping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionCategory {
    Firewall,
    Network,
    Services,
}

/// Result of an admin action execution.
#[derive(Debug)]
pub struct AdminActionResult {
    pub success: bool,
    pub message: String,
}

impl AdminActionResult {
    pub fn success(message: impl Into<String>) -> Self {
        Self {
            success: true,
            message: message.into(),
        }
    }

    pub fn failure(message: impl Into<String>) -> Self {
        Self {
            success: false,
            message: message.into(),
        }
    }
}

/// All available quick admin actions.
pub const QUICK_ACTIONS: &[AdminAction] = &[
    // Firewall actions
    AdminAction {
        id: "firewall_reload",
        title: "Reload Firewall",
        description: "Reload firewall rules from permanent configuration. Active connections are preserved.",
        icon: "view-refresh-symbolic",
        destructive: false,
        category: ActionCategory::Firewall,
    },
    AdminAction {
        id: "firewall_enable",
        title: "Enable Firewall",
        description: "Start the firewall service and enable it to start at boot.",
        icon: "security-high-symbolic",
        destructive: false,
        category: ActionCategory::Firewall,
    },
    AdminAction {
        id: "firewall_disable",
        title: "Disable Firewall",
        description: "Stop the firewall service and disable it at boot. WARNING: This will leave your system unprotected.",
        icon: "security-low-symbolic",
        destructive: true,
        category: ActionCategory::Firewall,
    },
    AdminAction {
        id: "firewall_panic_on",
        title: "Enable Panic Mode",
        description: "Block ALL network traffic immediately. Use for emergency lockdown.",
        icon: "dialog-error-symbolic",
        destructive: true,
        category: ActionCategory::Firewall,
    },
    AdminAction {
        id: "firewall_panic_off",
        title: "Disable Panic Mode",
        description: "Restore normal firewall operation after panic mode.",
        icon: "security-high-symbolic",
        destructive: false,
        category: ActionCategory::Firewall,
    },
    AdminAction {
        id: "firewall_runtime_to_permanent",
        title: "Save Runtime to Permanent",
        description: "Copy all runtime firewall rules to permanent configuration.",
        icon: "document-save-symbolic",
        destructive: false,
        category: ActionCategory::Firewall,
    },
    AdminAction {
        id: "firewall_flush_runtime",
        title: "Flush Runtime Rules",
        description: "Remove all runtime firewall rules and reload permanent configuration.",
        icon: "edit-clear-all-symbolic",
        destructive: true,
        category: ActionCategory::Firewall,
    },

    // Network actions
    AdminAction {
        id: "restart_networkmanager",
        title: "Restart NetworkManager",
        description: "Restart the NetworkManager service. This will briefly disconnect all network connections.",
        icon: "network-wired-symbolic",
        destructive: false,
        category: ActionCategory::Network,
    },

    // Service actions
    AdminAction {
        id: "restart_sshd",
        title: "Restart SSH Server",
        description: "Restart the SSH daemon. Existing connections will be preserved.",
        icon: "utilities-terminal-symbolic",
        destructive: false,
        category: ActionCategory::Services,
    },
    AdminAction {
        id: "reload_systemd",
        title: "Reload Systemd",
        description: "Reload systemd daemon configuration. Safe operation.",
        icon: "system-run-symbolic",
        destructive: false,
        category: ActionCategory::Services,
    },
];

/// Manager for executing quick admin actions.
pub struct QuickActionsManager {
    connection: Option<Connection>,
    systemd: Option<SystemdClient>,
}

impl Default for QuickActionsManager {
    fn default() -> Self {
        Self::new()
    }
}

impl QuickActionsManager {
    pub fn new() -> Self {
        Self {
            connection: None,
            systemd: None,
        }
    }

    /// Ensure we're connected to D-Bus.
    fn ensure_connected(&mut self) -> Result<&Connection> {
        if self.connection.is_none() {
            let conn = Connection::system().context("Failed to connect to system D-Bus")?;
            self.connection = Some(conn);
        }
        self.connection
            .as_ref()
            .ok_or_else(|| anyhow!("Not connected"))
    }

    /// Get a connected systemd client, connecting lazily on first use.
    fn systemd_client(&mut self) -> Result<&SystemdClient> {
        if self.systemd.is_none() {
            let mut client = SystemdClient::new();
            client.connect()?;
            self.systemd = Some(client);
        }
        self.systemd
            .as_ref()
            .ok_or_else(|| anyhow!("Not connected to systemd"))
    }

    /// Run a privileged systemd unit action (delegates to `SystemdClient`,
    /// which validates parameters and uses polkit interactive authorization).
    fn systemctl(&mut self, action: &str, service: &str) -> Result<()> {
        self.systemd_client()?.run_unit_action(action, service)
    }

    /// Execute an admin action by ID.
    pub fn execute(&mut self, action_id: &str) -> AdminActionResult {
        let result = match action_id {
            "firewall_reload" => self.firewall_reload(),
            "firewall_enable" => self.firewall_enable(),
            "firewall_disable" => self.firewall_disable(),
            "firewall_panic_on" => self.firewall_panic_on(),
            "firewall_panic_off" => self.firewall_panic_off(),
            "firewall_runtime_to_permanent" => self.firewall_runtime_to_permanent(),
            "firewall_flush_runtime" => self.firewall_flush_runtime(),
            "restart_networkmanager" => self.restart_service("NetworkManager.service"),
            "restart_sshd" => self.restart_ssh(),
            "reload_systemd" => self.reload_systemd(),
            _ => Err(anyhow!("Unknown action: {}", action_id)),
        };

        match result {
            Ok(msg) => {
                info!("Action {} completed successfully", action_id);
                AdminActionResult::success(msg)
            }
            Err(e) => {
                info!("Action {} failed: {}", action_id, e);
                AdminActionResult::failure(format!("{:#}", e))
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // FIREWALL ACTIONS
    // ═══════════════════════════════════════════════════════════════════════════

    /// Call a firewalld method with interactive polkit authorization so the
    /// desktop prompts for credentials instead of failing with AccessDenied.
    fn call_firewalld(&self, method: &str) -> Result<()> {
        let conn = self
            .connection
            .as_ref()
            .ok_or_else(|| anyhow!("Not connected"))?;
        let proxy = Proxy::new(conn, FIREWALLD_BUS, FIREWALLD_PATH, FIREWALLD_INTERFACE)
            .context("Failed to create firewalld proxy")?;
        let _: Option<()> = proxy
            .call_with_flags(method, MethodFlags::AllowInteractiveAuth.into(), &())
            .map_err(|e| anyhow!("{:#}", e))
            .context(format!("Failed to {} firewall", method))?;
        Ok(())
    }

    fn firewall_reload(&mut self) -> Result<String> {
        self.ensure_connected()?;
        self.call_firewalld("reload")?;

        Ok("Firewall reloaded successfully".to_string())
    }

    fn firewall_enable(&mut self) -> Result<String> {
        // Start the service, then enable at boot. Report which half failed so
        // a partial state is never presented as generic success/failure.
        if let Err(e) = self.systemctl("start", "firewalld.service") {
            return Err(anyhow!("Failed to start firewalld: {:#}", e));
        }
        if let Err(e) = self.systemctl("enable", "firewalld.service") {
            return Err(anyhow!(
                "Firewall started but failed to enable at boot: {:#}",
                e
            ));
        }

        Ok("Firewall enabled and started".to_string())
    }

    fn firewall_disable(&mut self) -> Result<String> {
        if let Err(e) = self.systemctl("stop", "firewalld.service") {
            return Err(anyhow!("Failed to stop firewalld: {:#}", e));
        }
        if let Err(e) = self.systemctl("disable", "firewalld.service") {
            return Err(anyhow!(
                "Firewall stopped but failed to disable at boot: {:#}",
                e
            ));
        }

        Ok("Firewall stopped and disabled".to_string())
    }

    fn firewall_panic_on(&mut self) -> Result<String> {
        self.ensure_connected()?;
        self.call_firewalld("enablePanicMode")?;

        Ok("Panic mode enabled - all traffic blocked".to_string())
    }

    fn firewall_panic_off(&mut self) -> Result<String> {
        self.ensure_connected()?;
        self.call_firewalld("disablePanicMode")?;

        Ok("Panic mode disabled - normal operation restored".to_string())
    }

    fn firewall_runtime_to_permanent(&mut self) -> Result<String> {
        self.ensure_connected()?;
        self.call_firewalld("runtimeToPermanent")?;

        Ok("Runtime rules saved to permanent configuration".to_string())
    }

    fn firewall_flush_runtime(&mut self) -> Result<String> {
        // Flush by reloading - this discards runtime changes
        self.firewall_reload()?;
        Ok("Runtime rules flushed, permanent rules restored".to_string())
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // SERVICE ACTIONS (via systemd D-Bus API with polkit interactive authorization)
    // ═══════════════════════════════════════════════════════════════════════════

    fn restart_service(&mut self, service: &str) -> Result<String> {
        self.systemctl("restart", service)?;
        Ok(format!("Service {} restarted", service))
    }

    fn restart_ssh(&mut self) -> Result<String> {
        // Try sshd.service first (RHEL/Fedora), then ssh.service (Debian/Ubuntu).
        // Only fall through on "unit not found" — auth cancellations and real
        // failures must propagate instead of triggering a second prompt.
        match self.systemctl("restart", "sshd.service") {
            Ok(()) => return Ok("SSH server restarted".to_string()),
            Err(e) => {
                let msg = format!("{:#}", e);
                let not_found = msg.contains("not found")
                    || msg.contains("NotFound")
                    || msg.contains("No such")
                    || msg.contains("LoadFailed");
                if !not_found {
                    return Err(e);
                }
            }
        }
        self.systemctl("restart", "ssh.service")?;
        Ok("SSH server restarted".to_string())
    }

    fn reload_systemd(&mut self) -> Result<String> {
        self.systemd_client()?.daemon_reload()?;
        Ok("Systemd configuration reloaded".to_string())
    }
}
