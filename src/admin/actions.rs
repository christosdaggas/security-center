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
use zbus::blocking::Connection;

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
        icon: "emblem-ok-symbolic",
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
}

impl Default for QuickActionsManager {
    fn default() -> Self {
        Self::new()
    }
}

impl QuickActionsManager {
    pub fn new() -> Self {
        Self { connection: None }
    }

    /// Ensure we're connected to D-Bus.
    fn ensure_connected(&mut self) -> Result<&Connection> {
        if self.connection.is_none() {
            let conn = Connection::system()
                .context("Failed to connect to system D-Bus")?;
            self.connection = Some(conn);
        }
        self.connection.as_ref().ok_or_else(|| anyhow!("Not connected"))
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

    fn firewall_reload(&mut self) -> Result<String> {
        let conn = self.ensure_connected()?;

        conn.call_method(
            Some(FIREWALLD_BUS),
            FIREWALLD_PATH,
            Some(FIREWALLD_INTERFACE),
            "reload",
            &(),
        ).context("Failed to reload firewall. Is firewalld running?")?;

        Ok("Firewall reloaded successfully".to_string())
    }

    fn firewall_enable(&mut self) -> Result<String> {
        // Start the service
        run_systemctl_command("start", "firewalld.service")?;
        // Enable at boot
        run_systemctl_command("enable", "firewalld.service")?;

        Ok("Firewall enabled and started".to_string())
    }

    fn firewall_disable(&mut self) -> Result<String> {
        // Stop the service
        run_systemctl_command("stop", "firewalld.service")?;
        // Disable at boot
        run_systemctl_command("disable", "firewalld.service")?;

        Ok("Firewall stopped and disabled".to_string())
    }

    fn firewall_panic_on(&mut self) -> Result<String> {
        let conn = self.ensure_connected()?;

        conn.call_method(
            Some(FIREWALLD_BUS),
            FIREWALLD_PATH,
            Some(FIREWALLD_INTERFACE),
            "enablePanicMode",
            &(),
        ).context("Failed to enable panic mode")?;

        Ok("Panic mode enabled - all traffic blocked".to_string())
    }

    fn firewall_panic_off(&mut self) -> Result<String> {
        let conn = self.ensure_connected()?;

        conn.call_method(
            Some(FIREWALLD_BUS),
            FIREWALLD_PATH,
            Some(FIREWALLD_INTERFACE),
            "disablePanicMode",
            &(),
        ).context("Failed to disable panic mode")?;

        Ok("Panic mode disabled - normal operation restored".to_string())
    }

    fn firewall_runtime_to_permanent(&mut self) -> Result<String> {
        let conn = self.ensure_connected()?;

        conn.call_method(
            Some(FIREWALLD_BUS),
            FIREWALLD_PATH,
            Some(FIREWALLD_INTERFACE),
            "runtimeToPermanent",
            &(),
        ).context("Failed to save runtime rules")?;

        Ok("Runtime rules saved to permanent configuration".to_string())
    }

    fn firewall_flush_runtime(&mut self) -> Result<String> {
        // Flush by reloading - this discards runtime changes
        self.firewall_reload()?;
        Ok("Runtime rules flushed, permanent rules restored".to_string())
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // SERVICE ACTIONS (using pkexec for Polkit authentication)
    // ═══════════════════════════════════════════════════════════════════════════

    fn restart_service(&mut self, service: &str) -> Result<String> {
        run_systemctl_command("restart", service)?;
        Ok(format!("Service {} restarted", service))
    }

    fn restart_ssh(&mut self) -> Result<String> {
        // Try sshd.service first (RHEL/Fedora), then ssh.service (Debian/Ubuntu)
        if run_systemctl_command("restart", "sshd.service").is_ok() {
            return Ok("SSH server restarted".to_string());
        }
        run_systemctl_command("restart", "ssh.service")?;
        Ok("SSH server restarted".to_string())
    }

    fn reload_systemd(&mut self) -> Result<String> {
        let output = std::process::Command::new("pkexec")
            .args(["systemctl", "daemon-reload"])
            .output()
            .context("Failed to execute pkexec systemctl daemon-reload")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("dismissed") || stderr.contains("cancelled") || output.status.code() == Some(126) {
                return Err(anyhow!("Authentication cancelled"));
            }
            return Err(anyhow!("Failed to reload systemd: {}", stderr));
        }

        Ok("Systemd configuration reloaded".to_string())
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
        if stderr.contains("dismissed") || stderr.contains("cancelled") || output.status.code() == Some(126) {
            return Err(anyhow!("Authentication cancelled"));
        }
        return Err(anyhow!("Failed to {} service {}: {}", action, service, stderr));
    }

    Ok(())
}
