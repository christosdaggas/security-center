// Security Center - D-Bus Client
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: MIT

//! Firewalld D-Bus client implementation.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use anyhow::{anyhow, Context, Result};
use tokio::sync::broadcast;
use tracing::{info, warn};
use zbus::blocking::{Connection, Proxy};
use zbus::proxy::MethodFlags;
use zbus::zvariant::{ObjectPath, OwnedObjectPath};

use super::{interfaces, paths, zone_description, BUS_NAME};
use crate::models::{Interface, Service, Zone};
use crate::validation::validate_zone_name;

/// Events emitted by the firewall client.
#[derive(Debug, Clone)]
pub enum FirewallEvent {
    Connected,
    Disconnected,
    StateChanged,
    Error(String),
}

/// Outcome of the permanent-config half of a firewall change.
///
/// The runtime half is reported through `Result`: an `Err` means the change
/// did not happen at all. This enum tells the caller whether the change will
/// also survive a reboot, so the UI can stop claiming success when it won't.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PermanentOutcome {
    /// The caller did not ask for a permanent change.
    NotRequested,
    /// The permanent configuration was updated (or already matched).
    Applied,
    /// The runtime change went through but the permanent write failed.
    Failed(String),
}

impl PermanentOutcome {
    /// True when a requested permanent change did not stick.
    pub fn failed(&self) -> bool {
        matches!(self, PermanentOutcome::Failed(_))
    }
}

/// Client for interacting with firewalld via D-Bus.
pub struct FirewallClient {
    connection: Option<Connection>,
    zones: Arc<RwLock<Vec<Zone>>>,
    services: Arc<RwLock<Vec<Service>>>,
    event_sender: broadcast::Sender<FirewallEvent>,
}

impl FirewallClient {
    /// Create a new firewall client.
    pub fn new() -> Self {
        let (event_sender, _) = broadcast::channel(32);
        Self {
            connection: None,
            zones: Arc::new(RwLock::new(Vec::new())),
            services: Arc::new(RwLock::new(Vec::new())),
            event_sender,
        }
    }

    /// Subscribe to firewall events.
    pub fn subscribe(&self) -> broadcast::Receiver<FirewallEvent> {
        self.event_sender.subscribe()
    }

    /// Connect to firewalld.
    pub fn connect(&mut self) -> Result<()> {
        info!("Connecting to firewalld...");

        let conn = Connection::system().context("Failed to connect to system D-Bus")?;

        // Test connection by getting the default zone
        let _: String = conn
            .call_method(
                Some(BUS_NAME),
                paths::ROOT,
                Some(interfaces::MAIN),
                "getDefaultZone",
                &(),
            )?
            .body()
            .deserialize()?;

        self.connection = Some(conn);
        let _ = self.event_sender.send(FirewallEvent::Connected);

        info!("Connected to firewalld");
        Ok(())
    }

    /// Check if connected to firewalld.
    pub fn is_connected(&self) -> bool {
        self.connection.is_some()
    }

    /// Call a firewalld method allowing polkit to prompt interactively.
    ///
    /// Without the ALLOW_INTERACTIVE_AUTHORIZATION flag, systems whose polkit
    /// policy requires authentication fail with a bare AccessDenied instead
    /// of showing an authentication dialog.
    fn call_interactive<B, R>(
        &self,
        path: ObjectPath<'_>,
        interface: &str,
        method: &str,
        body: &B,
    ) -> Result<Option<R>>
    where
        B: serde::ser::Serialize + zbus::zvariant::DynamicType,
        R: for<'d> zbus::zvariant::DynamicDeserialize<'d>,
    {
        let conn = self
            .connection
            .as_ref()
            .ok_or_else(|| anyhow!("Not connected to firewalld"))?;

        let proxy = Proxy::new(conn, BUS_NAME, path, interface)
            .context("Failed to create firewalld proxy")?;

        proxy
            .call_with_flags(method, MethodFlags::AllowInteractiveAuth.into(), body)
            .map_err(|e| anyhow!(friendly_dbus_error(&e)))
    }

    /// Get the default zone name.
    pub fn get_default_zone(&self) -> Result<String> {
        let conn = self
            .connection
            .as_ref()
            .ok_or_else(|| anyhow!("Not connected to firewalld"))?;

        let zone: String = conn
            .call_method(
                Some(BUS_NAME),
                paths::ROOT,
                Some(interfaces::MAIN),
                "getDefaultZone",
                &(),
            )?
            .body()
            .deserialize()?;

        Ok(zone)
    }

    /// Set the default zone.
    pub fn set_default_zone(&self, zone: &str) -> Result<()> {
        validate_zone_name(zone).ok_or_else(|| anyhow!("Invalid zone name: {}", zone))?;
        let _: Option<()> = self.call_interactive(
            ObjectPath::try_from(paths::ROOT)?,
            interfaces::MAIN,
            "setDefaultZone",
            &(zone,),
        )?;

        info!("Set default zone to: {}", zone);
        let _ = self.event_sender.send(FirewallEvent::StateChanged);
        Ok(())
    }

    /// Get all zones.
    pub fn get_zones(&mut self) -> Result<Vec<Zone>> {
        let conn = self
            .connection
            .as_ref()
            .ok_or_else(|| anyhow!("Not connected to firewalld"))?;

        // Get zone names
        let zone_names: Vec<String> = conn
            .call_method(
                Some(BUS_NAME),
                paths::ROOT,
                Some(interfaces::ZONE),
                "getZones",
                &(),
            )?
            .body()
            .deserialize()?;

        // Get active zones
        let active_zones: HashMap<String, HashMap<String, Vec<String>>> = conn
            .call_method(
                Some(BUS_NAME),
                paths::ROOT,
                Some(interfaces::ZONE),
                "getActiveZones",
                &(),
            )?
            .body()
            .deserialize()?;

        // Get default zone
        let default_zone = self.get_default_zone()?;

        let mut zones = Vec::new();

        for name in zone_names {
            let mut zone = Zone::new(&name);
            zone.description = zone_description(&name).to_string();
            zone.is_active = active_zones.contains_key(&name);
            zone.is_default = name == default_zone;

            // Get zone services
            if let Ok(services) = self.get_zone_services(&name) {
                zone.services = services;
            }

            // Get zone ports
            if let Ok(ports) = self.get_zone_ports(&name) {
                zone.ports = ports;
            }

            // Get zone rich rules
            if let Ok(rules) = self.get_zone_rich_rules(&name) {
                zone.rich_rules = rules;
            }

            // Get zone interfaces from active zones
            if let Some(info) = active_zones.get(&name) {
                if let Some(ifaces) = info.get("interfaces") {
                    zone.interfaces = ifaces.clone();
                }
            }

            zones.push(zone);
        }

        // Cache zones
        if let Ok(mut cached) = self.zones.write() {
            *cached = zones.clone();
        }

        Ok(zones)
    }

    /// Get services enabled in a zone.
    fn get_zone_services(&self, zone: &str) -> Result<Vec<String>> {
        let conn = self
            .connection
            .as_ref()
            .ok_or_else(|| anyhow!("Not connected to firewalld"))?;

        let services: Vec<String> = conn
            .call_method(
                Some(BUS_NAME),
                paths::ROOT,
                Some(interfaces::ZONE),
                "getServices",
                &(zone,),
            )?
            .body()
            .deserialize()?;

        Ok(services)
    }

    /// Get ports enabled in a zone.
    fn get_zone_ports(&self, zone: &str) -> Result<Vec<String>> {
        let conn = self
            .connection
            .as_ref()
            .ok_or_else(|| anyhow!("Not connected to firewalld"))?;

        // firewalld returns aas (array of array of strings) not a(ss)
        // Each inner array is [port, protocol] like ["80", "tcp"]
        let ports: Vec<Vec<String>> = conn
            .call_method(
                Some(BUS_NAME),
                paths::ROOT,
                Some(interfaces::ZONE),
                "getPorts",
                &(zone,),
            )?
            .body()
            .deserialize()?;

        // Convert from [[port, proto], ...] to ["port/proto", ...]
        Ok(ports
            .into_iter()
            .filter_map(|arr| {
                if arr.len() >= 2 {
                    Some(format!("{}/{}", arr[0], arr[1]))
                } else {
                    None
                }
            })
            .collect())
    }

    /// Get rich rules for a zone.
    pub fn get_zone_rich_rules(&self, zone: &str) -> Result<Vec<String>> {
        let conn = self
            .connection
            .as_ref()
            .ok_or_else(|| anyhow!("Not connected to firewalld"))?;

        let rules: Vec<String> = conn
            .call_method(
                Some(BUS_NAME),
                paths::ROOT,
                Some(interfaces::ZONE),
                "getRichRules",
                &(zone,),
            )?
            .body()
            .deserialize()?;

        Ok(rules)
    }

    /// Get all available services.
    pub fn get_services(&mut self) -> Result<Vec<Service>> {
        let conn = self
            .connection
            .as_ref()
            .ok_or_else(|| anyhow!("Not connected to firewalld"))?;

        // Get all service names (this is on the main interface)
        let service_names: Vec<String> = conn
            .call_method(
                Some(BUS_NAME),
                paths::ROOT,
                Some(interfaces::MAIN),
                "listServices",
                &(),
            )?
            .body()
            .deserialize()?;

        // Get default zone's enabled services
        let default_zone = self.get_default_zone()?;
        let enabled: Vec<String> = self.get_zone_services(&default_zone)?;

        let mut services = Vec::new();

        for name in service_names {
            let mut service = Service::new(&name);
            service.is_enabled = enabled.contains(&name);
            services.push(service);
        }

        // Cache services
        if let Ok(mut cached) = self.services.write() {
            *cached = services.clone();
        }

        Ok(services)
    }

    /// Add a port to a zone. Runtime failure is an `Err`; the returned
    /// outcome reports whether the permanent half also succeeded.
    pub fn add_port(
        &self,
        zone: &str,
        port: &str,
        protocol: &str,
        permanent: bool,
    ) -> Result<PermanentOutcome> {
        validate_zone_name(zone).ok_or_else(|| anyhow!("Invalid zone name: {}", zone))?;
        info!(
            "add_port called: zone={}, port={}, protocol={}, permanent={}",
            zone, port, protocol, permanent
        );

        // Add to runtime config
        let result: Result<Option<String>> = self.call_interactive(
            ObjectPath::try_from(paths::ROOT)?,
            interfaces::ZONE,
            "addPort",
            &(zone, port, protocol, 0i32),
        );

        match result {
            Ok(_) => info!(
                "Added port {}/{} to zone {} (runtime)",
                port, protocol, zone
            ),
            Err(e) if e.to_string().contains("ALREADY_ENABLED") => {
                info!(
                    "Port {}/{} already enabled in zone {}",
                    port, protocol, zone
                );
            }
            Err(e) => return Err(e),
        }

        let outcome = if permanent {
            self.apply_permanent(zone, "addPort", &(port, protocol))
        } else {
            PermanentOutcome::NotRequested
        };

        let _ = self.event_sender.send(FirewallEvent::StateChanged);
        Ok(outcome)
    }

    /// Remove a port from a zone. Runtime failure is an `Err` unless the
    /// port was already gone; the outcome reports the permanent half.
    pub fn remove_port(
        &self,
        zone: &str,
        port: &str,
        protocol: &str,
        permanent: bool,
    ) -> Result<PermanentOutcome> {
        validate_zone_name(zone).ok_or_else(|| anyhow!("Invalid zone name: {}", zone))?;
        // Remove from runtime
        let result: Result<Option<String>> = self.call_interactive(
            ObjectPath::try_from(paths::ROOT)?,
            interfaces::ZONE,
            "removePort",
            &(zone, port, protocol),
        );

        match result {
            Ok(_) => info!(
                "Removed port {}/{} from zone {} (runtime)",
                port, protocol, zone
            ),
            Err(e) if e.to_string().contains("NOT_ENABLED") => {}
            Err(e) => return Err(e),
        }

        let outcome = if permanent {
            self.apply_permanent(zone, "removePort", &(port, protocol))
        } else {
            PermanentOutcome::NotRequested
        };

        let _ = self.event_sender.send(FirewallEvent::StateChanged);
        Ok(outcome)
    }

    /// Apply a change to a zone's permanent configuration, reporting the
    /// outcome instead of silently swallowing failures.
    fn apply_permanent<B>(&self, zone: &str, method: &str, body: &B) -> PermanentOutcome
    where
        B: serde::ser::Serialize + zbus::zvariant::DynamicType,
    {
        let config_path = match self.get_zone_config_path(zone) {
            Ok(path) => path,
            Err(e) => {
                warn!("No permanent config path for zone {}: {}", zone, e);
                return PermanentOutcome::Failed(format!("zone lookup failed: {}", e));
            }
        };

        let path = match ObjectPath::try_from(config_path.as_str()) {
            Ok(path) => path,
            Err(e) => return PermanentOutcome::Failed(e.to_string()),
        };

        let result: Result<Option<()>> =
            self.call_interactive(path, interfaces::CONFIG_ZONE, method, body);

        match result {
            Ok(_) => PermanentOutcome::Applied,
            // Already matching permanent config counts as applied
            Err(e)
                if e.to_string().contains("ALREADY_ENABLED")
                    || e.to_string().contains("NOT_ENABLED") =>
            {
                PermanentOutcome::Applied
            }
            Err(e) => {
                warn!("Permanent {} failed for zone {}: {}", method, zone, e);
                PermanentOutcome::Failed(e.to_string())
            }
        }
    }

    /// Enable a service in a zone.
    pub fn enable_service(
        &self,
        zone: &str,
        service: &str,
        permanent: bool,
    ) -> Result<PermanentOutcome> {
        validate_zone_name(zone).ok_or_else(|| anyhow!("Invalid zone name: {}", zone))?;
        let result: Result<Option<String>> = self.call_interactive(
            ObjectPath::try_from(paths::ROOT)?,
            interfaces::ZONE,
            "addService",
            &(zone, service, 0i32),
        );

        match result {
            Ok(_) => info!("Enabled service {} in zone {} (runtime)", service, zone),
            Err(e) if e.to_string().contains("ALREADY_ENABLED") => {}
            Err(e) => return Err(e),
        }

        let outcome = if permanent {
            self.apply_permanent(zone, "addService", &(service,))
        } else {
            PermanentOutcome::NotRequested
        };

        let _ = self.event_sender.send(FirewallEvent::StateChanged);
        Ok(outcome)
    }

    /// Disable a service in a zone.
    pub fn disable_service(
        &self,
        zone: &str,
        service: &str,
        permanent: bool,
    ) -> Result<PermanentOutcome> {
        validate_zone_name(zone).ok_or_else(|| anyhow!("Invalid zone name: {}", zone))?;
        let result: Result<Option<String>> = self.call_interactive(
            ObjectPath::try_from(paths::ROOT)?,
            interfaces::ZONE,
            "removeService",
            &(zone, service),
        );

        match result {
            Ok(_) => info!("Disabled service {} in zone {} (runtime)", service, zone),
            Err(e) if e.to_string().contains("NOT_ENABLED") => {}
            Err(e) => return Err(e),
        }

        let outcome = if permanent {
            self.apply_permanent(zone, "removeService", &(service,))
        } else {
            PermanentOutcome::NotRequested
        };

        let _ = self.event_sender.send(FirewallEvent::StateChanged);
        Ok(outcome)
    }

    /// Add a rich rule to a zone.
    pub fn add_rich_rule(
        &self,
        zone: &str,
        rule: &str,
        permanent: bool,
    ) -> Result<PermanentOutcome> {
        validate_zone_name(zone).ok_or_else(|| anyhow!("Invalid zone name: {}", zone))?;
        let result: Result<Option<String>> = self.call_interactive(
            ObjectPath::try_from(paths::ROOT)?,
            interfaces::ZONE,
            "addRichRule",
            &(zone, rule, 0i32),
        );

        match result {
            Ok(_) => info!("Added rich rule to zone {}: {}", zone, rule),
            Err(e) if e.to_string().contains("ALREADY_ENABLED") => {}
            Err(e) => return Err(e),
        }

        let outcome = if permanent {
            self.apply_permanent(zone, "addRichRule", &(rule,))
        } else {
            PermanentOutcome::NotRequested
        };

        let _ = self.event_sender.send(FirewallEvent::StateChanged);
        Ok(outcome)
    }

    /// Remove a rich rule from a zone.
    pub fn remove_rich_rule(
        &self,
        zone: &str,
        rule: &str,
        permanent: bool,
    ) -> Result<PermanentOutcome> {
        validate_zone_name(zone).ok_or_else(|| anyhow!("Invalid zone name: {}", zone))?;
        let result: Result<Option<String>> = self.call_interactive(
            ObjectPath::try_from(paths::ROOT)?,
            interfaces::ZONE,
            "removeRichRule",
            &(zone, rule),
        );

        match result {
            Ok(_) => info!("Removed rich rule from zone {}: {}", zone, rule),
            Err(e) if e.to_string().contains("NOT_ENABLED") => {}
            Err(e) => return Err(e),
        }

        let outcome = if permanent {
            self.apply_permanent(zone, "removeRichRule", &(rule,))
        } else {
            PermanentOutcome::NotRequested
        };

        let _ = self.event_sender.send(FirewallEvent::StateChanged);
        Ok(outcome)
    }

    /// Get the D-Bus path for a zone's permanent config.
    fn get_zone_config_path(&self, zone_name: &str) -> Result<String> {
        let conn = self
            .connection
            .as_ref()
            .ok_or_else(|| anyhow!("Not connected to firewalld"))?;

        let path: OwnedObjectPath = conn
            .call_method(
                Some(BUS_NAME),
                paths::CONFIG,
                Some(interfaces::CONFIG),
                "getZoneByName",
                &(zone_name,),
            )?
            .body()
            .deserialize()?;

        Ok(path.to_string())
    }

    /// Get network interfaces.
    pub fn get_interfaces(&self) -> Result<Vec<Interface>> {
        let conn = self
            .connection
            .as_ref()
            .ok_or_else(|| anyhow!("Not connected to firewalld"))?;

        // Get active zones which contain interface info
        let active_zones: HashMap<String, HashMap<String, Vec<String>>> = conn
            .call_method(
                Some(BUS_NAME),
                paths::ROOT,
                Some(interfaces::ZONE),
                "getActiveZones",
                &(),
            )?
            .body()
            .deserialize()?;

        let mut interfaces = Vec::new();

        for (zone_name, info) in active_zones {
            if let Some(iface_names) = info.get("interfaces") {
                for name in iface_names {
                    let mut iface = Interface::new(name);
                    iface.zone = zone_name.clone();
                    iface.is_active = true;
                    interfaces.push(iface);
                }
            }
        }

        Ok(interfaces)
    }

    /// Reload firewalld configuration.
    pub fn reload(&self) -> Result<()> {
        let _: Option<()> = self.call_interactive(
            ObjectPath::try_from(paths::ROOT)?,
            interfaces::MAIN,
            "reload",
            &(),
        )?;

        info!("Firewalld configuration reloaded");
        let _ = self.event_sender.send(FirewallEvent::StateChanged);
        Ok(())
    }

    /// Enable panic mode - blocks all traffic.
    pub fn enable_panic_mode(&self) -> Result<()> {
        let _: Option<()> = self.call_interactive(
            ObjectPath::try_from(paths::ROOT)?,
            interfaces::MAIN,
            "enablePanicMode",
            &(),
        )?;

        info!("Panic mode enabled - all traffic blocked");
        let _ = self.event_sender.send(FirewallEvent::StateChanged);
        Ok(())
    }

    /// Disable panic mode - restore normal operation.
    pub fn disable_panic_mode(&self) -> Result<()> {
        let _: Option<()> = self.call_interactive(
            ObjectPath::try_from(paths::ROOT)?,
            interfaces::MAIN,
            "disablePanicMode",
            &(),
        )?;

        info!("Panic mode disabled - normal operation restored");
        let _ = self.event_sender.send(FirewallEvent::StateChanged);
        Ok(())
    }

    /// Query if panic mode is enabled.
    pub fn query_panic_mode(&self) -> Result<bool> {
        let conn = self
            .connection
            .as_ref()
            .ok_or_else(|| anyhow!("Not connected to firewalld"))?;

        let enabled: bool = conn
            .call_method(
                Some(BUS_NAME),
                paths::ROOT,
                Some(interfaces::MAIN),
                "queryPanicMode",
                &(),
            )?
            .body()
            .deserialize()?;

        Ok(enabled)
    }
}

impl Default for FirewallClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Map raw D-Bus/polkit errors to messages a user can act on.
fn friendly_dbus_error(e: &zbus::Error) -> String {
    let text = e.to_string();
    if text.contains("AccessDenied") || text.contains("NotAuthorized") {
        format!("Authorization denied: {}", text)
    } else if text.contains("InteractiveAuthorizationRequired") {
        format!("Administrator authentication required: {}", text)
    } else {
        text
    }
}
