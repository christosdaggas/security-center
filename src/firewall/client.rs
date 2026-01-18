// Security Center - D-Bus Client
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: MIT

//! Firewalld D-Bus client implementation.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use anyhow::{anyhow, Context, Result};
use tokio::sync::broadcast;
use tracing::info;
use zbus::blocking::Connection;
use zbus::zvariant::{ObjectPath, OwnedObjectPath};

use super::{interfaces, paths, zone_description, BUS_NAME};
use crate::models::{Interface, Service, Zone};

/// Events emitted by the firewall client.
#[derive(Debug, Clone)]
pub enum FirewallEvent {
    Connected,
    Disconnected,
    StateChanged,
    Error(String),
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

        let conn = Connection::system()
            .context("Failed to connect to system D-Bus")?;

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

    /// Get the default zone name.
    pub fn get_default_zone(&self) -> Result<String> {
        let conn = self.connection.as_ref()
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
        let conn = self.connection.as_ref()
            .ok_or_else(|| anyhow!("Not connected to firewalld"))?;

        conn.call_method(
            Some(BUS_NAME),
            paths::ROOT,
            Some(interfaces::MAIN),
            "setDefaultZone",
            &(zone,),
        )?;

        info!("Set default zone to: {}", zone);
        let _ = self.event_sender.send(FirewallEvent::StateChanged);
        Ok(())
    }

    /// Get all zones.
    pub fn get_zones(&mut self) -> Result<Vec<Zone>> {
        let conn = self.connection.as_ref()
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
        let conn = self.connection.as_ref()
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
        let conn = self.connection.as_ref()
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
        Ok(ports.into_iter()
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
        let conn = self.connection.as_ref()
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
        let conn = self.connection.as_ref()
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

    /// Add a port to a zone.
    pub fn add_port(&self, zone: &str, port: &str, protocol: &str, permanent: bool) -> Result<()> {
        info!("add_port called: zone={}, port={}, protocol={}, permanent={}", zone, port, protocol, permanent);
        
        let conn = self.connection.as_ref()
            .ok_or_else(|| anyhow!("Not connected to firewalld"))?;

        // Add to runtime config
        let result = conn.call_method(
            Some(BUS_NAME),
            paths::ROOT,
            Some(interfaces::ZONE),
            "addPort",
            &(zone, port, protocol, 0i32),
        );

        match result {
            Ok(_) => info!("Added port {}/{} to zone {} (runtime)", port, protocol, zone),
            Err(e) if e.to_string().contains("ALREADY_ENABLED") => {
                info!("Port {}/{} already enabled in zone {}", port, protocol, zone);
            },
            Err(e) => return Err(e.into()),
        }

        // Add to permanent config if requested
        if permanent {
            info!("Attempting to add port to permanent config...");
            match self.get_zone_config_path(zone) {
                Ok(config_path) => {
                    info!("Got zone config path: {}", config_path);
                    let perm_result = conn.call_method(
                        Some(BUS_NAME),
                        ObjectPath::try_from(config_path.as_str())?,
                        Some(interfaces::CONFIG_ZONE),
                        "addPort",
                        &(port, protocol),
                    );
                    match perm_result {
                        Ok(_) => info!("Added port {}/{} to zone {} (permanent)", port, protocol, zone),
                        Err(e) if e.to_string().contains("ALREADY_ENABLED") => {
                            info!("Port {}/{} already enabled in zone {} permanent config", port, protocol, zone);
                        },
                        Err(e) => {
                            info!("Failed to add port to permanent config: {}", e);
                            // Don't fail - runtime config was added successfully
                        }
                    }
                }
                Err(e) => {
                    info!("Failed to get zone config path for permanent config: {}", e);
                }
            }
        } else {
            info!("permanent=false, skipping permanent config");
        }

        let _ = self.event_sender.send(FirewallEvent::StateChanged);
        Ok(())
    }

    /// Remove a port from a zone.
    pub fn remove_port(&self, zone: &str, port: &str, protocol: &str, permanent: bool) -> Result<()> {
        let conn = self.connection.as_ref()
            .ok_or_else(|| anyhow!("Not connected to firewalld"))?;

        // Remove from runtime
        let _ = conn.call_method(
            Some(BUS_NAME),
            paths::ROOT,
            Some(interfaces::ZONE),
            "removePort",
            &(zone, port, protocol),
        );

        // Remove from permanent config
        if permanent {
            if let Ok(config_path) = self.get_zone_config_path(zone) {
                let _ = conn.call_method(
                    Some(BUS_NAME),
                    ObjectPath::try_from(config_path.as_str())?,
                    Some(interfaces::CONFIG_ZONE),
                    "removePort",
                    &(port, protocol),
                );
            }
        }

        info!("Removed port {}/{} from zone {}", port, protocol, zone);
        let _ = self.event_sender.send(FirewallEvent::StateChanged);
        Ok(())
    }

    /// Enable a service in a zone.
    pub fn enable_service(&self, zone: &str, service: &str, permanent: bool) -> Result<()> {
        let conn = self.connection.as_ref()
            .ok_or_else(|| anyhow!("Not connected to firewalld"))?;

        conn.call_method(
            Some(BUS_NAME),
            paths::ROOT,
            Some(interfaces::ZONE),
            "addService",
            &(zone, service, 0i32),
        )?;

        if permanent {
            if let Ok(config_path) = self.get_zone_config_path(zone) {
                let _ = conn.call_method(
                    Some(BUS_NAME),
                    ObjectPath::try_from(config_path.as_str())?,
                    Some(interfaces::CONFIG_ZONE),
                    "addService",
                    &(service,),
                );
            }
        }

        info!("Enabled service {} in zone {}", service, zone);
        let _ = self.event_sender.send(FirewallEvent::StateChanged);
        Ok(())
    }

    /// Disable a service in a zone.
    pub fn disable_service(&self, zone: &str, service: &str, permanent: bool) -> Result<()> {
        let conn = self.connection.as_ref()
            .ok_or_else(|| anyhow!("Not connected to firewalld"))?;

        let _ = conn.call_method(
            Some(BUS_NAME),
            paths::ROOT,
            Some(interfaces::ZONE),
            "removeService",
            &(zone, service),
        );

        if permanent {
            if let Ok(config_path) = self.get_zone_config_path(zone) {
                let _ = conn.call_method(
                    Some(BUS_NAME),
                    ObjectPath::try_from(config_path.as_str())?,
                    Some(interfaces::CONFIG_ZONE),
                    "removeService",
                    &(service,),
                );
            }
        }

        info!("Disabled service {} in zone {}", service, zone);
        let _ = self.event_sender.send(FirewallEvent::StateChanged);
        Ok(())
    }

    /// Add a rich rule to a zone.
    pub fn add_rich_rule(&self, zone: &str, rule: &str, permanent: bool) -> Result<()> {
        let conn = self.connection.as_ref()
            .ok_or_else(|| anyhow!("Not connected to firewalld"))?;

        // Add to runtime config
        let result = conn.call_method(
            Some(BUS_NAME),
            paths::ROOT,
            Some(interfaces::ZONE),
            "addRichRule",
            &(zone, rule, 0i32),
        );

        match result {
            Ok(_) => info!("Added rich rule to zone {}: {}", zone, rule),
            Err(e) if e.to_string().contains("ALREADY_ENABLED") => {},
            Err(e) => return Err(e.into()),
        }

        // Add to permanent config if requested
        if permanent {
            if let Ok(config_path) = self.get_zone_config_path(zone) {
                let _ = conn.call_method(
                    Some(BUS_NAME),
                    ObjectPath::try_from(config_path.as_str())?,
                    Some(interfaces::CONFIG_ZONE),
                    "addRichRule",
                    &(rule,),
                );
            }
        }

        let _ = self.event_sender.send(FirewallEvent::StateChanged);
        Ok(())
    }

    /// Remove a rich rule from a zone.
    pub fn remove_rich_rule(&self, zone: &str, rule: &str, permanent: bool) -> Result<()> {
        let conn = self.connection.as_ref()
            .ok_or_else(|| anyhow!("Not connected to firewalld"))?;

        // Remove from runtime config
        let result = conn.call_method(
            Some(BUS_NAME),
            paths::ROOT,
            Some(interfaces::ZONE),
            "removeRichRule",
            &(zone, rule),
        );

        match result {
            Ok(_) => info!("Removed rich rule from zone {}: {}", zone, rule),
            Err(e) if e.to_string().contains("NOT_ENABLED") => {},
            Err(e) => return Err(e.into()),
        }

        // Remove from permanent config if requested
        if permanent {
            if let Ok(config_path) = self.get_zone_config_path(zone) {
                let _ = conn.call_method(
                    Some(BUS_NAME),
                    ObjectPath::try_from(config_path.as_str())?,
                    Some(interfaces::CONFIG_ZONE),
                    "removeRichRule",
                    &(rule,),
                );
            }
        }

        let _ = self.event_sender.send(FirewallEvent::StateChanged);
        Ok(())
    }

    /// Get the D-Bus path for a zone's permanent config.
    fn get_zone_config_path(&self, zone_name: &str) -> Result<String> {
        let conn = self.connection.as_ref()
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
        let conn = self.connection.as_ref()
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
        let conn = self.connection.as_ref()
            .ok_or_else(|| anyhow!("Not connected to firewalld"))?;

        conn.call_method(
            Some(BUS_NAME),
            paths::ROOT,
            Some(interfaces::MAIN),
            "reload",
            &(),
        )?;

        info!("Firewalld configuration reloaded");
        let _ = self.event_sender.send(FirewallEvent::StateChanged);
        Ok(())
    }

    /// Enable panic mode - blocks all traffic.
    pub fn enable_panic_mode(&self) -> Result<()> {
        let conn = self.connection.as_ref()
            .ok_or_else(|| anyhow!("Not connected to firewalld"))?;

        conn.call_method(
            Some(BUS_NAME),
            paths::ROOT,
            Some(interfaces::MAIN),
            "enablePanicMode",
            &(),
        )?;

        info!("Panic mode enabled - all traffic blocked");
        let _ = self.event_sender.send(FirewallEvent::StateChanged);
        Ok(())
    }

    /// Disable panic mode - restore normal operation.
    pub fn disable_panic_mode(&self) -> Result<()> {
        let conn = self.connection.as_ref()
            .ok_or_else(|| anyhow!("Not connected to firewalld"))?;

        conn.call_method(
            Some(BUS_NAME),
            paths::ROOT,
            Some(interfaces::MAIN),
            "disablePanicMode",
            &(),
        )?;

        info!("Panic mode disabled - normal operation restored");
        let _ = self.event_sender.send(FirewallEvent::StateChanged);
        Ok(())
    }

    /// Query if panic mode is enabled.
    pub fn query_panic_mode(&self) -> Result<bool> {
        let conn = self.connection.as_ref()
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
