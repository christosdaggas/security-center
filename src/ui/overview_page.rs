// Security Center - Overview Page
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: MIT

//! Overview dashboard page with statistics charts.

use std::cell::RefCell;

use gtk4::prelude::*;
use gtk4::subclass::prelude::*;
use gtk4::glib;
use libadwaita as adw;

use crate::models::Zone;
use crate::stats::{StatsCache, TrafficCollector, ConnectionCollector};
use super::widgets::{DonutChart, LineChart, BarChart};

glib::wrapper! {
    /// Overview page showing firewall status.
    pub struct OverviewPage(ObjectSubclass<imp::OverviewPage>)
        @extends gtk4::Box, gtk4::Widget,
        @implements gtk4::Orientable;
}

impl OverviewPage {
    /// Create a new overview page.
    pub fn new() -> Self {
        let page: Self = glib::Object::new();
        page.setup_ui();
        // Note: load_cached_stats is called later with start_stats_collection
        page
    }

    /// Get the traffic switch widget.
    pub fn traffic_switch(&self) -> Option<gtk4::Switch> {
        self.imp().traffic_switch.borrow().clone()
    }

    /// Update the traffic status display.
    pub fn set_traffic_enabled(&self, enabled: bool) {
        let imp = self.imp();
        
        if let Some(switch) = imp.traffic_switch.borrow().as_ref() {
            switch.set_active(enabled);
        }
        
        if let Some(label) = imp.traffic_label.borrow().as_ref() {
            if enabled {
                label.set_label("Traffic Enabled");
                label.remove_css_class("error");
                label.add_css_class("success");
            } else {
                label.set_label("Traffic Disabled");
                label.remove_css_class("success");
                label.add_css_class("error");
            }
        }

        if let Some(icon) = imp.status_icon.borrow().as_ref() {
            if enabled {
                icon.set_icon_name(Some("security-high-symbolic"));
                icon.remove_css_class("error");
                icon.add_css_class("success");
            } else {
                icon.set_icon_name(Some("security-low-symbolic"));
                icon.remove_css_class("success");
                icon.add_css_class("error");
            }
        }

        if let Some(title) = imp.status_title.borrow().as_ref() {
            title.set_label(if enabled { "Firewall Active" } else { "Firewall Paused" });
        }

        if let Some(subtitle) = imp.status_subtitle.borrow().as_ref() {
            subtitle.set_label(if enabled { "Your system is protected" } else { "All traffic is blocked" });
        }
    }

    /// Setup the UI.
    fn setup_ui(&self) {
        let imp = self.imp();

        self.set_orientation(gtk4::Orientation::Vertical);
        self.set_spacing(0);

        // Main scrolled container - no clamp for full width
        let scrolled = gtk4::ScrolledWindow::builder()
            .hscrollbar_policy(gtk4::PolicyType::Never)
            .vscrollbar_policy(gtk4::PolicyType::Automatic)
            .vexpand(true)
            .hexpand(true)
            .build();

        let content = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Vertical)
            .spacing(24)
            .margin_top(24)
            .margin_bottom(24)
            .margin_start(24)
            .margin_end(24)
            .hexpand(true)
            .build();

        // === STATUS CARD ===
        let status_frame = gtk4::Frame::new(None);
        status_frame.add_css_class("card");
        
        let status_box = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .spacing(16)
            .margin_top(20)
            .margin_bottom(20)
            .margin_start(24)
            .margin_end(24)
            .build();

        let status_icon = gtk4::Image::builder()
            .icon_name("security-high-symbolic")
            .pixel_size(48)
            .css_classes(vec!["success".to_string()])
            .build();
        imp.status_icon.replace(Some(status_icon.clone()));

        let status_text = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Vertical)
            .spacing(4)
            .valign(gtk4::Align::Center)
            .hexpand(true)
            .build();

        let status_title = gtk4::Label::builder()
            .label("Firewall Active")
            .css_classes(vec!["title-2".to_string()])
            .halign(gtk4::Align::Start)
            .build();
        imp.status_title.replace(Some(status_title.clone()));

        let status_subtitle = gtk4::Label::builder()
            .label("Your system is protected")
            .css_classes(vec!["dim-label".to_string()])
            .halign(gtk4::Align::Start)
            .build();
        imp.status_subtitle.replace(Some(status_subtitle.clone()));

        status_text.append(&status_title);
        status_text.append(&status_subtitle);
        status_box.append(&status_icon);
        status_box.append(&status_text);

        // Traffic toggle area with default zone
        let toggle_box = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .spacing(16)
            .valign(gtk4::Align::Center)
            .halign(gtk4::Align::End)
            .build();

        // Default zone info (to the left of the switch)
        let zone_info_box = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .spacing(8)
            .valign(gtk4::Align::Center)
            .build();

        let zone_icon = gtk4::Image::builder()
            .icon_name("security-medium-symbolic")
            .css_classes(vec!["dim-label".to_string()])
            .build();
        zone_info_box.append(&zone_icon);

        let zone_label = gtk4::Label::builder()
            .label("Default Zone:")
            .css_classes(vec!["caption".to_string(), "dim-label".to_string()])
            .build();
        zone_info_box.append(&zone_label);

        let zone_name_label = gtk4::Label::builder()
            .label("public")
            .css_classes(vec!["caption".to_string()])
            .build();
        imp.default_zone_label.replace(Some(zone_name_label.clone()));
        zone_info_box.append(&zone_name_label);

        toggle_box.append(&zone_info_box);

        // Separator before restart button
        let separator1 = gtk4::Separator::builder()
            .orientation(gtk4::Orientation::Vertical)
            .build();
        toggle_box.append(&separator1);

        // Restart Firewall button
        let restart_box = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Vertical)
            .spacing(4)
            .valign(gtk4::Align::Center)
            .build();

        let restart_button = gtk4::Button::builder()
            .icon_name("view-refresh-symbolic")
            .tooltip_text("Restart Firewall")
            .css_classes(vec!["circular".to_string()])
            .valign(gtk4::Align::Center)
            .build();

        let restart_label = gtk4::Label::builder()
            .label("Restart")
            .css_classes(vec!["caption".to_string(), "dim-label".to_string()])
            .halign(gtk4::Align::Center)
            .build();

        restart_button.connect_clicked(move |button| {
            button.set_sensitive(false);
            let btn = button.clone();
            glib::spawn_future_local(async move {
                let result = gtk4::gio::spawn_blocking(move || {
                    let mut client = crate::firewall::FirewallClient::new();
                    if let Err(e) = client.connect() {
                        return Err(format!("Not connected to firewalld: {}", e));
                    }
                    client.reload().map_err(|e| e.to_string())
                }).await;

                btn.set_sensitive(true);
                
                // Show toast feedback via the window
                if let Some(root) = btn.root() {
                    if let Some(window) = root.downcast_ref::<gtk4::Window>() {
                        if let Some(main_window) = window.downcast_ref::<super::MainWindow>() {
                            match result {
                                Ok(Ok(())) => {
                                    main_window.show_toast("Firewall reloaded successfully");
                                    main_window.refresh_data();
                                }
                                Ok(Err(e)) => {
                                    main_window.show_toast(&format!("Failed to reload: {}", e));
                                }
                                Err(_) => {
                                    main_window.show_toast("Failed to reload firewall");
                                }
                            }
                        }
                    }
                }
            });
        });

        restart_box.append(&restart_button);
        restart_box.append(&restart_label);
        toggle_box.append(&restart_box);

        // Separator
        let separator = gtk4::Separator::builder()
            .orientation(gtk4::Orientation::Vertical)
            .build();
        toggle_box.append(&separator);

        // Switch and label in a vertical box
        let switch_box = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Vertical)
            .spacing(4)
            .valign(gtk4::Align::Center)
            .build();

        let traffic_switch = gtk4::Switch::builder()
            .active(true)
            .valign(gtk4::Align::Center)
            .halign(gtk4::Align::Center)
            .build();
        imp.traffic_switch.replace(Some(traffic_switch.clone()));

        let toggle_label = gtk4::Label::builder()
            .label("Traffic Enabled")
            .css_classes(vec!["caption".to_string(), "success".to_string()])
            .halign(gtk4::Align::Center)
            .build();
        imp.traffic_label.replace(Some(toggle_label.clone()));

        switch_box.append(&traffic_switch);
        switch_box.append(&toggle_label);
        toggle_box.append(&switch_box);

        status_box.append(&toggle_box);

        status_frame.set_child(Some(&status_box));
        content.append(&status_frame);

        imp.status_banner.replace(None); // Not using banner anymore

        // === SYSTEM STATISTICS === (moved up from below)
        let sys_stats_title = gtk4::Label::builder()
            .label("System Statistics")
            .css_classes(vec!["heading".to_string()])
            .halign(gtk4::Align::Start)
            .margin_top(8)
            .build();
        content.append(&sys_stats_title);

        // System stats cards in a row
        let sys_stats_box = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .spacing(16)
            .homogeneous(true)
            .build();

        // Running services card
        let services_stat = self.create_system_stat_card("0", "Running Services", "system-run-symbolic");
        imp.running_services_stat.replace(Some(services_stat.clone()));
        sys_stats_box.append(&services_stat);

        // Memory usage card
        let memory_stat = self.create_system_stat_card("0%", "Memory Usage", "computer-symbolic");
        imp.memory_usage_stat.replace(Some(memory_stat.clone()));
        sys_stats_box.append(&memory_stat);

        // Disk usage card
        let disk_stat = self.create_system_stat_card("0%", "Disk Usage", "drive-harddisk-symbolic");
        imp.disk_usage_stat.replace(Some(disk_stat.clone()));
        sys_stats_box.append(&disk_stat);

        content.append(&sys_stats_box);

        // === NETWORK STATISTICS ===
        let net_stats_title = gtk4::Label::builder()
            .label("Network Statistics")
            .css_classes(vec!["heading".to_string()])
            .halign(gtk4::Align::Start)
            .margin_top(8)
            .build();
        content.append(&net_stats_title);

        // Charts in a grid layout
        let charts_grid = gtk4::Grid::builder()
            .column_spacing(16)
            .row_spacing(16)
            .column_homogeneous(true)
            .build();

        // Traffic ratio donut chart
        let traffic_card = self.create_chart_card("Traffic Ratio");
        let donut_chart = DonutChart::new();
        donut_chart.set_size_request(180, 180);
        donut_chart.set_halign(gtk4::Align::Center);
        donut_chart.set_margin_top(8);
        donut_chart.set_margin_bottom(8);
        if let Some(content_box) = traffic_card.first_child() {
            if let Some(box_content) = content_box.downcast_ref::<gtk4::Box>() {
                box_content.append(&donut_chart);
            }
        }
        imp.traffic_chart.replace(Some(donut_chart));
        charts_grid.attach(&traffic_card, 0, 0, 1, 1);

        // Connections chart (TCP/UDP/ICMP)
        let connections_card = self.create_connections_card();
        charts_grid.attach(&connections_card, 1, 0, 1, 1);

        // Blocked ports bar chart  
        let ports_card = self.create_chart_card("Blocked Ports");
        let bar_chart = BarChart::new();
        bar_chart.set_size_request(-1, 160);
        bar_chart.set_hexpand(true);
        bar_chart.set_margin_top(8);
        bar_chart.set_margin_bottom(8);
        if let Some(content_box) = ports_card.first_child() {
            if let Some(box_content) = content_box.downcast_ref::<gtk4::Box>() {
                box_content.append(&bar_chart);
            }
        }
        imp.blocked_ports_chart.replace(Some(bar_chart));
        charts_grid.attach(&ports_card, 2, 0, 1, 1);

        content.append(&charts_grid);

        scrolled.set_child(Some(&content));
        self.append(&scrolled);

        // Start stats collection after delay
        let page = self.clone();
        glib::timeout_add_seconds_local_once(2, move || {
            page.start_stats_collection();
        });
    }

    /// Create a system stat card widget.
    fn create_system_stat_card(&self, value: &str, label: &str, icon: &str) -> gtk4::Frame {
        let frame = gtk4::Frame::builder()
            .build();
        frame.add_css_class("card");

        let card_content = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Vertical)
            .spacing(8)
            .margin_top(16)
            .margin_bottom(16)
            .margin_start(16)
            .margin_end(16)
            .halign(gtk4::Align::Center)
            .build();

        let icon_widget = gtk4::Image::builder()
            .icon_name(icon)
            .pixel_size(32)
            .css_classes(vec!["dim-label".to_string()])
            .build();

        let value_label = gtk4::Label::builder()
            .label(value)
            .css_classes(vec!["title-1".to_string()])
            .build();
        value_label.set_widget_name("value");

        let label_widget = gtk4::Label::builder()
            .label(label)
            .css_classes(vec!["dim-label".to_string(), "caption".to_string()])
            .build();

        card_content.append(&icon_widget);
        card_content.append(&value_label);
        card_content.append(&label_widget);

        frame.set_child(Some(&card_content));
        frame
    }

    /// Create a chart card container.
    fn create_chart_card(&self, title: &str) -> gtk4::Frame {
        let frame = gtk4::Frame::builder()
            .build();
        frame.add_css_class("card");

        let card_content = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Vertical)
            .spacing(8)
            .margin_top(16)
            .margin_bottom(16)
            .margin_start(16)
            .margin_end(16)
            .build();

        let title_label = gtk4::Label::builder()
            .label(title)
            .css_classes(vec!["heading".to_string()])
            .halign(gtk4::Align::Start)
            .build();
        card_content.append(&title_label);

        frame.set_child(Some(&card_content));
        frame
    }

    /// Create the connections card showing TCP/UDP/ICMP activity.
    fn create_connections_card(&self) -> gtk4::Frame {
        let imp = self.imp();
        
        let frame = gtk4::Frame::builder()
            .build();
        frame.add_css_class("card");

        let card_content = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Vertical)
            .spacing(8)
            .margin_top(16)
            .margin_bottom(16)
            .margin_start(16)
            .margin_end(16)
            .build();

        // Header with title
        let title_label = gtk4::Label::builder()
            .label("Connections")
            .css_classes(vec!["heading".to_string()])
            .halign(gtk4::Align::Start)
            .build();
        card_content.append(&title_label);

        // Line chart for TCP/UDP/ICMP
        let chart = LineChart::new();
        chart.set_size_request(-1, 120);
        chart.set_hexpand(true);
        chart.set_margin_top(8);
        chart.set_margin_bottom(8);
        chart.set_show_legend(true);
        
        imp.connections_chart.replace(Some(chart.clone()));
        card_content.append(&chart);

        frame.set_child(Some(&card_content));
        frame
    }

    /// Load cached statistics asynchronously.
    fn load_cached_stats_async(&self) {
        let page = self.clone();
        glib::spawn_future_local(async move {
            let cached = gtk4::gio::spawn_blocking(move || {
                let cache = StatsCache::new();
                cache.load()
            }).await;
            
            if let Ok(Some(cached)) = cached {
                let imp = page.imp();
                if let Some(chart) = imp.traffic_chart.borrow().as_ref() {
                    chart.set_data(
                        cached.traffic_ratio.accepted as f64,
                        cached.traffic_ratio.blocked as f64,
                    );
                }
                // Network activity chart handles its own live collection
                if let Some(chart) = imp.blocked_ports_chart.borrow().as_ref() {
                    chart.set_data(&cached.blocked_ports);
                }
            }
        });
    }

    /// Start periodic statistics collection.
    fn start_stats_collection(&self) {
        let imp = self.imp();
        
        // Create collectors (no I/O, just struct creation)
        let traffic_collector = TrafficCollector::new();
        let connection_collector = ConnectionCollector::new();
        
        imp.traffic_collector.replace(Some(traffic_collector));
        imp.connection_collector.replace(Some(connection_collector));

        // Load cached stats asynchronously first
        self.load_cached_stats_async();

        // Defer initial collection to avoid blocking startup
        let page = self.clone();
        glib::timeout_add_seconds_local_once(2, move || {
            page.collect_stats_async();
        });

        // Set up periodic collection every 5 seconds
        let page = self.clone();
        glib::timeout_add_seconds_local(5, move || {
            page.collect_stats_async();
            glib::ControlFlow::Continue
        });
    }

    /// Collect stats asynchronously to avoid blocking the UI.
    fn collect_stats_async(&self) {
        let page = self.clone();
        
        glib::spawn_future_local(async move {
            // Run file I/O in background thread
            let stats_data = gtk4::gio::spawn_blocking(move || {
                // Collect traffic stats
                let mut traffic_accepted: u64 = 0;
                let mut _traffic_blocked: u64 = 0;
                
                // Try to read from /proc/net/snmp
                if let Ok(content) = std::fs::read_to_string("/proc/net/snmp") {
                    for line in content.lines() {
                        if line.starts_with("Ip:") && !line.contains("Forwarding") {
                            let parts: Vec<&str> = line.split_whitespace().collect();
                            if parts.len() > 10 {
                                traffic_accepted = parts.get(3).unwrap_or(&"0").parse().unwrap_or(0);
                            }
                        }
                    }
                }
                
                // Read connection counts
                let mut tcp: u32 = 0;
                let mut udp: u32 = 0;
                let mut icmp: u32 = 0;
                
                if let Ok(content) = std::fs::read_to_string("/proc/net/nf_conntrack") {
                    for line in content.lines() {
                        if line.contains("tcp") {
                            tcp += 1;
                        } else if line.contains("udp") {
                            udp += 1;
                        } else if line.contains("icmp") {
                            icmp += 1;
                        }
                    }
                } else {
                    // Fallback
                    tcp = std::fs::read_to_string("/proc/net/tcp")
                        .map(|c| c.lines().count().saturating_sub(1) as u32).unwrap_or(0)
                        + std::fs::read_to_string("/proc/net/tcp6")
                        .map(|c| c.lines().count().saturating_sub(1) as u32).unwrap_or(0);
                    udp = std::fs::read_to_string("/proc/net/udp")
                        .map(|c| c.lines().count().saturating_sub(1) as u32).unwrap_or(0)
                        + std::fs::read_to_string("/proc/net/udp6")
                        .map(|c| c.lines().count().saturating_sub(1) as u32).unwrap_or(0);
                }

                // Collect system statistics
                // Running services count
                let running_services = std::process::Command::new("systemctl")
                    .args(["list-units", "--type=service", "--state=running", "--no-pager", "--no-legend"])
                    .output()
                    .map(|o| String::from_utf8_lossy(&o.stdout).lines().count() as u32)
                    .unwrap_or(0);

                // Memory usage from /proc/meminfo
                let memory_percent = if let Ok(content) = std::fs::read_to_string("/proc/meminfo") {
                    let mut total: u64 = 0;
                    let mut available: u64 = 0;
                    for line in content.lines() {
                        if line.starts_with("MemTotal:") {
                            total = line.split_whitespace().nth(1).unwrap_or("0").parse().unwrap_or(0);
                        } else if line.starts_with("MemAvailable:") {
                            available = line.split_whitespace().nth(1).unwrap_or("0").parse().unwrap_or(0);
                        }
                    }
                    if total > 0 {
                        ((total - available) * 100 / total) as u32
                    } else {
                        0
                    }
                } else {
                    0
                };

                // Disk usage using df command (simpler approach without libc)
                let disk_percent = std::process::Command::new("df")
                    .args(["--output=pcent", "/"])
                    .output()
                    .map(|o| {
                        let output = String::from_utf8_lossy(&o.stdout);
                        // Skip header line, parse percentage
                        output.lines()
                            .nth(1)
                            .and_then(|line| line.trim().trim_end_matches('%').parse::<u32>().ok())
                            .unwrap_or(0)
                    })
                    .unwrap_or(0);
                
                (traffic_accepted, _traffic_blocked, tcp, udp, icmp, running_services, memory_percent, disk_percent)
            }).await;
            
            // Update UI on main thread
            if let Ok((accepted, blocked, tcp, udp, icmp, running_services, memory_percent, disk_percent)) = stats_data {
                page.update_charts(accepted, blocked, tcp, udp, icmp);
                page.update_system_stats(running_services, memory_percent, disk_percent);
            }
        });
    }

    /// Update system statistics display.
    fn update_system_stats(&self, running_services: u32, memory_percent: u32, disk_percent: u32) {
        let imp = self.imp();

        // Helper to update card value
        fn update_card_value(card: &gtk4::Frame, value: &str) {
            if let Some(content) = card.child() {
                if let Some(box_widget) = content.downcast_ref::<gtk4::Box>() {
                    let mut child = box_widget.first_child();
                    while let Some(widget) = child {
                        if let Some(label) = widget.downcast_ref::<gtk4::Label>() {
                            if label.widget_name() == "value" {
                                label.set_label(value);
                                return;
                            }
                        }
                        child = widget.next_sibling();
                    }
                }
            }
        }

        if let Some(card) = imp.running_services_stat.borrow().as_ref() {
            update_card_value(card, &running_services.to_string());
        }

        if let Some(card) = imp.memory_usage_stat.borrow().as_ref() {
            update_card_value(card, &format!("{}%", memory_percent));
        }

        if let Some(card) = imp.disk_usage_stat.borrow().as_ref() {
            update_card_value(card, &format!("{}%", disk_percent));
        }
    }

    /// Update chart widgets with collected data.
    fn update_charts(&self, accepted: u64, blocked: u64, tcp: u32, udp: u32, icmp: u32) {
        let imp = self.imp();
        
        // Update traffic chart
        if let Some(chart) = imp.traffic_chart.borrow().as_ref() {
            // Use reasonable defaults if no traffic
            let total = accepted + blocked;
            if total > 0 {
                chart.set_data(accepted as f64, blocked as f64);
            } else {
                chart.set_data(95.0, 5.0); // Default placeholder
            }
        }
        
        // Update connection history and chart
        if let Some(collector) = imp.connection_collector.borrow_mut().as_mut() {
            // Manually update the collector
            let stats = crate::stats::models::ConnectionStats {
                tcp, udp, icmp, other: 0, timestamp: None,
            };
            collector.push_stats(stats);
            let ts = collector.timeseries();
            
            if let Some(chart) = imp.connections_chart.borrow().as_ref() {
                chart.set_data(
                    &ts.tcp.iter().map(|&v| v as f64).collect::<Vec<_>>(),
                    &ts.udp.iter().map(|&v| v as f64).collect::<Vec<_>>(),
                    &ts.icmp.iter().map(|&v| v as f64).collect::<Vec<_>>(),
                );
            }
        }
        
        // Update traffic collector for caching
        if let Some(collector) = imp.traffic_collector.borrow_mut().as_mut() {
            collector.update_totals(accepted, blocked);
        }
        
        // Save to cache
        self.save_stats_cache();
    }



    /// Save current stats to cache.
    fn save_stats_cache(&self) {
        let imp = self.imp();
        let cache = StatsCache::new();
        
        let traffic_ratio = if let Some(collector) = imp.traffic_collector.borrow().as_ref() {
            let snap = collector.snapshot();
            crate::stats::CachedTrafficRatio {
                accepted: snap.accepted,
                blocked: snap.blocked,
            }
        } else {
            crate::stats::CachedTrafficRatio { accepted: 0, blocked: 0 }
        };
        
        let connections = if let Some(collector) = imp.connection_collector.borrow().as_ref() {
            let ts = collector.timeseries();
            crate::stats::CachedConnectionStats {
                tcp_series: ts.tcp.iter().map(|&v| v as f64).collect(),
                udp_series: ts.udp.iter().map(|&v| v as f64).collect(),
                icmp_series: ts.icmp.iter().map(|&v| v as f64).collect(),
            }
        } else {
            crate::stats::CachedConnectionStats {
                tcp_series: vec![],
                udp_series: vec![],
                icmp_series: vec![],
            }
        };
        
        let cached = crate::stats::CachedStats {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            traffic_ratio,
            connections,
            blocked_ports: vec![], // TODO: collect blocked ports
        };
        
        cache.save(&cached);
    }

    /// Update the page with zone data.
    pub fn set_zones(&self, zones: &[Zone]) {
        let imp = self.imp();

        // Count active zones
        let active_count = zones.iter().filter(|z| z.is_active).count();
        
        // Count total services across active zones
        let services_count: usize = zones.iter()
            .filter(|z| z.is_active)
            .map(|z| z.services.len())
            .sum();

        // Count total ports across active zones
        let ports_count: usize = zones.iter()
            .filter(|z| z.is_active)
            .map(|z| z.ports.len())
            .sum();

        // Helper to find value label in stat card (Frame -> Box -> icon -> value_label -> label)
        fn update_stat_value(frame: &gtk4::Frame, value: &str) {
            // Structure: Frame -> Box with (icon -> value_label -> label)
            if let Some(content) = frame.child() {
                if let Some(box_widget) = content.downcast_ref::<gtk4::Box>() {
                    if let Some(icon) = box_widget.first_child() {
                        if let Some(value_widget) = icon.next_sibling() {
                            if let Some(label) = value_widget.downcast_ref::<gtk4::Label>() {
                                label.set_label(value);
                            }
                        }
                    }
                }
            }
        }

        // Update stat items
        if let Some(card) = imp.zones_count.borrow().as_ref() {
            update_stat_value(card, &active_count.to_string());
        }

        if let Some(card) = imp.services_count.borrow().as_ref() {
            update_stat_value(card, &services_count.to_string());
        }

        if let Some(card) = imp.ports_count.borrow().as_ref() {
            update_stat_value(card, &ports_count.to_string());
        }

        // Update default zone label
        if let Some(default_zone) = zones.iter().find(|z| z.is_default) {
            if let Some(label) = imp.default_zone_label.borrow().as_ref() {
                label.set_label(&default_zone.name);
            }
        }
    }

    /// Update the blocked ports chart with current blocked port data.
    pub fn set_blocked_ports(&self, blocked_ports: &[crate::models::Port]) {
        let imp = self.imp();

        // Convert ports to bar chart data format: (label, count)
        // Group by port/protocol and count occurrences (or just show each as 1 block)
        let chart_data: Vec<(String, u64)> = blocked_ports.iter()
            .take(5)  // Show top 5 blocked ports
            .map(|port| {
                let label = format!("{}/{}", port.number, port.protocol.to_uppercase());
                (label, 1u64)  // Each blocked port counts as 1
            })
            .collect();

        if let Some(chart) = imp.blocked_ports_chart.borrow().as_ref() {
            if chart_data.is_empty() {
                // Show placeholder when no blocked ports
                chart.set_placeholder("No blocked ports");
            } else {
                chart.set_data(&chart_data);
            }
        }
    }
}

impl Default for OverviewPage {
    fn default() -> Self {
        Self::new()
    }
}

mod imp {
    use super::*;
    use crate::stats::{TrafficCollector, ConnectionCollector};

    #[derive(Default)]
    pub struct OverviewPage {
        pub status_banner: RefCell<Option<adw::Banner>>,
        pub status_icon: RefCell<Option<gtk4::Image>>,
        pub status_title: RefCell<Option<gtk4::Label>>,
        pub status_subtitle: RefCell<Option<gtk4::Label>>,
        pub traffic_switch: RefCell<Option<gtk4::Switch>>,
        pub traffic_label: RefCell<Option<gtk4::Label>>,
        pub zones_count: RefCell<Option<gtk4::Frame>>,
        pub services_count: RefCell<Option<gtk4::Frame>>,
        pub ports_count: RefCell<Option<gtk4::Frame>>,
        pub default_zone_label: RefCell<Option<gtk4::Label>>,
        // Charts
        pub traffic_chart: RefCell<Option<DonutChart>>,
        pub connections_chart: RefCell<Option<LineChart>>,
        pub blocked_ports_chart: RefCell<Option<BarChart>>,
        // Collectors
        pub traffic_collector: RefCell<Option<TrafficCollector>>,
        pub connection_collector: RefCell<Option<ConnectionCollector>>,
        // System statistics
        pub running_services_stat: RefCell<Option<gtk4::Frame>>,
        pub memory_usage_stat: RefCell<Option<gtk4::Frame>>,
        pub disk_usage_stat: RefCell<Option<gtk4::Frame>>,
    }

    #[glib::object_subclass]
    impl ObjectSubclass for OverviewPage {
        const NAME: &'static str = "SecurityCenterOverviewPage";
        type Type = super::OverviewPage;
        type ParentType = gtk4::Box;
    }

    impl ObjectImpl for OverviewPage {}
    impl WidgetImpl for OverviewPage {}
    impl BoxImpl for OverviewPage {}
}
