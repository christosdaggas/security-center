// Security Center - Connections Page
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: MIT

//! Full analytical view of every active outbound connection.
//!
//! Where the dashboard shows only the top few talkers, this page lists *all*
//! established outgoing sessions grouped per destination, with per-group byte
//! totals, offline country, live search and sorting. Clicking any row opens the
//! IP details window.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use gtk4::glib;
use gtk4::prelude::*;
use gtk4::subclass::prelude::*;
use libadwaita as adw;
use libadwaita::prelude::*;

use super::app_icons::icon_for_process;
use super::ip_details::{present_ip_details, IpDetailsContext};
use crate::i18n::gettext;

/// How often the list refreshes while the page is on screen.
const REFRESH_SECS: u32 = 5;

/// One destination endpoint for one application, with its socket totals.
#[derive(Clone)]
pub(crate) struct ConnGroup {
    process: String,
    pid: Option<u32>,
    protocol: String,
    addr: IpAddr,
    port: u16,
    count: usize,
    bytes_in: u64,
    bytes_out: u64,
    country: Option<String>,
}

impl ConnGroup {
    fn bytes_total(&self) -> u64 {
        self.bytes_in.saturating_add(self.bytes_out)
    }

    /// Does this group match a lower-cased search needle?
    fn matches(&self, needle: &str) -> bool {
        if needle.is_empty() {
            return true;
        }
        self.process.to_lowercase().contains(needle)
            || self.addr.to_string().contains(needle)
            || self.port.to_string().contains(needle)
            || self
                .country
                .as_deref()
                .map(|c| c.to_lowercase().contains(needle))
                .unwrap_or(false)
    }
}

glib::wrapper! {
    /// Page listing all active outbound connections.
    pub struct ConnectionsPage(ObjectSubclass<imp::ConnectionsPage>)
        @extends gtk4::Box, gtk4::Widget,
        @implements gtk4::Accessible, gtk4::Buildable, gtk4::Orientable;
}

impl Default for ConnectionsPage {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionsPage {
    pub fn new() -> Self {
        let obj: Self = glib::Object::new();
        obj.setup_ui();
        obj
    }

    fn setup_ui(&self) {
        let imp = self.imp();
        self.set_orientation(gtk4::Orientation::Vertical);
        self.set_spacing(0);

        super::app_icons::register_flatpak_icon_paths();

        // --- Header: title + refresh ---
        let header = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .spacing(12)
            .margin_start(24)
            .margin_end(24)
            .margin_top(24)
            .margin_bottom(12)
            .build();
        let title_box = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Vertical)
            .spacing(4)
            .hexpand(true)
            .build();
        title_box.append(
            &gtk4::Label::builder()
                .label(gettext("Connections"))
                .css_classes(vec!["title-1".to_string()])
                .halign(gtk4::Align::Start)
                .build(),
        );
        title_box.append(
            &gtk4::Label::builder()
                .label(gettext("Every active outbound connection, by destination"))
                .css_classes(vec!["dim-label".to_string()])
                .halign(gtk4::Align::Start)
                .build(),
        );
        header.append(&title_box);

        let refresh_button = gtk4::Button::builder()
            .icon_name("view-refresh-symbolic")
            .tooltip_text(gettext("Refresh"))
            .css_classes(vec!["flat".to_string()])
            .valign(gtk4::Align::Center)
            .build();
        let page = self.clone();
        refresh_button.connect_clicked(move |_| page.refresh());
        header.append(&refresh_button);
        self.append(&header);

        // --- Scrollable content ---
        let scrolled = gtk4::ScrolledWindow::builder()
            .vexpand(true)
            .hexpand(true)
            .hscrollbar_policy(gtk4::PolicyType::Never)
            .build();
        let content = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Vertical)
            .spacing(16)
            .margin_top(8)
            .margin_bottom(24)
            .margin_start(24)
            .margin_end(24)
            .hexpand(true)
            .build();

        // Summary chips.
        let summary = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .spacing(12)
            .homogeneous(true)
            .build();
        let chip_conns = summary_chip(&summary, "network-transmit-receive-symbolic", &gettext("Connections"));
        let chip_hosts = summary_chip(&summary, "network-server-symbolic", &gettext("Remote hosts"));
        let chip_apps = summary_chip(&summary, "view-app-grid-symbolic", &gettext("Applications"));
        let chip_traffic = summary_chip(&summary, "network-wired-symbolic", &gettext("Total traffic"));
        imp.chip_conns.replace(Some(chip_conns));
        imp.chip_hosts.replace(Some(chip_hosts));
        imp.chip_apps.replace(Some(chip_apps));
        imp.chip_traffic.replace(Some(chip_traffic));
        content.append(&summary);

        // Search + sort controls.
        let controls = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .spacing(10)
            .build();
        let search = gtk4::SearchEntry::builder()
            .placeholder_text(gettext("Search by app, IP, port or country"))
            .hexpand(true)
            .build();
        let page = self.clone();
        search.connect_search_changed(move |_| page.render());
        controls.append(&search);
        imp.search.replace(Some(search));

        let sort = gtk4::DropDown::from_strings(&[
            gettext("Traffic").as_str(),
            gettext("Application").as_str(),
            gettext("Country").as_str(),
            gettext("Connections").as_str(),
        ]);
        sort.set_tooltip_text(Some(&gettext("Sort connections")));
        let page = self.clone();
        sort.connect_selected_notify(move |_| page.render());
        controls.append(&sort);
        imp.sort.replace(Some(sort));
        content.append(&controls);

        // The list itself (boxed-list of ActionRows).
        let list = gtk4::ListBox::builder()
            .selection_mode(gtk4::SelectionMode::None)
            .css_classes(vec!["boxed-list".to_string()])
            .build();
        imp.list.replace(Some(list.clone()));
        content.append(&list);

        let status = gtk4::Label::builder()
            .label(gettext("Scanning…"))
            .css_classes(vec!["dim-label".to_string()])
            .halign(gtk4::Align::Center)
            .margin_top(8)
            .build();
        imp.status.replace(Some(status.clone()));
        content.append(&status);

        imp.scrolled.replace(Some(scrolled.clone()));
        scrolled.set_child(Some(&content));
        self.append(&scrolled);

        // Live refresh while the page is visible.
        let page = self.clone();
        glib::timeout_add_seconds_local(REFRESH_SECS, move || {
            if page.is_mapped() {
                page.refresh();
            }
            glib::ControlFlow::Continue
        });
    }

    /// Rescan connections in the background, then re-render.
    pub fn refresh(&self) {
        let page = self.clone();
        glib::spawn_future_local(async move {
            let data = gtk4::gio::spawn_blocking(|| {
                let mut scanner = crate::admin::NetworkExposure::new();
                let connections = scanner.scan_connections().unwrap_or_default();
                let socket_bytes = crate::admin::collect_socket_bytes().unwrap_or_default();
                let geo = crate::admin::GeoIp::load();
                let labels: HashMap<IpAddr, String> = connections
                    .iter()
                    .filter_map(|c| geo.country_label(c.remote_addr).map(|l| (c.remote_addr, l)))
                    .collect();
                (connections, socket_bytes, labels)
            })
            .await;

            if let Ok((connections, socket_bytes, geo_labels)) = data {
                page.ingest(connections, socket_bytes, geo_labels);
            }
        });
    }

    /// Fold raw sockets into per-destination groups and cache them.
    fn ingest(
        &self,
        connections: Vec<crate::admin::ActiveConnection>,
        socket_bytes: HashMap<u32, (u64, u64)>,
        geo_labels: HashMap<IpAddr, String>,
    ) {
        let mut groups: Vec<ConnGroup> = Vec::new();
        for conn in &connections {
            let (bin, bout) = socket_bytes
                .get(&(conn.inode as u32))
                .copied()
                .unwrap_or((0, 0));
            let proc = conn.process_label();
            if let Some(g) = groups.iter_mut().find(|g| {
                g.process == proc && g.addr == conn.remote_addr && g.port == conn.remote_port
            }) {
                g.count += 1;
                g.bytes_in = g.bytes_in.saturating_add(bin);
                g.bytes_out = g.bytes_out.saturating_add(bout);
                if g.pid.is_none() {
                    g.pid = conn.pid;
                }
            } else {
                groups.push(ConnGroup {
                    process: proc,
                    pid: conn.pid,
                    protocol: conn.protocol.as_str().to_string(),
                    addr: conn.remote_addr,
                    port: conn.remote_port,
                    count: 1,
                    bytes_in: bin,
                    bytes_out: bout,
                    country: geo_labels.get(&conn.remote_addr).cloned(),
                });
            }
        }

        // Summary chips (over the unfiltered set).
        let hosts: HashSet<IpAddr> = groups.iter().map(|g| g.addr).collect();
        let apps: HashSet<&str> = groups.iter().map(|g| g.process.as_str()).collect();
        let total_conns: usize = groups.iter().map(|g| g.count).sum();
        let total_bytes: u64 = groups.iter().map(|g| g.bytes_total()).sum();
        set_chip(&self.imp().chip_conns, &total_conns.to_string());
        set_chip(&self.imp().chip_hosts, &hosts.len().to_string());
        set_chip(&self.imp().chip_apps, &apps.len().to_string());
        set_chip(&self.imp().chip_traffic, &format_bytes(total_bytes));

        self.imp().groups.replace(groups);
        self.render();
    }

    /// Apply the current search + sort to the cached groups and rebuild rows.
    fn render(&self) {
        let imp = self.imp();
        let list = match imp.list.borrow().as_ref() {
            Some(l) => l.clone(),
            None => return,
        };
        // Preserve the scroll position across the rebuild so the 5s live refresh
        // doesn't yank a browsing user back to the top of the list.
        let scroll_pos = imp
            .scrolled
            .borrow()
            .as_ref()
            .map(|s| s.vadjustment().value());
        while let Some(child) = list.first_child() {
            list.remove(&child);
        }

        let needle = imp
            .search
            .borrow()
            .as_ref()
            .map(|s| s.text().to_lowercase())
            .unwrap_or_default();
        let sort_mode = imp.sort.borrow().as_ref().map(|d| d.selected()).unwrap_or(0);

        let all = imp.groups.borrow();
        let mut rows: Vec<ConnGroup> = all.iter().filter(|g| g.matches(&needle)).cloned().collect();
        match sort_mode {
            1 => rows.sort_by(|a, b| {
                a.process
                    .to_lowercase()
                    .cmp(&b.process.to_lowercase())
                    .then(b.bytes_total().cmp(&a.bytes_total()))
            }),
            2 => rows.sort_by(|a, b| {
                country_key(a).cmp(&country_key(b)).then(b.bytes_total().cmp(&a.bytes_total()))
            }),
            3 => rows.sort_by(|a, b| b.count.cmp(&a.count).then(b.bytes_total().cmp(&a.bytes_total()))),
            _ => rows.sort_by(|a, b| {
                b.bytes_total()
                    .cmp(&a.bytes_total())
                    .then(b.count.cmp(&a.count))
            }),
        }

        for g in &rows {
            list.append(&self.build_row(g));
        }

        // Restore the scroll offset after the new rows have been laid out.
        if let Some(pos) = scroll_pos {
            if let Some(sw) = imp.scrolled.borrow().as_ref() {
                let adj = sw.vadjustment();
                glib::idle_add_local_once(move || adj.set_value(pos));
            }
        }

        if let Some(status) = imp.status.borrow().as_ref() {
            let text = if all.is_empty() {
                gettext("No active outbound connections")
            } else if rows.is_empty() {
                gettext("No connections match your search")
            } else {
                format!(
                    "{} {} · {} {}",
                    rows.len(),
                    gettext("destinations"),
                    all.iter().map(|g| g.count).sum::<usize>(),
                    gettext("sockets")
                )
            };
            status.set_label(&text);
        }
    }

    /// Build one connection row that opens the IP details window when activated.
    fn build_row(&self, g: &ConnGroup) -> adw::ActionRow {
        let title = format!("{} → {}:{}", g.process, g.addr, g.port);
        let mut parts = vec![g.protocol.clone()];
        if g.count > 1 {
            parts.push(format!("{} {}", g.count, gettext("connections")));
        }
        let total = g.bytes_total();
        if total > 0 {
            parts.push(format!(
                "↓{} ↑{}",
                format_bytes(g.bytes_in),
                format_bytes(g.bytes_out)
            ));
        }

        let row = adw::ActionRow::builder()
            .title(glib::markup_escape_text(&title).as_str())
            .subtitle(glib::markup_escape_text(&parts.join(" · ")).as_str())
            .activatable(true)
            .build();
        row.add_prefix(
            &gtk4::Image::builder()
                .icon_name(icon_for_process(&g.process, g.port))
                .pixel_size(24)
                .build(),
        );

        if let Some(country) = &g.country {
            row.add_suffix(
                &gtk4::Label::builder()
                    .label(country)
                    .css_classes(vec!["caption".to_string()])
                    .valign(gtk4::Align::Center)
                    .build(),
            );
        }
        let info = gtk4::Button::builder()
            .icon_name("dialog-information-symbolic")
            .css_classes(vec!["flat".to_string()])
            .valign(gtk4::Align::Center)
            .tooltip_text(gettext("IP details"))
            .build();
        row.add_suffix(&info);

        // Both the info button and row activation open the details window.
        let ctx_src = g.clone();
        let page = self.clone();
        let open = move || {
            present_ip_details(
                &page,
                IpDetailsContext {
                    ip: ctx_src.addr,
                    port: ctx_src.port,
                    protocol: ctx_src.protocol.clone(),
                    process: Some(ctx_src.process.clone()),
                    pid: ctx_src.pid,
                    bytes_in: ctx_src.bytes_in,
                    bytes_out: ctx_src.bytes_out,
                    country_label: ctx_src.country.clone(),
                },
            );
        };
        let open_btn = open.clone();
        info.connect_clicked(move |_| open_btn());
        row.connect_activated(move |_| open());
        row
    }
}

/// A country sort key that pushes unknown/empty countries to the end.
fn country_key(g: &ConnGroup) -> String {
    match &g.country {
        Some(c) if !c.is_empty() => c.to_lowercase(),
        _ => "\u{10ffff}".to_string(),
    }
}

/// Add a summary chip card to `parent`, returning its value label.
fn summary_chip(parent: &gtk4::Box, icon: &str, caption: &str) -> gtk4::Label {
    let frame = gtk4::Frame::new(None);
    frame.add_css_class("card");
    let content = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(12)
        .margin_top(12)
        .margin_bottom(12)
        .margin_start(14)
        .margin_end(14)
        .build();
    content.append(
        &gtk4::Image::builder()
            .icon_name(icon)
            .pixel_size(20)
            .css_classes(vec!["dim-label".to_string()])
            .valign(gtk4::Align::Center)
            .build(),
    );
    let text = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(0)
        .build();
    let value = gtk4::Label::builder()
        .label("0")
        .css_classes(vec!["title-3".to_string()])
        .halign(gtk4::Align::Start)
        .build();
    text.append(&value);
    text.append(
        &gtk4::Label::builder()
            .label(caption)
            .css_classes(vec!["caption".to_string(), "dim-label".to_string()])
            .halign(gtk4::Align::Start)
            .build(),
    );
    content.append(&text);
    frame.set_child(Some(&content));
    parent.append(&frame);
    value
}

fn set_chip(cell: &RefCell<Option<gtk4::Label>>, text: &str) {
    if let Some(label) = cell.borrow().as_ref() {
        label.set_label(text);
    }
}

/// Format a byte count as a compact human-readable string (B/KB/MB/GB).
fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{} {}", bytes, UNITS[unit])
    } else {
        format!("{:.1} {}", value, UNITS[unit])
    }
}

mod imp {
    use super::*;

    #[derive(Default)]
    pub struct ConnectionsPage {
        pub chip_conns: RefCell<Option<gtk4::Label>>,
        pub chip_hosts: RefCell<Option<gtk4::Label>>,
        pub chip_apps: RefCell<Option<gtk4::Label>>,
        pub chip_traffic: RefCell<Option<gtk4::Label>>,
        pub search: RefCell<Option<gtk4::SearchEntry>>,
        pub sort: RefCell<Option<gtk4::DropDown>>,
        pub list: RefCell<Option<gtk4::ListBox>>,
        pub scrolled: RefCell<Option<gtk4::ScrolledWindow>>,
        pub status: RefCell<Option<gtk4::Label>>,
        pub(crate) groups: RefCell<Vec<ConnGroup>>,
    }

    #[glib::object_subclass]
    impl ObjectSubclass for ConnectionsPage {
        const NAME: &'static str = "SecurityCenterConnectionsPage";
        type Type = super::ConnectionsPage;
        type ParentType = gtk4::Box;
    }

    impl ObjectImpl for ConnectionsPage {}
    impl WidgetImpl for ConnectionsPage {}
    impl BoxImpl for ConnectionsPage {}
}
