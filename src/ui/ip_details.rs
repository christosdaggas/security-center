// Security Center - IP details dialog
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: MIT

//! A reusable window that shows everything known about a single remote IP:
//! the local connection facts and offline country instantly, plus an optional
//! on-demand online lookup (ISP, city, region, ASN, reverse DNS) and quick
//! links to open the address on external reputation/geolocation services.

use std::net::IpAddr;

use gtk4::glib;
use gtk4::prelude::*;
use libadwaita as adw;
use libadwaita::prelude::*;

use crate::admin::IpDetails;
use crate::i18n::gettext;

/// Everything the caller already knows about the connection to `ip`.
pub struct IpDetailsContext {
    pub ip: IpAddr,
    pub port: u16,
    pub protocol: String,
    pub process: Option<String>,
    pub pid: Option<u32>,
    pub bytes_in: u64,
    pub bytes_out: u64,
    /// Offline "flag + country" label, when the local GeoIP database resolves.
    pub country_label: Option<String>,
}

/// Rows whose values are filled in once the online lookup returns.
#[derive(Clone)]
struct DetailRows {
    region: adw::ActionRow,
    city: adw::ActionRow,
    timezone: adw::ActionRow,
    coords: adw::ActionRow,
    isp: adw::ActionRow,
    org: adw::ActionRow,
    asn: adw::ActionRow,
    reverse: adw::ActionRow,
    flags: adw::ActionRow,
    network_group: adw::PreferencesGroup,
    source: gtk4::Label,
    hero_country: gtk4::Label,
}

/// Build and present the IP details dialog anchored to `parent`.
pub fn present_ip_details(parent: &impl IsA<gtk4::Widget>, ctx: IpDetailsContext) {
    let dialog = adw::Dialog::builder()
        .title(gettext("IP Details"))
        .content_width(500)
        .build();

    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&adw::HeaderBar::new());

    let page = adw::PreferencesPage::new();

    // --- Hero: address + offline country ---
    let hero = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(4)
        .halign(gtk4::Align::Center)
        .margin_top(6)
        .margin_bottom(6)
        .build();
    hero.append(
        &gtk4::Label::builder()
            .label(ctx.ip.to_string())
            .css_classes(vec!["title-2".to_string(), "mono-addr".to_string()])
            .selectable(true)
            .wrap(true)
            .justify(gtk4::Justification::Center)
            .build(),
    );
    let hero_country = gtk4::Label::builder()
        .label(
            ctx.country_label
                .clone()
                .unwrap_or_else(|| gettext("Location unknown offline")),
        )
        .css_classes(vec!["dim-label".to_string()])
        .build();
    hero.append(&hero_country);
    let hero_group = adw::PreferencesGroup::new();
    hero_group.add(&hero);
    page.add(&hero_group);

    // --- Connection facts (all known locally) ---
    let conn_group = adw::PreferencesGroup::builder()
        .title(gettext("Connection"))
        .build();

    let process_text = match (&ctx.process, ctx.pid) {
        (Some(name), Some(pid)) => format!("{name} (PID {pid})"),
        (Some(name), None) => name.clone(),
        (None, Some(pid)) => format!("PID {pid}"),
        (None, None) => gettext("Unknown"),
    };
    conn_group.add(&static_row(&gettext("Application"), &process_text));
    conn_group.add(&static_row(
        &gettext("Remote endpoint"),
        &format!("{}:{}", ctx.ip, ctx.port),
    ));
    conn_group.add(&static_row(&gettext("Protocol"), &ctx.protocol));
    conn_group.add(&static_row(
        &gettext("Data received"),
        &format_bytes(ctx.bytes_in),
    ));
    conn_group.add(&static_row(&gettext("Data sent"), &format_bytes(ctx.bytes_out)));
    page.add(&conn_group);

    // --- Location (offline country now; rest filled online) ---
    let loc_group = adw::PreferencesGroup::builder()
        .title(gettext("Location"))
        .build();

    let country_row = static_row(
        &gettext("Country"),
        &ctx.country_label
            .clone()
            .unwrap_or_else(|| gettext("Unknown")),
    );
    loc_group.add(&country_row);

    let region = hidden_row(&gettext("Region"));
    let city = hidden_row(&gettext("City"));
    let timezone = hidden_row(&gettext("Time zone"));
    let coords = hidden_row(&gettext("Coordinates"));
    loc_group.add(&region);
    loc_group.add(&city);
    loc_group.add(&timezone);
    loc_group.add(&coords);
    page.add(&loc_group);

    // --- Network / ownership (filled online) ---
    let network_group = adw::PreferencesGroup::builder()
        .title(gettext("Network"))
        .visible(false)
        .build();
    let isp = hidden_row(&gettext("ISP"));
    let org = hidden_row(&gettext("Organization"));
    let asn = hidden_row(&gettext("AS number"));
    let reverse = hidden_row(&gettext("Reverse DNS"));
    let flags = hidden_row(&gettext("Flags"));
    network_group.add(&isp);
    network_group.add(&org);
    network_group.add(&asn);
    network_group.add(&reverse);
    network_group.add(&flags);
    page.add(&network_group);

    let rows = DetailRows {
        region,
        city,
        timezone,
        coords,
        isp,
        org,
        asn,
        reverse,
        flags,
        network_group,
        source: gtk4::Label::builder()
            .css_classes(vec!["caption".to_string(), "dim-label".to_string()])
            .halign(gtk4::Align::Center)
            .wrap(true)
            .build(),
        hero_country: hero_country.clone(),
    };

    // --- Online lookup control ---
    let online_enabled = crate::config::Settings::new().enable_online_ip_lookup();
    let lookup_group = adw::PreferencesGroup::new();
    if online_enabled {
        let lookup_btn = gtk4::Button::builder()
            .label(gettext("Look up online"))
            .css_classes(vec!["pill".to_string(), "suggested-action".to_string()])
            .halign(gtk4::Align::Center)
            .build();
        let spinner = gtk4::Spinner::new();
        let status = rows.source.clone();

        let control = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Vertical)
            .spacing(8)
            .halign(gtk4::Align::Center)
            .margin_top(2)
            .build();
        let btn_row = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .spacing(8)
            .halign(gtk4::Align::Center)
            .build();
        btn_row.append(&lookup_btn);
        btn_row.append(&spinner);
        control.append(&btn_row);
        control.append(&status);
        lookup_group.add(&control);

        let ip = ctx.ip;
        let rows_cb = rows.clone();
        let country_row_cb = country_row.clone();
        lookup_btn.connect_clicked(move |btn| {
            btn.set_sensitive(false);
            spinner.set_visible(true);
            spinner.start();
            status.set_text(&gettext("Looking up…"));
            status.remove_css_class("error");

            let btn = btn.clone();
            let spinner = spinner.clone();
            let status = status.clone();
            let rows_cb = rows_cb.clone();
            let country_row_cb = country_row_cb.clone();
            glib::spawn_future_local(async move {
                let result =
                    gtk4::gio::spawn_blocking(move || crate::admin::lookup_ip_online(ip)).await;
                spinner.stop();
                spinner.set_visible(false);
                match result {
                    Ok(Ok(details)) => {
                        let source = details.source.clone();
                        apply_details(&rows_cb, &country_row_cb, &details);
                        status.set_text(&format!("{} {}", gettext("Source:"), source));
                        // A successful lookup needs no retry button.
                        btn.set_label(&gettext("Refresh"));
                        btn.set_sensitive(true);
                    }
                    Ok(Err(e)) => {
                        status.add_css_class("error");
                        status.set_text(&format!("{}: {}", gettext("Lookup failed"), e));
                        btn.set_sensitive(true);
                    }
                    Err(_) => {
                        status.add_css_class("error");
                        status.set_text(&gettext("Lookup failed"));
                        btn.set_sensitive(true);
                    }
                }
            });
        });
    } else {
        lookup_group.add(&static_row(
            &gettext("Online lookups"),
            &gettext("Disabled in Preferences"),
        ));
    }
    page.add(&lookup_group);

    // --- External services (open in browser) ---
    let ext_group = adw::PreferencesGroup::builder()
        .title(gettext("Open in browser"))
        .description(gettext("Look up this address on external services"))
        .build();
    let ip_str = ctx.ip.to_string();
    for (name, url) in [
        ("ipinfo.io", format!("https://ipinfo.io/{ip_str}")),
        ("AbuseIPDB", format!("https://www.abuseipdb.com/check/{ip_str}")),
        ("Shodan", format!("https://www.shodan.io/host/{ip_str}")),
        (
            "Whois (ARIN)",
            format!("https://search.arin.net/rdap/?query={ip_str}"),
        ),
    ] {
        ext_group.add(&link_row(name, &url));
    }
    page.add(&ext_group);

    toolbar.set_content(Some(&page));
    dialog.set_child(Some(&toolbar));
    dialog.present(Some(parent));
}

/// Populate the online-only rows from a lookup result.
fn apply_details(rows: &DetailRows, country_row: &adw::ActionRow, d: &IpDetails) {
    // Country: prefer the online (often more specific) value, with a flag.
    if let Some(country) = &d.country {
        let text = match &d.flag_emoji {
            Some(flag) if !flag.is_empty() => format!("{flag} {country}"),
            _ => country.clone(),
        };
        // The ActionRow subtitle is Pango markup — escape untrusted remote data.
        country_row.set_subtitle(glib::markup_escape_text(&text).as_str());
        // Keep the hero's location line in sync (plain GtkLabel, no escaping).
        rows.hero_country.set_text(&text);
    }
    fill(&rows.region, d.region.clone());
    fill(&rows.city, d.city.clone());
    fill(&rows.timezone, d.timezone.clone());
    fill(
        &rows.coords,
        match (d.latitude, d.longitude) {
            (Some(lat), Some(lon)) => Some(format!("{lat:.4}, {lon:.4}")),
            _ => None,
        },
    );

    fill(&rows.isp, d.isp.clone());
    fill(&rows.org, d.org.clone());
    fill(
        &rows.asn,
        match (&d.asn, &d.asn_org) {
            (Some(asn), Some(org)) if !org.is_empty() && !asn.contains(org.as_str()) => {
                Some(format!("{asn} · {org}"))
            }
            (Some(asn), _) => Some(asn.clone()),
            (None, Some(org)) => Some(org.clone()),
            _ => None,
        },
    );
    fill(&rows.reverse, d.reverse_hostname.clone());
    fill(&rows.flags, threat_flags(d));

    // Reveal the Network group only if at least one field landed.
    let any_network = [&rows.isp, &rows.org, &rows.asn, &rows.reverse, &rows.flags]
        .iter()
        .any(|r| r.is_visible());
    rows.network_group.set_visible(any_network);
}

/// Human-readable summary of the proxy/hosting/mobile threat flags.
fn threat_flags(d: &IpDetails) -> Option<String> {
    let mut parts = Vec::new();
    if d.is_proxy == Some(true) {
        parts.push(gettext("Proxy/VPN"));
    }
    if d.is_hosting == Some(true) {
        parts.push(gettext("Hosting/Datacenter"));
    }
    if d.is_mobile == Some(true) {
        parts.push(gettext("Mobile network"));
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(" · "))
    }
}

/// A key/value row with a static, selectable value.
fn static_row(title: &str, value: &str) -> adw::ActionRow {
    let row = adw::ActionRow::builder()
        .title(glib::markup_escape_text(title).as_str())
        .subtitle(glib::markup_escape_text(value).as_str())
        .build();
    row.set_subtitle_selectable(true);
    row
}

/// A key/value row that starts hidden until a value is available.
fn hidden_row(title: &str) -> adw::ActionRow {
    let row = static_row(title, "—");
    row.set_visible(false);
    row
}

/// Fill a hidden row with a value and reveal it, or keep it hidden if empty.
fn fill(row: &adw::ActionRow, value: Option<String>) {
    match value {
        Some(v) if !v.trim().is_empty() => {
            row.set_subtitle(glib::markup_escape_text(v.trim()).as_str());
            row.set_visible(true);
        }
        _ => row.set_visible(false),
    }
}

/// An activatable row that opens `url` in the default browser.
fn link_row(name: &str, url: &str) -> adw::ActionRow {
    let row = adw::ActionRow::builder()
        .title(name)
        .subtitle(url)
        .activatable(true)
        .build();
    row.add_suffix(&gtk4::Image::from_icon_name("adw-external-link-symbolic"));
    let url = url.to_string();
    row.connect_activated(move |_| {
        if let Err(e) =
            gtk4::gio::AppInfo::launch_default_for_uri(&url, gtk4::gio::AppLaunchContext::NONE)
        {
            tracing::warn!("Failed to open {}: {}", url, e);
        }
    });
    row
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
