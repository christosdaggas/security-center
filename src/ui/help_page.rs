// Security Center - Help Page
// Copyright (C) 2026 Christos A. Daggas
// SPDX-License-Identifier: GPL-3.0-or-later

//! Help Page - Application documentation and guidance.

use gtk4 as gtk;
use gtk4::prelude::*;
use gtk4::glib;
use gtk4::subclass::prelude::*;

mod imp {
    use super::*;

    #[derive(Default)]
    pub struct HelpPage {}

    #[glib::object_subclass]
    impl ObjectSubclass for HelpPage {
        const NAME: &'static str = "HelpPage";
        type Type = super::HelpPage;
        type ParentType = gtk::Box;
    }

    impl ObjectImpl for HelpPage {
        fn constructed(&self) {
            self.parent_constructed();
            self.obj().setup_ui();
        }
    }

    impl WidgetImpl for HelpPage {}
    impl BoxImpl for HelpPage {}
}

glib::wrapper! {
    pub struct HelpPage(ObjectSubclass<imp::HelpPage>)
        @extends gtk::Widget, gtk::Box;
}

impl HelpPage {
    pub fn new() -> Self {
        glib::Object::builder()
            .property("orientation", gtk::Orientation::Vertical)
            .property("spacing", 0)
            .build()
    }

    fn setup_ui(&self) {
        // Page header
        let header_box = gtk::Box::new(gtk::Orientation::Vertical, 4);
        header_box.set_margin_start(24);
        header_box.set_margin_end(24);
        header_box.set_margin_top(24);
        header_box.set_margin_bottom(12);

        let title = gtk::Label::new(Some("Help"));
        title.add_css_class("title-1");
        title.set_halign(gtk::Align::Start);
        header_box.append(&title);

        let subtitle = gtk::Label::new(Some("Learn how to use Security Center"));
        subtitle.add_css_class("dim-label");
        subtitle.set_halign(gtk::Align::Start);
        header_box.append(&subtitle);

        self.append(&header_box);

        // Scrollable content
        let scroll = gtk::ScrolledWindow::new();
        scroll.set_vexpand(true);
        scroll.set_hexpand(true);
        scroll.set_policy(gtk::PolicyType::Never, gtk::PolicyType::Automatic);

        let content_box = gtk::Box::new(gtk::Orientation::Vertical, 24);
        content_box.set_margin_start(24);
        content_box.set_margin_end(24);
        content_box.set_margin_top(12);
        content_box.set_margin_bottom(24);

        // About section
        content_box.append(&self.create_section(
            "About Security Center",
            "Security Center is a comprehensive firewall and network security management tool for Linux. \
             It provides a graphical interface for managing firewalld zones, services, ports, and network \
             exposure settings. Monitor your system's security posture and quickly apply security configurations."
        ));

        // Overview section
        content_box.append(&self.create_section(
            "Overview",
            "The Overview page provides a summary of your system's security status. \
             It displays the current firewall state, active zone, number of open ports, \
             and running services. Use this page to get a quick assessment of your \
             system's security configuration and identify potential issues."
        ));

        // Zones section
        content_box.append(&self.create_section(
            "Zones",
            "Firewall zones define trust levels for network connections. \
             The Zones page lets you view and manage firewalld zones such as public, home, work, and trusted. \
             Assign network interfaces to zones, configure default zones, and create custom zones \
             for specific security requirements. Each zone has its own set of allowed services and ports."
        ));

        // Services section
        content_box.append(&self.create_section(
            "Services",
            "The Services page manages firewall service definitions. \
             Services are predefined combinations of ports and protocols (like HTTP, SSH, or DNS). \
             Enable or disable services for specific zones, view service details, \
             and add custom service definitions. Using services is easier and more maintainable \
             than managing individual port rules."
        ));

        // Ports section
        content_box.append(&self.create_section(
            "Ports",
            "The Ports page allows direct management of open ports. \
             Add or remove port rules for specific zones, specify TCP or UDP protocols, \
             and set port ranges. View all currently open ports and their associated zones. \
             Use this page when you need to open ports for applications that don't have \
             predefined service definitions."
        ));

        // System Services section
        content_box.append(&self.create_section(
            "System Services",
            "The System Services page shows network-related system services. \
             Monitor the status of services like firewalld, NetworkManager, and other \
             security-related daemons. Start, stop, enable, or disable services directly \
             from this interface. Ensure critical security services are running and \
             configured to start at boot."
        ));

        // Network Exposure section
        content_box.append(&self.create_section(
            "Network Exposure",
            "The Network Exposure page analyzes your system's network attack surface. \
             View listening ports and their associated processes, identify potentially \
             unnecessary exposed services, and get recommendations for reducing your \
             network footprint. This helps you understand what services are accessible \
             from the network and minimize security risks."
        ));

        // Quick Actions section
        content_box.append(&self.create_section(
            "Quick Actions",
            "Quick Actions provides one-click security operations for common tasks. \
             Enable panic mode to immediately block all network traffic, toggle the firewall, \
             apply preset security profiles, or reset to default settings. \
             Use these actions for emergency situations or quick configuration changes."
        ));

        // Tips section
        content_box.append(&self.create_section(
            "Tips",
            "• Always use the most restrictive zone that allows your applications to work.\n\
             • Prefer services over individual port rules for better maintainability.\n\
             • Regularly review open ports and disable unnecessary services.\n\
             • Keep firewalld running and enabled at boot for continuous protection.\n\
             • Use Network Exposure to audit your system's security periodically."
        ));

        scroll.set_child(Some(&content_box));
        self.append(&scroll);
    }

    fn create_section(&self, title: &str, description: &str) -> gtk::Box {
        let section = gtk::Box::new(gtk::Orientation::Vertical, 8);

        let title_label = gtk::Label::new(Some(title));
        title_label.add_css_class("title-3");
        title_label.set_halign(gtk::Align::Start);
        section.append(&title_label);

        let desc_label = gtk::Label::new(Some(description));
        desc_label.set_wrap(true);
        desc_label.set_wrap_mode(gtk::pango::WrapMode::WordChar);
        desc_label.set_xalign(0.0);
        desc_label.set_halign(gtk::Align::Start);
        desc_label.add_css_class("body");
        section.append(&desc_label);

        section
    }
}
