// Security Center - UI Module
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: MIT

//! User interface components.

mod help_page;
mod main_window;
mod network_exposure_page;
mod overview_page;
mod ports_page;
mod quick_actions_page;
mod services_page;
mod system_services_page;
mod zones_page;

pub mod widgets;

pub use help_page::HelpPage;
pub use main_window::MainWindow;
pub use network_exposure_page::NetworkExposurePage;
pub use overview_page::OverviewPage;
pub use ports_page::PortsPage;
pub use quick_actions_page::QuickActionsPage;
pub use services_page::ServicesPage;
pub use system_services_page::SystemServicesPage;
pub use zones_page::ZonesPage;
