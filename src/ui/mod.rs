// Security Center - UI Module
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: MIT

//! User interface components.

mod main_window;
mod overview_page;
mod zones_page;
mod services_page;
mod ports_page;
mod system_services_page;
mod network_exposure_page;
mod quick_actions_page;
mod help_page;

pub mod widgets; 

pub use main_window::MainWindow;
pub use overview_page::OverviewPage;
pub use zones_page::ZonesPage;
pub use services_page::ServicesPage;
pub use ports_page::PortsPage;
pub use system_services_page::SystemServicesPage;
pub use network_exposure_page::NetworkExposurePage;
pub use quick_actions_page::QuickActionsPage;
pub use help_page::HelpPage;
