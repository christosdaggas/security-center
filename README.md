# Security Center

A modern, GTK4/Libadwaita security management application for Linux, providing a clean interface to **firewalld**, **systemd**, and system security monitoring.

<img width="1451" height="850" alt="security-center-white" src="https://github.com/user-attachments/assets/9bfe741e-6433-4167-b563-8f30ba901ffa" />

## Features

- **Firewall Management**: View and manage firewalld zones, services, and ports
- **Port Control**: Open and block custom TCP/UDP ports with rich rules; consolidated view groups same-port entries across zones and protocols
- **Network Exposure**: Monitor listening ports and correlate with firewall status
- **System Services**: Manage systemd services with start/stop/enable/disable
- **Quick Actions**: Common administrative tasks with one click (enable/disable firewall, panic mode, etc.)
- **Dashboard Overview**: Real-time statistics showing firewall status, connections, and traffic with donut, bar, and line charts
- **Three-State Firewall Display**: Dashboard shows Active, Panic Mode, or Inactive states with appropriate indicators
- **Collapsible Sidebar**: Toggle between expanded and icon-only navigation mode
- **Update Checker**: Automatic GitHub release check notifies when new versions are available
- **GNOME Integration**: Native look and feel with Libadwaita, dark mode support
- **Safe by Default**: Read-only mode with Polkit authentication for changes
- **Internationalization**: Translations for Arabic, German, Greek, Spanish, French, Hindi, Italian, Portuguese, Russian, and Chinese

## Screenshots

*Coming soon*

## Requirements

### Runtime Dependencies

- GTK4 4.14+
- Libadwaita 1.5+
- firewalld
- polkit
- systemd

### Build Dependencies

- Rust 1.70+
- GTK4 development libraries
- Libadwaita development libraries

**Fedora:**
```bash
sudo dnf install gtk4-devel libadwaita-devel glib2-devel dbus-devel
```

**Ubuntu/Debian:**
```bash
sudo apt install libgtk-4-dev libadwaita-1-dev libglib2.0-dev libdbus-1-dev
```

**Arch Linux:**
```bash
sudo pacman -S gtk4 libadwaita glib2 dbus
```

## Building

### From Source

```bash
# Clone the repository
git clone https://github.com/christosdaggas/security-center.git
cd security-center

# Build
cargo build --release

# Run
cargo run --release
```

### Development

```bash
# Install development tools
rustup component add rustfmt clippy

# Build in debug mode
cargo build

# Run with logging
RUST_LOG=debug cargo run

# Run linter
cargo clippy -- -D warnings

# Format code
cargo fmt
```

**Note:** Some features require elevated privileges. For full functionality:
```bash
sudo -E cargo run --release
```

## Architecture

```
security-center/
├── src/
│   ├── main.rs              # Entry point, CSS loading
│   ├── application.rs       # GTK Application lifecycle
│   ├── config.rs            # Application settings
│   ├── autostart.rs         # Desktop autostart management
│   ├── storage.rs           # Port metadata persistence
│   ├── version_check.rs     # GitHub release update checker
│   ├── admin/               # Administrative actions
│   │   ├── actions.rs       # Quick action definitions
│   │   └── network.rs       # Network exposure scanner
│   ├── firewall/            # firewalld D-Bus client
│   │   └── client.rs        # Zone, port, service management
│   ├── systemd/             # systemd D-Bus client
│   │   └── client.rs        # Service management
│   ├── models/              # Data models
│   │   ├── zone.rs          # Firewall zone model
│   │   ├── port.rs          # Port model with rich rule parsing
│   │   ├── consolidated_port.rs  # Port consolidation logic
│   │   ├── service.rs       # Firewall service model
│   │   └── interface.rs     # Network interface model
│   ├── stats/               # System statistics
│   │   ├── collectors.rs    # Traffic/connection collection
│   │   ├── cache.rs         # Stats caching
│   │   └── models.rs        # Stats data models
│   └── ui/                  # GTK4/Adw widgets and pages
│       ├── main_window.rs   # Main window with collapsible sidebar
│       ├── overview_page.rs # Dashboard with charts and status
│       ├── zones_page.rs    # Zone management
│       ├── ports_page.rs    # Port rules with consolidated view
│       ├── services_page.rs # Firewall services
│       ├── system_services_page.rs  # Systemd services
│       ├── network_exposure_page.rs # Network exposure analysis
│       ├── quick_actions_page.rs    # Administrative quick actions
│       ├── help_page.rs     # Help and documentation
│       └── widgets/         # Custom chart widgets
│           ├── donut_chart.rs
│           ├── bar_chart.rs
│           ├── line_chart.rs
│           └── network_activity_chart.rs
├── data/
│   ├── icons/               # Application icons
│   ├── *.desktop            # Desktop entry
│   └── *.metainfo.xml       # AppStream metadata
├── po/                      # Translation files
└── packaging/               # DEB, RPM, Arch, AppImage packaging
```

### Key Design Decisions

1. **D-Bus Only**: All firewalld/systemd communication uses D-Bus. No shell commands.
2. **Pure Rust**: Network introspection via procfs without external tools.
3. **Read-Only by Default**: Write operations require Polkit authentication.
4. **GNOME HIG Compliance**: Follows GNOME Human Interface Guidelines.

## Packaging

### DEB Package (requires cargo-deb)
```bash
cargo install cargo-deb
cargo deb
```

### RPM Package (requires cargo-generate-rpm)
```bash
cargo install cargo-generate-rpm
cargo build --release
cargo generate-rpm
```

### Flatpak
```bash
flatpak-builder --user --install --force-clean build-dir com.chrisdaggas.security-center.yml
```

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Security Center is licensed under the [MIT License](LICENSE).

## Credits

- Built with [GTK4](https://gtk.org/) and [Libadwaita](https://gnome.pages.gitlab.gnome.org/libadwaita/)
- Uses [firewalld](https://firewalld.org/) and [systemd](https://systemd.io/) D-Bus APIs
- Inspired by GNOME Circle applications

## See Also

- [firewalld Documentation](https://firewalld.org/documentation/)
- [GNOME Human Interface Guidelines](https://developer.gnome.org/hig/)
- [GTK4 Documentation](https://docs.gtk.org/gtk4/)
- [Libadwaita Documentation](https://gnome.pages.gitlab.gnome.org/libadwaita/doc/)

