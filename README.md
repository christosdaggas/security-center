# Security Center

A modern, GTK4/Libadwaita security management application for Linux, providing a clean interface to **firewalld**, **systemd**, and system security monitoring.

![Security Center]<img width="1451" height="850" alt="security-center-white" src="https://github.com/user-attachments/assets/9bfe741e-6433-4167-b563-8f30ba901ffa" />

## Features

- **Firewall Management**: View and manage firewalld zones, services, and ports
- **Port Control**: Open and block custom TCP/UDP ports with rich rules
- **Network Exposure**: Monitor listening ports and correlate with firewall status
- **System Services**: Manage systemd services with start/stop/enable/disable
- **Quick Actions**: Common administrative tasks with one click
- **Dashboard Overview**: Real-time statistics showing firewall status, connections, and traffic
- **GNOME Integration**: Native look and feel with Libadwaita, dark mode support
- **Safe by Default**: Read-only mode with Polkit authentication for changes

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
│   ├── admin/               # Administrative actions
│   │   ├── actions.rs       # Quick action definitions
│   │   └── network.rs       # Network exposure scanner
│   ├── firewall/            # firewalld D-Bus client
│   │   └── client.rs        # Zone, port, service management
│   ├── systemd/             # systemd D-Bus client
│   │   └── client.rs        # Service management
│   ├── models/              # Data models
│   │   ├── zone.rs, port.rs, service.rs, interface.rs
│   ├── stats/               # System statistics
│   │   ├── collectors.rs    # Traffic/connection collection
│   │   └── cache.rs         # Stats caching
│   └── ui/                  # GTK4/Adw widgets and pages
│       ├── main_window.rs
│       ├── overview_page.rs
│       ├── zones_page.rs
│       ├── ports_page.rs
│       ├── services_page.rs
│       ├── network_exposure_page.rs
│       ├── quick_actions_page.rs
│       └── widgets/         # Custom chart widgets
└── data/
    ├── icons/               # Application icons
    ├── *.desktop            # Desktop entry
    └── *.metainfo.xml       # AppStream metadata
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

