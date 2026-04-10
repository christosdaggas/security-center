# Contributing to Security Center Cosmic

Thank you for your interest in contributing to Security Center Cosmic!

## Development Setup

### Prerequisites

- Rust 1.70 or later
- GTK4 development libraries (gtk4-devel)
- libadwaita development libraries (libadwaita-devel)
- GResource compiler (glib2-devel)
- D-Bus development headers (for zbus)

**Fedora:**
```bash
sudo dnf install gtk4-devel libadwaita-devel glib2-devel dbus-devel
```

**Ubuntu:**
```bash
sudo apt install libgtk-4-dev libadwaita-1-dev libglib2.0-dev libdbus-1-dev
```

### Development Tools

Install required Rust tools:
```bash
rustup component add rustfmt clippy
```

### Building

```bash
cargo build
```

### Running

```bash
cargo run
```

**Note:** Some features require root access (e.g., firewall management). For full functionality:
```bash
sudo -E cargo run
```

## Code Quality

### Before Submitting

Run these checks before submitting a PR:

```bash
# Format code
cargo fmt

# Run linter (with warnings as errors)
cargo clippy -- -D warnings

# Run tests
cargo test

# Check for security advisories (optional)
cargo audit
```

## Code Style

### Naming Conventions

- **Modules**: `snake_case` (e.g., `dashboard_page.rs`)
- **Types**: `PascalCase` (e.g., `FirewallZone`, `SystemdService`)
- **Functions**: `snake_case` verbs (e.g., `add_port()`, `check_firewall_status()`)
- **Constants**: `SCREAMING_SNAKE_CASE` (e.g., `APP_ID`)

### Architecture

The codebase follows a layered architecture:

```
src/
├── main.rs              # Entry point, CSS loading
├── application.rs       # GTK Application lifecycle
├── config.rs            # Application settings
├── autostart.rs         # Autostart desktop file management
├── admin/               # Admin quick actions
│   ├── quick_actions.rs # Action definitions
│   └── action_runner.rs # Execution logic
├── firewall/            # Firewall management (zbus client)
│   ├── client.rs        # firewalld D-Bus client
│   ├── zone.rs          # Zone model
│   └── services.rs      # Service definitions
├── systemd/             # systemd D-Bus client
│   └── client.rs
├── stats/               # System statistics
│   ├── collector.rs     # Stats collection
│   └── cache.rs         # Stats caching
├── models/              # Data models
│   └── port.rs
├── storage/             # Persistence
│   └── port_storage.rs
└── ui/                  # GTK widgets and pages
    ├── main_window.rs
    └── pages/
        ├── dashboard_page.rs
        ├── ports_page.rs
        ├── services_page.rs
        ├── exposure_page.rs
        └── ...
```

### Key Rules

1. **Handle missing displays**: Always check `gdk::Display::default()` returns Some
2. **D-Bus error handling**: firewalld/systemd may not be available - handle gracefully
3. **RwLock poisoning**: Use `unwrap_or_else(|e| e.into_inner())` pattern
4. **PolicyKit integration**: Privileged operations need polkit authorization

## D-Bus Integration

### firewalld

The app uses zbus to communicate with firewalld:
- Interface: `org.fedoraproject.FirewallD1`
- Bus: System bus
- Handle case where firewalld is not installed/running

### systemd

For service management:
- Interface: `org.freedesktop.systemd1`
- Bus: System bus
- Requires PolicyKit authorization for start/stop

## Testing

### Unit Tests

```bash
cargo test
```

### Areas to Test

- `firewall/` - Zone parsing, service definitions
- `stats/` - /proc parsing
- `storage/` - CRUD operations
- `models/` - Validation

## Packaging

### Building Packages

```bash
# DEB package (requires cargo-deb)
cargo deb

# RPM package (requires cargo-generate-rpm)
cargo generate-rpm

# Flatpak (requires flatpak-builder)
flatpak-builder --user --install --force-clean build-dir com.chrisdaggas.security-center.yml
```

## Questions?

Open an issue for:
- Bug reports
- Feature requests
- Questions about the codebase


## License change

This project was relicensed to the MIT License (see `LICENSE`). If you have
contributed code and did not agree to relicensing, please contact the
maintainer. By contributing you confirm that you have the right to license
your contributions under the project's license.
