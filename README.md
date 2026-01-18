# GNOME Firewall

A modern, GNOME-native graphical firewall manager for Linux, providing a clean interface to **firewalld**.

![GNOME Firewall](data/icons/hicolor/scalable/apps/org.gnome.Firewall.svg)

## Features

- **Zone Management**: View and manage firewalld zones with clear status indicators
- **Service Control**: Enable/disable predefined network services
- **Port Management**: Open and close custom TCP/UDP ports
- **Dashboard Overview**: Quick statistics showing firewall status, active zones, and open ports
- **GNOME Integration**: Native look and feel with Libadwaita, dark mode support
- **Safe by Default**: Read-only mode with Polkit authentication for changes

## Screenshots

*Coming soon*

## Requirements

### Runtime Dependencies

- GTK 4.0+
- Libadwaita 1.0+
- Python 3.10+
- PyGObject
- firewalld
- polkit

### Build Dependencies

- Meson 0.62+
- Ninja

## Building

### From Source

```bash
# Clone the repository
git clone https://gitlab.gnome.org/GNOME/gnome-firewall.git
cd gnome-firewall

# Configure build
meson setup builddir
meson configure builddir -Dprefix=/usr/local

# Build
meson compile -C builddir

# Install
sudo meson install -C builddir
```

### Development

For development without installing:

```bash
# Compile GSettings schemas
glib-compile-schemas data/

# Run directly
chmod +x run.sh
./run.sh
```

Or using Python directly:

```bash
export PYTHONPATH="$PWD/src:$PYTHONPATH"
export GSETTINGS_SCHEMA_DIR="$PWD/data"
python3 src/main.py
```

### Flatpak (Future)

Flatpak packaging is planned for easy distribution.

## Architecture

```
gnome-firewall/
├── src/
│   ├── gnome_firewall/
│   │   ├── application/    # GApplication lifecycle
│   │   ├── auth/           # Polkit integration
│   │   ├── firewall/       # firewalld D-Bus client
│   │   ├── models/         # Data models (Zone, Service, Port)
│   │   ├── ui/             # GTK4/Adw widgets and views
│   │   └── utils/          # Logging, errors, helpers
│   └── main.py             # Development entry point
├── data/
│   ├── icons/              # Application icons
│   ├── *.desktop.in        # Desktop entry
│   ├── *.metainfo.xml.in   # AppStream metadata
│   └── *.gschema.xml       # GSettings schema
└── meson.build             # Build configuration
```

### Key Design Decisions

1. **D-Bus Only**: All firewalld communication uses D-Bus. No shell commands.
2. **Read-Only by Default**: The app starts in read-only mode; write operations require Polkit authentication.
3. **Model-View Separation**: Clean separation between UI, domain logic, and system access.
4. **GNOME HIG Compliance**: Follows GNOME Human Interface Guidelines strictly.

## Current Status (v0.1.0)

### Implemented ✓

- [x] Project structure and build system
- [x] Application lifecycle (GApplication/AdwApplication)
- [x] Main window with navigation sidebar
- [x] Overview dashboard with statistics
- [x] Zones view with expandable details
- [x] Services view (read-only)
- [x] Ports view (read-only)
- [x] firewalld D-Bus client (read operations)
- [x] Polkit integration framework
- [x] Desktop integration files

### TODO (v1.0)

- [ ] Write operations (add/remove ports, services)
- [ ] Zone interface assignment
- [ ] Set default zone
- [ ] Runtime vs permanent toggle
- [ ] "Make permanent" action
- [ ] Firewall enable/disable
- [ ] GNOME notifications
- [ ] Keyboard shortcuts overlay
- [ ] Flatpak packaging

### Non-Goals (v1.x)

- nftables direct editing
- Container-specific rules
- Remote firewall management
- Custom zone creation

## Contributing

Contributions are welcome! Please:

1. Follow GNOME coding style
2. Test with firewalld running
3. Ensure no shell commands are used
4. Keep UI consistent with GNOME HIG

### Running Tests

```bash
# TODO: Add test infrastructure
```

## License

GNOME Firewall is licensed under the [GPL-3.0-or-later](COPYING).

## Credits

- Inspired by GNOME Circle applications
- Built with [GTK4](https://gtk.org/) and [Libadwaita](https://gnome.pages.gitlab.gnome.org/libadwaita/)
- Uses [firewalld](https://firewalld.org/) D-Bus API

## See Also

- [firewalld Documentation](https://firewalld.org/documentation/)
- [GNOME Human Interface Guidelines](https://developer.gnome.org/hig/)
- [GTK4 Documentation](https://docs.gtk.org/gtk4/)
- [Libadwaita Documentation](https://gnome.pages.gitlab.gnome.org/libadwaita/doc/)
