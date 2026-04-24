Name:           security-center
Version:        1.6.0
Release:        1%{?dist}
Summary:        A modern GTK4 security center for Linux

License:        MIT
URL:            https://github.com/christosdaggas/security-center
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  cargo >= 1.70
BuildRequires:  rust >= 1.70
BuildRequires:  gtk4-devel >= 4.14
BuildRequires:  libadwaita-devel >= 1.5
BuildRequires:  cairo-devel
BuildRequires:  pango-devel
BuildRequires:  gdk-pixbuf2-devel
BuildRequires:  graphene-devel

Requires:       gtk4 >= 4.14
Requires:       libadwaita >= 1.5
Requires:       firewalld
Requires:       polkit

%description
Security Center is a modern GTK4/Libadwaita application for managing
system security on Linux. It provides a user-friendly interface for
controlling firewalld, monitoring network exposure, and managing
system services.

Features:
- Firewall zone management
- Port and service configuration  
- Network exposure monitoring
- System service management
- Quick administrative actions

%prep
%autosetup

%build
cargo build --release

%install
install -Dm755 target/release/%{name} %{buildroot}%{_bindir}/%{name}
install -Dm644 data/com.chrisdaggas.security-center.desktop %{buildroot}%{_datadir}/applications/com.chrisdaggas.security-center.desktop
install -Dm644 data/com.chrisdaggas.security-center.metainfo.xml %{buildroot}%{_datadir}/metainfo/com.chrisdaggas.security-center.metainfo.xml
install -Dm644 data/icons/hicolor/scalable/apps/com.chrisdaggas.security-center.svg %{buildroot}%{_datadir}/icons/hicolor/scalable/apps/com.chrisdaggas.security-center.svg
install -Dm644 data/icons/hicolor/symbolic/apps/com.chrisdaggas.security-center-symbolic.svg %{buildroot}%{_datadir}/icons/hicolor/symbolic/apps/com.chrisdaggas.security-center-symbolic.svg
install -Dm644 README.md %{buildroot}%{_docdir}/%{name}/README.md

%files
%license LICENSE
%doc README.md
%{_bindir}/%{name}
%{_datadir}/applications/com.chrisdaggas.security-center.desktop
%{_datadir}/metainfo/com.chrisdaggas.security-center.metainfo.xml
%{_datadir}/icons/hicolor/scalable/apps/com.chrisdaggas.security-center.svg
%{_datadir}/icons/hicolor/symbolic/apps/com.chrisdaggas.security-center-symbolic.svg
%{_docdir}/%{name}/README.md

%post
gtk-update-icon-cache -q -t -f %{_datadir}/icons/hicolor || :
update-desktop-database -q %{_datadir}/applications || :
appstreamcli refresh-cache || :

%postun
gtk-update-icon-cache -q -t -f %{_datadir}/icons/hicolor || :
update-desktop-database -q %{_datadir}/applications || :
appstreamcli refresh-cache || :

%changelog
* Thu Apr 24 2026 Christos Daggas <chrisdaggas@example.com> - 1.6.0-1
- Security hardening release: dependency updates, input validation, pkexec parameter allowlisting,
  config file sanitization, semver parsing, CI/CD pipeline, test expansion, accessibility improvements,
  logging safety, and unused dependency cleanup.

* Thu Apr 10 2026 Christos Daggas <chrisdaggas@example.com> - 1.5.0-1
- Cross-distro support for Fedora, Ubuntu, Debian and all desktop environments
- Fixed Debian/Ubuntu package dependencies (polkit package naming)
- KDE Plasma compatibility for accent color detection
- Config directory renamed from gnome-security-center to security-center
- Automatic settings migration from old config path
- Universal autostart desktop entry for all DEs
- AppImage now bundles GTK4/libadwaita shared libraries
- Architecture-independent AppImage build
- Clear error message when PolicyKit is not installed

* Sun Feb 08 2026 Christos Daggas <chrisdaggas@example.com> - 1.4.0-1
- Consolidated port view — same-port entries grouped into single rows
- Improved firewall state display (Active, Panic Mode, Inactive)
- Traffic switch disabled when firewall is stopped
- Dashboard status syncs after Quick Actions changes
- Fixed restart button stretching and signal feedback loops

* Tue Jan 07 2026 Christos Daggas <chrisdaggas@example.com> - 1.0.0-1
- Initial release
- Firewall management with firewalld integration
- Network exposure monitoring
- System services management
- Quick administrative actions
