#!/bin/bash
# Doctor Script for Security Center
# Checks dependencies and system readiness for building packages

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

ok() { echo -e "  ${GREEN}✓${NC} $1"; }
fail() { echo -e "  ${RED}✗${NC} $1"; ERRORS=$((ERRORS+1)); }
warn() { echo -e "  ${YELLOW}!${NC} $1"; }

ERRORS=0

echo "=== Security Center Build Environment Check ==="
echo ""

# Rust toolchain
echo "Rust Toolchain:"
if command -v rustc &> /dev/null; then
    ok "rustc $(rustc --version | cut -d' ' -f2)"
else
    fail "rustc not found"
fi

if command -v cargo &> /dev/null; then
    ok "cargo $(cargo --version | cut -d' ' -f2)"
else
    fail "cargo not found"
fi

# GTK4 development libraries
echo ""
echo "GTK4/Libadwaita Development Libraries:"
if pkg-config --exists gtk4 2>/dev/null; then
    ok "gtk4 $(pkg-config --modversion gtk4)"
else
    fail "gtk4-devel not found (install: sudo dnf install gtk4-devel)"
fi

if pkg-config --exists libadwaita-1 2>/dev/null; then
    ok "libadwaita $(pkg-config --modversion libadwaita-1)"
else
    fail "libadwaita-devel not found (install: sudo dnf install libadwaita-devel)"
fi

# GResource compiler
echo ""
echo "Build Tools:"
if command -v glib-compile-resources &> /dev/null; then
    ok "glib-compile-resources"
else
    fail "glib-compile-resources not found (install: sudo dnf install glib2-devel)"
fi

# Cargo packaging tools
echo ""
echo "Cargo Packaging Tools:"
if command -v cargo-deb &> /dev/null; then
    ok "cargo-deb"
else
    warn "cargo-deb not installed (will be auto-installed)"
fi

if command -v cargo-generate-rpm &> /dev/null; then
    ok "cargo-generate-rpm"
else
    warn "cargo-generate-rpm not installed (will be auto-installed)"
fi

# AppImage tools
echo ""
echo "AppImage Tools:"
if command -v wget &> /dev/null; then
    ok "wget"
else
    fail "wget not found (needed to download appimagetool)"
fi

if command -v rsvg-convert &> /dev/null; then
    ok "rsvg-convert (for icon conversion)"
else
    warn "rsvg-convert not found (optional, for PNG icon generation)"
fi

# Native packaging tools
echo ""
echo "Native Packaging Tools (optional):"
if command -v rpmbuild &> /dev/null; then
    ok "rpmbuild"
else
    warn "rpmbuild not found (install: sudo dnf install rpm-build)"
fi

if command -v dpkg-buildpackage &> /dev/null; then
    ok "dpkg-buildpackage"
else
    warn "dpkg-buildpackage not found (Debian/Ubuntu only)"
fi

# Summary
echo ""
echo "=== Summary ==="
if [ $ERRORS -eq 0 ]; then
    echo -e "${GREEN}All required dependencies are installed!${NC}"
    exit 0
else
    echo -e "${RED}$ERRORS required dependencies are missing.${NC}"
    exit 1
fi
