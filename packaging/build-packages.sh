#!/bin/bash
# Build script for creating .deb, .rpm, and .appimage packages
# Usage: ./packaging/build-packages.sh [deb|rpm|appimage|all]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
VERSION="1.4.0"
APP_NAME="security-center"
APP_ID="com.chrisdaggas.security-center"

cd "$PROJECT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

step() {
    echo -e "${BLUE}==>${NC} $1"
}

check_command() {
    if ! command -v "$1" &> /dev/null; then
        return 1
    fi
    return 0
}

build_release() {
    step "Building release binary..."
    cargo build --release
    info "Release binary built successfully"
    ls -lh "$PROJECT_DIR/target/release/$APP_NAME"
}

# =============================================================================
# DEB PACKAGE
# =============================================================================
build_deb() {
    step "Building .deb package..."
    
    if ! check_command cargo-deb; then
        warn "cargo-deb not found. Installing..."
        cargo install cargo-deb
    fi
    
    # Build the package
    cargo deb --no-build
    
    DEB_FILE=$(ls -t target/debian/*.deb 2>/dev/null | head -1)
    if [ -n "$DEB_FILE" ]; then
        mkdir -p "$PROJECT_DIR/dist/deb"
        cp "$DEB_FILE" "$PROJECT_DIR/dist/deb/"
        info "DEB package created: dist/deb/$(basename "$DEB_FILE")"
        echo ""
        dpkg-deb --info "$PROJECT_DIR/dist/deb/$(basename "$DEB_FILE")" 2>/dev/null || true
    else
        error "Failed to create .deb package"
    fi
}

build_deb_native() {
    step "Building .deb package (native dpkg-buildpackage)..."
    
    if ! check_command dpkg-buildpackage; then
        error "dpkg-buildpackage not found. Install: sudo apt install dpkg-dev debhelper"
    fi
    
    rm -rf "$PROJECT_DIR/debian"
    cp -r "$PROJECT_DIR/packaging/deb" "$PROJECT_DIR/debian"
    chmod +x "$PROJECT_DIR/debian/rules"
    
    dpkg-buildpackage -us -uc -b
    
    mkdir -p "$PROJECT_DIR/dist/deb"
    mv "$PROJECT_DIR/../${APP_NAME}_${VERSION}"*.deb "$PROJECT_DIR/dist/deb/" 2>/dev/null || true
    mv "$PROJECT_DIR/../${APP_NAME}_${VERSION}"*.buildinfo "$PROJECT_DIR/dist/deb/" 2>/dev/null || true
    mv "$PROJECT_DIR/../${APP_NAME}_${VERSION}"*.changes "$PROJECT_DIR/dist/deb/" 2>/dev/null || true
    rm -rf "$PROJECT_DIR/debian"
    
    DEB_FILE=$(ls -t "$PROJECT_DIR/dist/deb/"*.deb 2>/dev/null | head -1)
    if [ -n "$DEB_FILE" ]; then
        info "DEB package created: $DEB_FILE"
    else
        error "Failed to create .deb package"
    fi
}

# =============================================================================
# RPM PACKAGE
# =============================================================================
build_rpm() {
    step "Building .rpm package..."
    
    if ! check_command cargo-generate-rpm; then
        warn "cargo-generate-rpm not found. Installing..."
        cargo install cargo-generate-rpm
    fi
    
    strip --strip-all "$PROJECT_DIR/target/release/$APP_NAME" 2>/dev/null || true
    cargo generate-rpm
    
    RPM_FILE=$(ls -t target/generate-rpm/*.rpm 2>/dev/null | head -1)
    if [ -n "$RPM_FILE" ]; then
        mkdir -p "$PROJECT_DIR/dist/rpm"
        cp "$RPM_FILE" "$PROJECT_DIR/dist/rpm/"
        info "RPM package created: dist/rpm/$(basename "$RPM_FILE")"
        echo ""
        rpm -qip "$PROJECT_DIR/dist/rpm/$(basename "$RPM_FILE")" 2>/dev/null || true
    else
        error "Failed to create .rpm package"
    fi
}

build_rpm_native() {
    step "Building .rpm package (native rpmbuild)..."
    
    if ! check_command rpmbuild; then
        error "rpmbuild not found. Install: sudo dnf install rpm-build rpmdevtools"
    fi
    
    RPMBUILD_DIR="$PROJECT_DIR/target/rpmbuild"
    mkdir -p "$RPMBUILD_DIR"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
    cp "$PROJECT_DIR/packaging/rpm/security-center.spec" "$RPMBUILD_DIR/SPECS/"
    
    tar -czf "$RPMBUILD_DIR/SOURCES/${APP_NAME}-${VERSION}.tar.gz" \
        --transform "s,^,${APP_NAME}-${VERSION}/," \
        --exclude='target' --exclude='.git' --exclude='dist' \
        -C "$PROJECT_DIR" .
    
    rpmbuild --define "_topdir $RPMBUILD_DIR" -bb "$RPMBUILD_DIR/SPECS/security-center.spec"
    
    mkdir -p "$PROJECT_DIR/dist/rpm"
    find "$RPMBUILD_DIR/RPMS" -name "*.rpm" -exec cp {} "$PROJECT_DIR/dist/rpm/" \;
    
    RPM_FILE=$(ls -t "$PROJECT_DIR/dist/rpm/"*.rpm 2>/dev/null | head -1)
    if [ -n "$RPM_FILE" ]; then
        info "RPM package created: $RPM_FILE"
    else
        error "Failed to create .rpm package"
    fi
}

# =============================================================================
# APPIMAGE
# =============================================================================
build_appimage() {
    step "Building AppImage..."
    
    WORK_DIR="$PROJECT_DIR/target/appimage"
    APPDIR="$WORK_DIR/AppDir"
    APPIMAGE_NAME="Security_Center-${VERSION}-x86_64.AppImage"
    
    # Clean and create directories
    rm -rf "$WORK_DIR"
    mkdir -p "$APPDIR/usr/bin"
    mkdir -p "$APPDIR/usr/lib"
    mkdir -p "$APPDIR/usr/share/applications"
    mkdir -p "$APPDIR/usr/share/metainfo"
    mkdir -p "$APPDIR/usr/share/icons/hicolor/256x256/apps"
    mkdir -p "$APPDIR/usr/share/icons/hicolor/256x256/apps"
    mkdir -p "$APPDIR/usr/share/icons/hicolor/scalable/apps"
    mkdir -p "$PROJECT_DIR/dist/appimage"
    
    # Copy binary
    cp "$PROJECT_DIR/target/release/$APP_NAME" "$APPDIR/usr/bin/"
    strip --strip-all "$APPDIR/usr/bin/$APP_NAME" 2>/dev/null || true
    
    # Copy desktop file to root and usr/share
    cp "$PROJECT_DIR/data/${APP_ID}.desktop" "$APPDIR/"
    cp "$PROJECT_DIR/data/${APP_ID}.desktop" "$APPDIR/usr/share/applications/"
    sed -i 's|Exec=security-center|Exec=security-center %U|g' "$APPDIR/${APP_ID}.desktop"
    
    # Copy metainfo file
    cp "$PROJECT_DIR/data/${APP_ID}.metainfo.xml" "$APPDIR/usr/share/metainfo/"
    
    # Copy icon to root and proper locations
    cp "$PROJECT_DIR/data/icons/hicolor/scalable/apps/${APP_ID}.svg" "$APPDIR/${APP_ID}.svg"
    cp "$PROJECT_DIR/data/icons/hicolor/scalable/apps/${APP_ID}.svg" "$APPDIR/usr/share/icons/hicolor/scalable/apps/"
    cp "$PROJECT_DIR/data/icons/hicolor/scalable/apps/${APP_ID}.svg" "$APPDIR/.DirIcon"
    
    # Generate PNG icon if rsvg-convert is available
    if check_command rsvg-convert; then
        rsvg-convert -w 256 -h 256 \
            "$PROJECT_DIR/data/icons/hicolor/scalable/apps/${APP_ID}.svg" \
            -o "$APPDIR/usr/share/icons/hicolor/256x256/apps/${APP_ID}.png"
    fi
    
    # Create AppRun script
    cat > "$APPDIR/AppRun" << 'APPRUN_EOF'
#!/bin/bash
SELF="$(readlink -f "$0")"
APPDIR="${SELF%/*}"

export PATH="${APPDIR}/usr/bin:${PATH}"
export LD_LIBRARY_PATH="${APPDIR}/usr/lib:${LD_LIBRARY_PATH}"
export XDG_DATA_DIRS="${APPDIR}/usr/share:${XDG_DATA_DIRS:-/usr/local/share:/usr/share}"
export GSETTINGS_SCHEMA_DIR="${APPDIR}/usr/share/glib-2.0/schemas:${GSETTINGS_SCHEMA_DIR}"
export GTK_USE_PORTAL=1

exec "${APPDIR}/usr/bin/security-center" "$@"
APPRUN_EOF
    chmod +x "$APPDIR/AppRun"
    
    # Download appimagetool if not present
    APPIMAGETOOL="$WORK_DIR/appimagetool-x86_64.AppImage"
    if [ ! -f "$APPIMAGETOOL" ]; then
        info "Downloading appimagetool..."
        wget -q --show-progress \
            "https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-x86_64.AppImage" \
            -O "$APPIMAGETOOL"
        chmod +x "$APPIMAGETOOL"
    fi
    
    export APPIMAGE_EXTRACT_AND_RUN=1
    
    # Create AppImage
    info "Generating AppImage..."
    cd "$WORK_DIR"
    ARCH=x86_64 "$APPIMAGETOOL" --no-appstream AppDir "$PROJECT_DIR/dist/appimage/$APPIMAGE_NAME"
    
    if [ -f "$PROJECT_DIR/dist/appimage/$APPIMAGE_NAME" ]; then
        chmod +x "$PROJECT_DIR/dist/appimage/$APPIMAGE_NAME"
        info "AppImage created: dist/appimage/$APPIMAGE_NAME"
        ls -lh "$PROJECT_DIR/dist/appimage/$APPIMAGE_NAME"
    else
        error "Failed to create AppImage"
    fi
}

# =============================================================================
# HELP AND MAIN
# =============================================================================
show_help() {
    echo "Build script for Security Center packages"
    echo ""
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  deb           Build .deb package using cargo-deb"
    echo "  deb-native    Build .deb package using dpkg-buildpackage"
    echo "  rpm           Build .rpm package using cargo-generate-rpm"
    echo "  rpm-native    Build .rpm package using rpmbuild"
    echo "  appimage      Build AppImage"
    echo "  all           Build deb, rpm, and appimage packages"
    echo "  clean         Remove dist directory and build artifacts"
    echo "  help          Show this help message"
    echo ""
    echo "Prerequisites:"
    echo "  - Rust toolchain (cargo, rustc >= 1.70)"
    echo "  - cargo-deb (auto-installed if missing)"
    echo "  - cargo-generate-rpm (auto-installed if missing)"
    echo "  - wget (for AppImage tool download)"
    echo ""
    echo "Output:"
    echo "  dist/deb/       - Debian packages"
    echo "  dist/rpm/       - RPM packages"
    echo "  dist/appimage/  - AppImage files"
}

show_summary() {
    echo ""
    echo "========================================"
    echo "        Build Summary"
    echo "========================================"
    echo ""
    if [ -d "$PROJECT_DIR/dist" ]; then
        find "$PROJECT_DIR/dist" -type f \( -name "*.deb" -o -name "*.rpm" -o -name "*.AppImage" \) \
            -exec ls -lh {} \; 2>/dev/null || echo "  No packages found"
    else
        echo "  No packages found"
    fi
    echo ""
}

clean() {
    step "Cleaning build artifacts..."
    rm -rf "$PROJECT_DIR/dist"
    rm -rf "$PROJECT_DIR/target/appimage"
    rm -rf "$PROJECT_DIR/target/debian"
    rm -rf "$PROJECT_DIR/target/generate-rpm"
    rm -rf "$PROJECT_DIR/target/rpmbuild"
    rm -rf "$PROJECT_DIR/debian"
    info "Clean complete"
}

# Main
case "${1:-help}" in
    deb)
        build_release
        build_deb
        show_summary
        ;;
    deb-native)
        build_release
        build_deb_native
        show_summary
        ;;
    rpm)
        build_release
        build_rpm
        show_summary
        ;;
    rpm-native)
        build_release
        build_rpm_native
        show_summary
        ;;
    appimage)
        build_release
        build_appimage
        show_summary
        ;;
    all)
        build_release
        echo ""
        build_deb
        echo ""
        build_rpm
        echo ""
        build_appimage
        echo ""
        info "All packages built successfully!"
        show_summary
        ;;
    clean)
        clean
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        error "Unknown command: $1"
        show_help
        exit 1
        ;;
esac
