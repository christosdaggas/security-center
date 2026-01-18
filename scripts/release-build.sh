#!/bin/bash
# Release Build Script for Security Center
# Builds all packages: RPM, DEB, and AppImage
# Output: dist/rpm/, dist/deb/, dist/appimage/

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
VERSION="1.0.0"
APP_NAME="security-center"
APP_ID="com.chrisdaggas.security-center"

cd "$PROJECT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
step() { echo -e "${BLUE}==>${NC} $1"; }

# Create dist directories
mkdir -p "$PROJECT_DIR/dist"/{rpm,deb,appimage,build-logs}

# Build release binary
step "Building release binary..."
cargo build --release 2>&1 | tee "$PROJECT_DIR/dist/build-logs/cargo-build.log"
info "Release binary: target/release/$APP_NAME"

# Generate checksums and manifest
generate_artifacts() {
    step "Generating checksums and manifest..."
    
    cd "$PROJECT_DIR/dist"
    
    # Generate SHA256 checksums
    find rpm deb appimage -type f \( -name "*.rpm" -o -name "*.deb" -o -name "*.AppImage" \) \
        -exec sha256sum {} \; > checksums.txt 2>/dev/null || true
    
    # Generate manifest
    cat > manifest.json << EOF
{
    "app_name": "$APP_NAME",
    "app_id": "$APP_ID",
    "version": "$VERSION",
    "build_timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
    "build_host": "$(hostname)",
    "git_commit": "$(git rev-parse HEAD 2>/dev/null || echo 'unknown')",
    "rust_version": "$(rustc --version)",
    "cargo_version": "$(cargo --version)",
    "artifacts": {
        "rpm": $(ls rpm/*.rpm 2>/dev/null | jq -R -s -c 'split("\n") | map(select(length > 0))' || echo '[]'),
        "deb": $(ls deb/*.deb 2>/dev/null | jq -R -s -c 'split("\n") | map(select(length > 0))' || echo '[]'),
        "appimage": $(ls appimage/*.AppImage 2>/dev/null | jq -R -s -c 'split("\n") | map(select(length > 0))' || echo '[]')
    }
}
EOF
    
    cd "$PROJECT_DIR"
    info "Checksums: dist/checksums.txt"
    info "Manifest: dist/manifest.json"
}

# Show summary
show_summary() {
    echo ""
    echo "========================================"
    echo "        Build Summary"
    echo "========================================"
    echo ""
    if [ -d "$PROJECT_DIR/dist" ]; then
        echo "RPM packages:"
        ls -lh "$PROJECT_DIR/dist/rpm/"*.rpm 2>/dev/null || echo "  (none)"
        echo ""
        echo "DEB packages:"
        ls -lh "$PROJECT_DIR/dist/deb/"*.deb 2>/dev/null || echo "  (none)"
        echo ""
        echo "AppImage packages:"
        ls -lh "$PROJECT_DIR/dist/appimage/"*.AppImage 2>/dev/null || echo "  (none)"
    fi
    echo ""
}

# Main
case "${1:-all}" in
    rpm)
        "$SCRIPT_DIR/package-rpm.sh"
        generate_artifacts
        show_summary
        ;;
    deb)
        "$SCRIPT_DIR/package-deb.sh"
        generate_artifacts
        show_summary
        ;;
    appimage)
        "$SCRIPT_DIR/package-appimage.sh"
        generate_artifacts
        show_summary
        ;;
    all)
        "$SCRIPT_DIR/package-deb.sh" 2>&1 | tee "$PROJECT_DIR/dist/build-logs/deb.log" || warn "DEB build failed"
        "$SCRIPT_DIR/package-rpm.sh" 2>&1 | tee "$PROJECT_DIR/dist/build-logs/rpm.log" || warn "RPM build failed"
        "$SCRIPT_DIR/package-appimage.sh" 2>&1 | tee "$PROJECT_DIR/dist/build-logs/appimage.log" || warn "AppImage build failed"
        generate_artifacts
        info "All packages built!"
        show_summary
        ;;
    *)
        echo "Usage: $0 [rpm|deb|appimage|all]"
        exit 1
        ;;
esac
