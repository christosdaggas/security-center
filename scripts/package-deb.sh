#!/bin/bash
# DEB Package Build Script for Security Center
# Output: dist/deb/

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
VERSION="1.7.0"
APP_NAME="security-center"

cd "$PROJECT_DIR"

echo "==> Building DEB package..."

# Check for cargo-deb
if ! command -v cargo-deb &> /dev/null; then
    echo "[WARN] cargo-deb not found. Installing..."
    cargo install cargo-deb
fi

# Ensure release binary exists
if [ ! -f "$PROJECT_DIR/target/release/$APP_NAME" ]; then
    echo "[INFO] Building release binary..."
    cargo build --release
fi

# Compile translation catalogs (.mo) so cargo-deb can package them.
# The paths are listed in [package.metadata.deb].assets in Cargo.toml.
if ! command -v msgfmt &> /dev/null; then
    echo "[ERROR] msgfmt not found. Install gettext to build translation catalogs."
    exit 1
fi
echo "[INFO] Compiling translation catalogs..."
while IFS= read -r LANG_CODE; do
    [ -z "$LANG_CODE" ] && continue
    mkdir -p "$PROJECT_DIR/target/locale/$LANG_CODE/LC_MESSAGES"
    msgfmt "$PROJECT_DIR/po/$LANG_CODE.po" \
        -o "$PROJECT_DIR/target/locale/$LANG_CODE/LC_MESSAGES/$APP_NAME.mo"
done < "$PROJECT_DIR/po/LINGUAS"

# Build DEB package
cargo deb --no-build

# Copy to dist/deb
mkdir -p "$PROJECT_DIR/dist/deb"
DEB_FILE=$(ls -t target/debian/*.deb 2>/dev/null | head -1)
if [ -n "$DEB_FILE" ]; then
    cp "$DEB_FILE" "$PROJECT_DIR/dist/deb/"
    echo "[INFO] DEB package created: dist/deb/$(basename "$DEB_FILE")"
    
    # Show package info
    dpkg-deb --info "$PROJECT_DIR/dist/deb/$(basename "$DEB_FILE")" 2>/dev/null || true
else
    echo "[ERROR] Failed to create DEB package"
    exit 1
fi
