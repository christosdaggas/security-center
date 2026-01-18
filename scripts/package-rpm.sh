#!/bin/bash
# RPM Package Build Script for Security Center
# Output: dist/rpm/

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
VERSION="1.0.0"
APP_NAME="security-center"

cd "$PROJECT_DIR"

echo "==> Building RPM package..."

# Check for cargo-generate-rpm
if ! command -v cargo-generate-rpm &> /dev/null; then
    echo "[WARN] cargo-generate-rpm not found. Installing..."
    cargo install cargo-generate-rpm
fi

# Ensure release binary exists
if [ ! -f "$PROJECT_DIR/target/release/$APP_NAME" ]; then
    echo "[INFO] Building release binary..."
    cargo build --release
fi

# Strip the binary
strip --strip-all "$PROJECT_DIR/target/release/$APP_NAME" 2>/dev/null || true

# Generate RPM
cargo generate-rpm

# Copy to dist/rpm
mkdir -p "$PROJECT_DIR/dist/rpm"
RPM_FILE=$(ls -t target/generate-rpm/*.rpm 2>/dev/null | head -1)
if [ -n "$RPM_FILE" ]; then
    cp "$RPM_FILE" "$PROJECT_DIR/dist/rpm/"
    echo "[INFO] RPM package created: dist/rpm/$(basename "$RPM_FILE")"
    
    # Show package info
    rpm -qip "$PROJECT_DIR/dist/rpm/$(basename "$RPM_FILE")" 2>/dev/null || true
else
    echo "[ERROR] Failed to create RPM package"
    exit 1
fi
