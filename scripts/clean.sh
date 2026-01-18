#!/bin/bash
# Clean Script for Security Center
# Safely removes build outputs

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

echo "==> Cleaning build artifacts..."

# Clean dist directory
rm -rf "$PROJECT_DIR/dist"

# Clean cargo build artifacts
cargo clean 2>/dev/null || true

# Clean packaging artifacts
rm -rf "$PROJECT_DIR/target/appimage"
rm -rf "$PROJECT_DIR/target/debian"
rm -rf "$PROJECT_DIR/target/generate-rpm"
rm -rf "$PROJECT_DIR/target/rpmbuild"
rm -rf "$PROJECT_DIR/debian"

echo "[INFO] Clean complete"
