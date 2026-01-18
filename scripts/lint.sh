#!/bin/bash
# Lint Script for Security Center
# Runs formatting and clippy checks

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

ERRORS=0

echo "==> Running cargo fmt check..."
if cargo fmt --check 2>&1; then
    echo "[OK] Code formatting is correct"
else
    echo "[WARN] Code formatting issues found. Run 'cargo fmt' to fix."
    ERRORS=$((ERRORS+1))
fi

echo ""
echo "==> Running cargo clippy..."
if cargo clippy --release -- -D warnings 2>&1; then
    echo "[OK] No clippy warnings"
else
    echo "[WARN] Clippy warnings found"
    ERRORS=$((ERRORS+1))
fi

echo ""
if [ $ERRORS -eq 0 ]; then
    echo "=== All lint checks passed! ==="
    exit 0
else
    echo "=== $ERRORS lint check(s) had issues ==="
    exit 1
fi
