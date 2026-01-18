#!/bin/bash
# AppImage Package Build Script for Security Center
# Output: dist/appimage/

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
VERSION="1.0.0"
APP_NAME="security-center"
APP_ID="com.chrisdaggas.security-center"
APPIMAGE_NAME="Security_Center-${VERSION}-x86_64.AppImage"

cd "$PROJECT_DIR"

echo "==> Building AppImage..."

# Ensure release binary exists
if [ ! -f "$PROJECT_DIR/target/release/$APP_NAME" ]; then
    echo "[INFO] Building release binary..."
    cargo build --release
fi

WORK_DIR="$PROJECT_DIR/target/appimage"
APPDIR="$WORK_DIR/AppDir"

# Clean and create directories
rm -rf "$WORK_DIR"
mkdir -p "$APPDIR/usr/bin"
mkdir -p "$APPDIR/usr/lib"
mkdir -p "$APPDIR/usr/share/applications"
mkdir -p "$APPDIR/usr/share/metainfo"
mkdir -p "$APPDIR/usr/share/icons/hicolor/256x256/apps"
mkdir -p "$APPDIR/usr/share/icons/hicolor/scalable/apps"
mkdir -p "$PROJECT_DIR/dist/appimage"

# Copy binary
cp "$PROJECT_DIR/target/release/$APP_NAME" "$APPDIR/usr/bin/"
strip --strip-all "$APPDIR/usr/bin/$APP_NAME" 2>/dev/null || true

# Copy desktop file
cp "$PROJECT_DIR/data/${APP_ID}.desktop" "$APPDIR/"
cp "$PROJECT_DIR/data/${APP_ID}.desktop" "$APPDIR/usr/share/applications/"
sed -i 's|Exec=security-center|Exec=security-center %U|g' "$APPDIR/${APP_ID}.desktop"

# Copy metainfo
cp "$PROJECT_DIR/data/${APP_ID}.metainfo.xml" "$APPDIR/usr/share/metainfo/"

# Copy icons
cp "$PROJECT_DIR/data/icons/hicolor/scalable/apps/${APP_ID}.svg" "$APPDIR/${APP_ID}.svg"
cp "$PROJECT_DIR/data/icons/hicolor/scalable/apps/${APP_ID}.svg" "$APPDIR/usr/share/icons/hicolor/scalable/apps/"
cp "$PROJECT_DIR/data/icons/hicolor/scalable/apps/${APP_ID}.svg" "$APPDIR/.DirIcon"

# Generate PNG icon if rsvg-convert is available
if command -v rsvg-convert &> /dev/null; then
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
    echo "[INFO] Downloading appimagetool..."
    wget -q --show-progress \
        "https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-x86_64.AppImage" \
        -O "$APPIMAGETOOL"
    chmod +x "$APPIMAGETOOL"
fi

export APPIMAGE_EXTRACT_AND_RUN=1

# Create AppImage
echo "[INFO] Generating AppImage..."
cd "$WORK_DIR"
ARCH=x86_64 "$APPIMAGETOOL" --no-appstream AppDir "$PROJECT_DIR/dist/appimage/$APPIMAGE_NAME"

if [ -f "$PROJECT_DIR/dist/appimage/$APPIMAGE_NAME" ]; then
    chmod +x "$PROJECT_DIR/dist/appimage/$APPIMAGE_NAME"
    echo "[INFO] AppImage created: dist/appimage/$APPIMAGE_NAME"
    ls -lh "$PROJECT_DIR/dist/appimage/$APPIMAGE_NAME"
else
    echo "[ERROR] Failed to create AppImage"
    exit 1
fi
