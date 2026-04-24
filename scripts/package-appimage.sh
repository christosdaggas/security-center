#!/bin/bash
# AppImage Package Build Script for Security Center
# Output: dist/appimage/

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
VERSION="1.6.0"
APP_NAME="security-center"
APP_ID="com.chrisdaggas.security-center"
ARCH="$(uname -m)"
APPIMAGE_NAME="Security_Center-${VERSION}-${ARCH}.AppImage"

cd "$PROJECT_DIR"

echo "==> Building AppImage for ${ARCH}..."

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
mkdir -p "$APPDIR/usr/share/icons/hicolor/symbolic/apps"
mkdir -p "$APPDIR/usr/share/glib-2.0/schemas"
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
cp "$PROJECT_DIR/data/icons/hicolor/symbolic/apps/${APP_ID}-symbolic.svg" "$APPDIR/usr/share/icons/hicolor/symbolic/apps/"
cp "$PROJECT_DIR/data/icons/hicolor/scalable/apps/${APP_ID}.svg" "$APPDIR/.DirIcon"

# Generate PNG icon if rsvg-convert is available
if command -v rsvg-convert &> /dev/null; then
    rsvg-convert -w 256 -h 256 \
        "$PROJECT_DIR/data/icons/hicolor/scalable/apps/${APP_ID}.svg" \
        -o "$APPDIR/usr/share/icons/hicolor/256x256/apps/${APP_ID}.png"
fi

# Bundle required shared libraries
echo "[INFO] Bundling shared libraries..."
BINARY="$APPDIR/usr/bin/$APP_NAME"

# Collect all required shared libraries (excluding glibc/ld-linux which must come from host)
ldd "$BINARY" | grep "=> /" | awk '{print $3}' | while read -r lib; do
    # Skip glibc, ld-linux, and other base system libraries that must match the host
    case "$(basename "$lib")" in
        libc.so*|libm.so*|libdl.so*|librt.so*|libpthread.so*|ld-linux*|libstdc++*) continue ;;
    esac
    cp -n "$lib" "$APPDIR/usr/lib/" 2>/dev/null || true
done

# Bundle GDK-Pixbuf loaders
PIXBUF_DIR=$(pkg-config --variable=gdk_pixbuf_moduledir gdk-pixbuf-2.0 2>/dev/null || echo "")
if [ -n "$PIXBUF_DIR" ] && [ -d "$PIXBUF_DIR" ]; then
    mkdir -p "$APPDIR/usr/lib/gdk-pixbuf-2.0/2.10.0/loaders"
    cp -r "$PIXBUF_DIR"/*.so "$APPDIR/usr/lib/gdk-pixbuf-2.0/2.10.0/loaders/" 2>/dev/null || true
    # Generate loaders cache for the bundled path
    GDK_PIXBUF_MODULEDIR="$APPDIR/usr/lib/gdk-pixbuf-2.0/2.10.0/loaders" \
        gdk-pixbuf-query-loaders > "$APPDIR/usr/lib/gdk-pixbuf-2.0/2.10.0/loaders.cache" 2>/dev/null || true
fi

# Bundle GLib schemas
SCHEMAS_DIR=$(pkg-config --variable=schemasdir gio-2.0 2>/dev/null || echo "/usr/share/glib-2.0/schemas")
if [ -d "$SCHEMAS_DIR" ]; then
    cp "$SCHEMAS_DIR"/org.gtk.* "$APPDIR/usr/share/glib-2.0/schemas/" 2>/dev/null || true
    cp "$SCHEMAS_DIR"/org.gnome.desktop.interface.gschema.xml "$APPDIR/usr/share/glib-2.0/schemas/" 2>/dev/null || true
    glib-compile-schemas "$APPDIR/usr/share/glib-2.0/schemas/" 2>/dev/null || true
fi

echo "[INFO] Bundled $(ls "$APPDIR/usr/lib/"*.so* 2>/dev/null | wc -l) shared libraries"

# Create AppRun script
cat > "$APPDIR/AppRun" << 'APPRUN_EOF'
#!/bin/bash
SELF="$(readlink -f "$0")"
APPDIR="${SELF%/*}"

export PATH="${APPDIR}/usr/bin:${PATH}"
export LD_LIBRARY_PATH="${APPDIR}/usr/lib:${LD_LIBRARY_PATH}"
export XDG_DATA_DIRS="${APPDIR}/usr/share:${XDG_DATA_DIRS:-/usr/local/share:/usr/share}"
export GSETTINGS_SCHEMA_DIR="${APPDIR}/usr/share/glib-2.0/schemas:${GSETTINGS_SCHEMA_DIR}"
export GDK_PIXBUF_MODULE_FILE="${APPDIR}/usr/lib/gdk-pixbuf-2.0/2.10.0/loaders.cache"
export GTK_USE_PORTAL=1

exec "${APPDIR}/usr/bin/security-center" "$@"
APPRUN_EOF
chmod +x "$APPDIR/AppRun"

# Download appimagetool if not present
# Pinned to a specific release for reproducibility.
# Update APPIMAGETOOL_URL and APPIMAGETOOL_SHA256 when upgrading.
APPIMAGETOOL_URL="https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-${ARCH}.AppImage"
APPIMAGETOOL_SHA256="" # Set this to the known SHA256 of the pinned release
APPIMAGETOOL="$WORK_DIR/appimagetool-${ARCH}.AppImage"
if [ ! -f "$APPIMAGETOOL" ]; then
    echo "[INFO] Downloading appimagetool for ${ARCH}..."
    wget -q --show-progress \
        "$APPIMAGETOOL_URL" \
        -O "$APPIMAGETOOL"
    chmod +x "$APPIMAGETOOL"

    if [ -n "$APPIMAGETOOL_SHA256" ]; then
        echo "[INFO] Verifying appimagetool checksum..."
        echo "$APPIMAGETOOL_SHA256  $APPIMAGETOOL" | sha256sum -c - || {
            echo "[ERROR] appimagetool checksum verification failed"
            rm -f "$APPIMAGETOOL"
            exit 1
        }
    else
        echo "[WARN] APPIMAGETOOL_SHA256 is not set; skipping checksum verification"
    fi
fi

export APPIMAGE_EXTRACT_AND_RUN=1

# Create AppImage
echo "[INFO] Generating AppImage..."
cd "$WORK_DIR"
ARCH="$ARCH" "$APPIMAGETOOL" --no-appstream AppDir "$PROJECT_DIR/dist/appimage/$APPIMAGE_NAME"

if [ -f "$PROJECT_DIR/dist/appimage/$APPIMAGE_NAME" ]; then
    chmod +x "$PROJECT_DIR/dist/appimage/$APPIMAGE_NAME"
    echo "[INFO] AppImage created: dist/appimage/$APPIMAGE_NAME"
    ls -lh "$PROJECT_DIR/dist/appimage/$APPIMAGE_NAME"
else
    echo "[ERROR] Failed to create AppImage"
    exit 1
fi
