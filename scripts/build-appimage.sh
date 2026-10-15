#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$(readlink -f "$0")")/.."
arch=$(uname -m)
tools="$PWD/target/appimage-tools"
mkdir -p "$tools" "$PWD/target/appimage"

download() {
    if [[ ! -x "$2" ]]; then
        curl --fail --location --retry 3 "$1" --output "$2.tmp"
        chmod +x "$2.tmp"
        mv "$2.tmp" "$2"
    fi
}

download "https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous/linuxdeploy-$arch.AppImage" \
    "$tools/linuxdeploy-$arch.AppImage"

cargo build --locked --release -p pkg-gtk
version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' crates/pkg-gtk/Cargo.toml)
test -n "$version"

# Use a fresh staging directory so removed dependencies cannot leak into releases.
appdir=$(mktemp -d "$PWD/target/appimage/AppDir.XXXXXX")
trap 'rm -rf "$appdir"' EXIT
mkdir -p "$appdir/usr/share/icons"
cp -a /usr/share/icons/Adwaita "$appdir/usr/share/icons/"
mkdir -p "$appdir/usr/share/glib-2.0/schemas"
cp /usr/share/glib-2.0/schemas/org.gtk.gtk4.*.xml \
    "$appdir/usr/share/glib-2.0/schemas/"
glib-compile-schemas "$appdir/usr/share/glib-2.0/schemas"

export PATH="$tools:$PATH"
export APPIMAGE_EXTRACT_AND_RUN=1
export VERSION="$version"
export OUTPUT="$PWD/target/appimage/PKG_Tools-$version-$arch.AppImage"
"$tools/linuxdeploy-$arch.AppImage" \
    --appdir "$appdir" \
    --executable "$PWD/target/release/pkg-gtk" \
    --desktop-file "$PWD/crates/pkg-gtk/data/io.github.pkg_tools.PkgTools.desktop" \
    --icon-file /usr/share/icons/Adwaita/scalable/mimetypes/package-x-generic.svg \
    --custom-apprun "$PWD/scripts/appimage/AppRun" \
    --output appimage

test -x "$OUTPUT"
cd "$(dirname "$OUTPUT")"
sha256sum "$(basename "$OUTPUT")" > "$(basename "$OUTPUT").sha256"
printf 'Created %s\n' "$OUTPUT"
