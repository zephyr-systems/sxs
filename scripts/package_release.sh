#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
  echo "Usage: $0 <version>"
  echo "Example: $0 0.1.0"
  exit 1
fi

ARCH="$(uname -m)"
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
TARGET="${OS}-${ARCH}"
PKG_NAME="sxs-${VERSION}-${TARGET}"
DIST_DIR="$ROOT_DIR/dist"
STAGE_DIR="$DIST_DIR/$PKG_NAME"
TARBALL="$DIST_DIR/${PKG_NAME}.tar.gz"
SHA_FILE="$DIST_DIR/${PKG_NAME}.sha256"

mkdir -p "$DIST_DIR"
rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR"

echo "[1/4] Building sxs and bundling tree-sitter libs"
make build

echo "[2/4] Staging release files into $STAGE_DIR"
cp "$ROOT_DIR/sxs" "$STAGE_DIR/"
cp "$ROOT_DIR/libtree-sitter-"*.dylib "$STAGE_DIR/"
cp "$ROOT_DIR/README.md" "$STAGE_DIR/"
cp "$ROOT_DIR/LICENSE" "$STAGE_DIR/"
cp "$ROOT_DIR/docs/sxs.1" "$STAGE_DIR/"

echo "[3/4] Creating tarball $TARBALL"
rm -f "$TARBALL" "$SHA_FILE"
tar -czf "$TARBALL" -C "$DIST_DIR" "$PKG_NAME"

echo "[4/4] Writing checksum $SHA_FILE"
shasum -a 256 "$TARBALL" | awk '{print $1}' > "$SHA_FILE"

echo ""
echo "Release artifact created:"
echo "  $TARBALL"
echo "Checksum file:"
echo "  $SHA_FILE"
echo "SHA256:"
cat "$SHA_FILE"
