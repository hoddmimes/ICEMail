#!/bin/bash
#
# Build the ICEMail self-extracting installers using makeself.
# Produces two .run files — one for the server, one for the bridge.
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if ! command -v makeself &>/dev/null; then
    echo "ERROR: makeself is not installed. Install it with: sudo apt install makeself"
    exit 1
fi

VERSION="$(jq -r .version "$SCRIPT_DIR/version.json")"
if [ -z "$VERSION" ] || [ "$VERSION" = "null" ]; then
    echo "ERROR: could not read version from version.json"
    exit 1
fi

# ─── Server installer ─────────────────────────────────────────────────────────
echo "Building server installer (version $VERSION)..."
cp "$SCRIPT_DIR/install_server.sh" "$SCRIPT_DIR/release/server/"

makeself "$SCRIPT_DIR/release/server" \
         "$SCRIPT_DIR/ice-server-installer-${VERSION}.run" \
         "ICEMail Server Installer" \
         ./install_server.sh

echo "Created: $SCRIPT_DIR/ice-server-installer-${VERSION}.run"

# ─── Bridge installer ─────────────────────────────────────────────────────────
echo "Building bridge installer (version $VERSION)..."
cp "$SCRIPT_DIR/install_bridge.sh" "$SCRIPT_DIR/release/bridge/"

makeself "$SCRIPT_DIR/release/bridge" \
         "$SCRIPT_DIR/ice-bridge-installer-${VERSION}.run" \
         "ICEMail Bridge Installer" \
         ./install_bridge.sh

echo "Created: $SCRIPT_DIR/ice-bridge-installer-${VERSION}.run"
