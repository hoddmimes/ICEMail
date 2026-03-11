#!/bin/bash
#
# ICEMail Bridge Installer
#

set -euo pipefail

REQUIRED_JAVA_VERSION=17

# ─── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RELEASE_DIR="$SCRIPT_DIR"

echo ""
echo "============================================"
echo "  ICEMail Bridge Installer"
echo "============================================"
echo ""

# ─── 1. Check prerequisites ───────────────────────────────────────────────────
info "Checking prerequisites..."

if ! command -v java &>/dev/null; then
    error "Java is not installed or not on PATH."
    error "Please install Java $REQUIRED_JAVA_VERSION or later and re-run this installer."
    exit 1
fi

JAVA_VERSION=$(java -version 2>&1 | awk -F'"' '/version/ {print $2}' | awk -F'.' '{print $1}')
if [ "$JAVA_VERSION" = "1" ]; then
    JAVA_VERSION=$(java -version 2>&1 | awk -F'"' '/version/ {print $2}' | awk -F'.' '{print $2}')
fi
if [ "$JAVA_VERSION" -lt "$REQUIRED_JAVA_VERSION" ] 2>/dev/null; then
    error "Java $JAVA_VERSION found, but Java $REQUIRED_JAVA_VERSION or later is required."
    exit 1
fi
info "Java $JAVA_VERSION found — OK"
echo ""

# ─── 2. Choose install directory ──────────────────────────────────────────────
DEFAULT_INSTALL_DIR="/usr/local/ice-bridge"

read -rp "Install directory [${DEFAULT_INSTALL_DIR}]: " BRIDGE_DIR
BRIDGE_DIR="${BRIDGE_DIR:-$DEFAULT_INSTALL_DIR}"

echo ""
info "Installing to: $BRIDGE_DIR"
echo ""

read -rp "Proceed? [y/N]: " CONFIRM
if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
    echo "Installation cancelled."
    exit 0
fi

# ─── 3. Create directory and copy files ───────────────────────────────────────
mkdir -p "$BRIDGE_DIR"

info "Installing ICEMail Bridge..."
cp "$RELEASE_DIR/ice-bridge-1.0.jar"  "$BRIDGE_DIR/"
cp "$RELEASE_DIR/log4j2.xml"           "$BRIDGE_DIR/"
cp "$RELEASE_DIR/bridge_run.sh"        "$BRIDGE_DIR/"
chmod +x "$BRIDGE_DIR/bridge_run.sh"

# ─── 4. Generate config from template ─────────────────────────────────────────
if [ ! -f "$BRIDGE_DIR/ice-bridge.json" ]; then
    echo ""
    info "Bridge configuration — please provide the following:"
    echo ""

    read -rp "  Hostname or IP of the ICEMail server       : " ICE_SERVER_HOST
    while [ -z "$ICE_SERVER_HOST" ]; do
        warn "Cannot be empty."; read -rp "  Hostname or IP of the ICEMail server       : " ICE_SERVER_HOST
    done

    read -rp "  Hostname of this bridge machine (for cert) : " BRIDGE_HOST
    BRIDGE_HOST="${BRIDGE_HOST:-localhost}"

    # Generate self-signed TLS certificate for IMAPS (99999 days, no key password)
    info "Generating self-signed TLS certificate (CN=${BRIDGE_HOST})..."
    openssl req -x509 -newkey rsa:4096 \
      -keyout "$BRIDGE_DIR/privkey.pem" \
      -out    "$BRIDGE_DIR/fullchain.pem" \
      -days   99999 \
      -noenc \
      -subj   "/CN=${BRIDGE_HOST}" \
      2>/dev/null
    info "Certificate generated: $BRIDGE_DIR/fullchain.pem"

    sed \
      -e "s|#ICE_SERVER_HOST#|${ICE_SERVER_HOST}|g" \
      -e "s|#BRIDGE_CERT_PATH#|${BRIDGE_DIR}/fullchain.pem|g" \
      -e "s|#BRIDGE_KEY_PATH#|${BRIDGE_DIR}/privkey.pem|g" \
      "$RELEASE_DIR/ice-bridge-template.json" > "$BRIDGE_DIR/ice-bridge.json"

    info "Installed ice-bridge.json — review before starting."
else
    warn "Existing ice-bridge.json found, not overwritten."
fi

# ─── 5. Systemd service file ──────────────────────────────────────────────────
if command -v systemctl &>/dev/null; then
    info "Installing systemd service file..."
    sed "s|#INSTALL_DIR#|${BRIDGE_DIR}|g" \
        "$RELEASE_DIR/ice-bridge.service" > /etc/systemd/system/ice-bridge.service
    chmod 755 /etc/systemd/system/ice-bridge.service
    systemctl daemon-reload
    info "Service file installed: /etc/systemd/system/ice-bridge.service"
else
    warn "systemctl not found — skipping service file installation."
fi

# ─── 6. Next steps ────────────────────────────────────────────────────────────
echo ""
sed "s|#BRIDGE_DIR#|${BRIDGE_DIR}|g" "$RELEASE_DIR/next_steps.txt"
echo ""
