#!/bin/bash
#
# ICEMail Installer
#

set -euo pipefail

REQUIRED_JAVA_VERSION=17

# ─── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()    { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RELEASE_DIR="$SCRIPT_DIR/release"

echo ""
echo "============================================"
echo "  ICEMail Installer"
echo "============================================"
echo ""

# ─── 1. Check prerequisites ───────────────────────────────────────────────────
info "Checking prerequisites..."

if ! command -v openssl &>/dev/null; then
    error "openssl is not installed or not on PATH."
    error "Please install it (e.g. sudo apt install openssl) and re-run this installer."
    exit 1
fi
info "openssl found — OK"

# ─── 2. Check Java ────────────────────────────────────────────────────────────
info "Checking Java installation..."

if ! command -v java &>/dev/null; then
    error "Java is not installed or not on PATH."
    error "Please install Java $REQUIRED_JAVA_VERSION or later and re-run this installer."
    exit 1
fi

JAVA_VERSION=$(java -version 2>&1 | awk -F'"' '/version/ {print $2}' | awk -F'.' '{print $1}')
# Handle old-style version strings like "1.8" → major = 8
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
DEFAULT_INSTALL_DIR="/usr/local/ICEMail"

read -rp "Install directory [${DEFAULT_INSTALL_DIR}]: " INSTALL_DIR
INSTALL_DIR="${INSTALL_DIR:-$DEFAULT_INSTALL_DIR}"

SERVER_DIR="$INSTALL_DIR/server"
BRIDGE_DIR="$INSTALL_DIR/bridge"

echo ""
info "Installing to: $INSTALL_DIR"
info "  Server : $SERVER_DIR"
info "  Bridge : $BRIDGE_DIR"
echo ""

read -rp "Proceed? [y/N]: " CONFIRM
if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
    echo "Installation cancelled."
    exit 0
fi

# ─── 3. Create directories ────────────────────────────────────────────────────
mkdir -p "$SERVER_DIR" "$BRIDGE_DIR"

# ─── 4. Install server ────────────────────────────────────────────────────────
info "Installing ICEMail Server..."
cp "$RELEASE_DIR/server/ice-server-1.0.jar"   "$SERVER_DIR/"
cp "$RELEASE_DIR/server/log4j2.xml"            "$SERVER_DIR/"
cp "$RELEASE_DIR/server/server_run.sh"         "$SERVER_DIR/"
cp "$RELEASE_DIR/server/create_user.sh"        "$SERVER_DIR/"
cp "$RELEASE_DIR/server/delete_user.sh"        "$SERVER_DIR/"
chmod +x "$SERVER_DIR/server_run.sh" "$SERVER_DIR/create_user.sh" "$SERVER_DIR/delete_user.sh"

# Install WebContent
info "Extracting WebContent..."
unzip -qo "$RELEASE_DIR/server/WebContent.zip" -d "$SERVER_DIR/"

# Install config template (don't overwrite an existing config)
if [ ! -f "$SERVER_DIR/ice-server.json" ]; then
    echo ""
    info "Server configuration — please provide the following:"
    echo ""

    read -rp "  Public hostname or IP of the ICEMail server : " ICE_SERVER_HOST
    while [ -z "$ICE_SERVER_HOST" ]; do
        warn "Cannot be empty."; read -rp "  Public hostname or IP of the ICEMail server : " ICE_SERVER_HOST
    done

    read -rp "  Mail domain handled by this server         : " MAIL_DOMAIN
    while [ -z "$MAIL_DOMAIN" ]; do
        warn "Cannot be empty."; read -rp "  Mail domain handled by this server         : " MAIL_DOMAIN
    done

    read -rp "  Admin client IP (allowed to access admin)  : " ADMIN_CLIENT
    while [ -z "$ADMIN_CLIENT" ]; do
        warn "Cannot be empty."; read -rp "  Admin client IP (allowed to access admin)  : " ADMIN_CLIENT
    done

    read -rsp "  Admin password                             : " ADMIN_PASSWORD; echo
    while [ -z "$ADMIN_PASSWORD" ]; do
        warn "Cannot be empty."; read -rsp "  Admin password                             : " ADMIN_PASSWORD; echo
    done

    # Generate a random 64-char hex string for the Altcha HMAC key
    ALTCHA_RANDOM=$(openssl rand -hex 32)

    sed \
      -e "s|#ICE_SERVER_HOST#|${ICE_SERVER_HOST}|g" \
      -e "s|#MAIL_DOMAIN#|${MAIL_DOMAIN}|g" \
      -e "s|#ADMIN_CLIENT#|${ADMIN_CLIENT}|g" \
      -e "s|#ADMIN_PASSWORD#|${ADMIN_PASSWORD}|g" \
      -e "s|#ALTCHA_RANDOM#|${ALTCHA_RANDOM}|g" \
      "$RELEASE_DIR/server/ice-server-template.json" > "$SERVER_DIR/ice-server.json"

    info "Installed ice-server.json — review $SERVER_DIR/ice-server.json before starting."
else
    warn "Existing ice-server.json found, not overwritten."
fi

# ─── 5. Install bridge ────────────────────────────────────────────────────────
info "Installing ICEMail Bridge..."
cp "$RELEASE_DIR/bridge/ice-bridge-1.0.jar"   "$BRIDGE_DIR/"
cp "$RELEASE_DIR/bridge/log4j2.xml"            "$BRIDGE_DIR/"
cp "$RELEASE_DIR/bridge/bridge_run.sh"         "$BRIDGE_DIR/"
chmod +x "$BRIDGE_DIR/bridge_run.sh"

if [ ! -f "$BRIDGE_DIR/ice-bridge.json" ]; then
    echo ""
    read -rp "Hostname or IP of the ICEMail server: " ICE_SERVER_HOST
    while [ -z "$ICE_SERVER_HOST" ]; do
        warn "Host cannot be empty."
        read -rp "Hostname or IP of the ICEMail server: " ICE_SERVER_HOST
    done
    sed "s|#ICE_SERVER_HOST#|${ICE_SERVER_HOST}|g" \
        "$RELEASE_DIR/bridge/ice-bridge-template.json" > "$BRIDGE_DIR/ice-bridge.json"
    info "Installed ice-bridge.json with server host '${ICE_SERVER_HOST}' — review before starting the bridge."
else
    warn "Existing ice-bridge.json found, not overwritten."
fi

# ─── 6. Systemd service files (optional) ─────────────────────────────────────
if command -v systemctl &>/dev/null; then
    echo ""
    read -rp "Install systemd service files? [y/N]: " INSTALL_SERVICES
    if [[ "$INSTALL_SERVICES" =~ ^[Yy]$ ]]; then
        cp "$RELEASE_DIR/server/ice-server.service" /etc/systemd/system/
        cp "$RELEASE_DIR/bridge/ice-bridge.service" /etc/systemd/system/
        systemctl daemon-reload
        info "Service files installed. Enable with:"
        echo "    systemctl enable ice-server ice-bridge"
    fi
fi

# ─── 7. Next steps ────────────────────────────────────────────────────────────
echo ""
echo "============================================"
echo "  Installation complete — Next Steps"
echo "============================================"
echo ""
echo "1. Configure the server:"
echo "     Edit $SERVER_DIR/ice-server.json"
echo "     Key settings:"
echo "       base_url      — your public HTTPS URL (e.g. https://mail.example.com)"
echo "       mail_domain   — your mail domain (e.g. example.com)"
echo "       ssl.cert/key  — paths to your TLS certificate and private key"
echo "       https_port    — HTTPS port (default 443)"
echo ""
echo "2. Configure the bridge (run on the user's own machine):"
echo "     Edit $BRIDGE_DIR/ice-bridge.json"
echo "     Key settings:"
echo "       serverBaseUrl     — URL of the ICEMail server"
echo "       imapsCertPath/Key — TLS certificate and key for IMAPS"
echo "       smtpListenPort    — SMTP submission port (default 587)"
echo ""
echo "3. Install and configure the Apache James IMAP server:"
echo "     See https://github.com/hoddmimes/IMAP-Apache-James"
echo "     James must listen on LMTP port 24 and IMAP port 1993."
echo ""
echo "4. Configure Postfix:"
echo "     virtual_transport = lmtp:inet:127.0.0.1:24"
echo "     content_filter    = smtp:127.0.0.1:10026"
echo "     smtpd_sasl_type   = dovecot"
echo "     smtpd_sasl_path   = inet:127.0.0.1:12345"
echo ""
echo "5. Start the server:"
echo "     cd $SERVER_DIR && ./server_run.sh"
echo "   Or via systemd:"
echo "     systemctl start ice-server"
echo ""
echo "6. Start the bridge (on the user's machine):"
echo "     cd $BRIDGE_DIR && ./bridge_run.sh"
echo "   Or via systemd:"
echo "     systemctl start ice-bridge"
echo ""
echo "7. Create users:"
echo "     cd $SERVER_DIR && ./create_user.sh"
echo ""
info "See README.md and doc/architecture.md for full setup details."
echo ""
