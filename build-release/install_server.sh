#!/bin/bash
#
# ICEMail Server Installer
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
echo "  ICEMail Server Installer"
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

if ! command -v unzip &>/dev/null; then
    error "unzip is not installed or not on PATH."
    error "Please install it (e.g. sudo apt install unzip) and re-run this installer."
    exit 1
fi
info "unzip found — OK"

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
DEFAULT_INSTALL_DIR="/usr/local/ice-server"

read -rp "Install directory [${DEFAULT_INSTALL_DIR}]: " SERVER_DIR
SERVER_DIR="${SERVER_DIR:-$DEFAULT_INSTALL_DIR}"

echo ""
info "Installing to: $SERVER_DIR"
echo ""

read -rp "Proceed? [y/N]: " CONFIRM
if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
    echo "Installation cancelled."
    exit 0
fi

# ─── 3. Create directory and copy files ───────────────────────────────────────
mkdir -p "$SERVER_DIR"

info "Installing ICEMail Server..."
cp "$RELEASE_DIR/ice-server-1.0.jar"  "$SERVER_DIR/"
cp "$RELEASE_DIR/log4j2.xml"           "$SERVER_DIR/"
cp "$RELEASE_DIR/server_run.sh"        "$SERVER_DIR/"
cp "$RELEASE_DIR/create_user.sh"       "$SERVER_DIR/"
cp "$RELEASE_DIR/delete_user.sh"       "$SERVER_DIR/"
chmod +x "$SERVER_DIR/server_run.sh" "$SERVER_DIR/create_user.sh" "$SERVER_DIR/delete_user.sh"

info "Extracting WebContent..."
unzip -qo "$RELEASE_DIR/WebContent.zip" -d "$SERVER_DIR/"

# ─── 4. Generate config from template ─────────────────────────────────────────
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

    ALTCHA_RANDOM=$(openssl rand -hex 32)

    # Generate self-signed TLS certificate (99999 days, no key password)
    info "Generating self-signed TLS certificate (CN=${ICE_SERVER_HOST})..."
    openssl req -x509 -newkey rsa:4096 \
      -keyout "$SERVER_DIR/privkey.pem" \
      -out    "$SERVER_DIR/fullchain.pem" \
      -days   99999 \
      -nodes \
      -subj   "/CN=${ICE_SERVER_HOST}" \
      2>/dev/null
    info "Certificate generated: $SERVER_DIR/fullchain.pem"

    sed \
      -e "s|#ICE_SERVER_HOST#|${ICE_SERVER_HOST}|g" \
      -e "s|#MAIL_DOMAIN#|${MAIL_DOMAIN}|g" \
      -e "s|#ADMIN_CLIENT#|${ADMIN_CLIENT}|g" \
      -e "s|#ADMIN_PASSWORD#|${ADMIN_PASSWORD}|g" \
      -e "s|#ALTCHA_RANDOM#|${ALTCHA_RANDOM}|g" \
      -e "s|#SSL_CERT_PATH#|${SERVER_DIR}/fullchain.pem|g" \
      -e "s|#SSL_KEY_PATH#|${SERVER_DIR}/privkey.pem|g" \
      "$RELEASE_DIR/ice-server-template.json" > "$SERVER_DIR/ice-server.json"

    info "Installed ice-server.json — review before starting."
else
    warn "Existing ice-server.json found, not overwritten."
fi

# ─── 5. Systemd service file ──────────────────────────────────────────────────
if command -v systemctl &>/dev/null; then
    info "Installing systemd service file..."
    sed "s|#INSTALL_DIR#|${SERVER_DIR}|g" \
        "$RELEASE_DIR/ice-server.service" > /etc/systemd/system/ice-server.service
    chmod 755 /etc/systemd/system/ice-server.service
    systemctl daemon-reload
    info "Service file installed: /etc/systemd/system/ice-server.service"
else
    warn "systemctl not found — skipping service file installation."
fi

# ─── 6. Next steps ────────────────────────────────────────────────────────────
echo ""
sed "s|#SERVER_DIR#|${SERVER_DIR}|g" "$RELEASE_DIR/next_steps.txt"
echo ""
