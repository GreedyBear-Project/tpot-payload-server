#!/usr/bin/env bash
# --------------------------------------------------------------------------
# tpot-payload-server — Automated Deployment Script
# Run this script from the repository root: sudo ./install.sh
# --------------------------------------------------------------------------
set -euo pipefail

# ── Defaults ─────────────────────────────────────────────────────────────
TPOT_DIR=""
TPOT_DATA_PATH=""
API_PORT="64444"
PROXY_PORT="64445"
SKIP_PROXY=false
SKIP_CONFIRM=false

# ── Colors ───────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

# ── Helpers ──────────────────────────────────────────────────────────────
banner() {
    cat <<'EOF'
 _____     ____       _     ____                 _                 _
|_   _|   |  _ \ ___ | |_  |  _ \ __ _ _   _   | | ___   __ _  __| |
  | |_____| |_) / _ \| __| | |_) / _` | | | |  | |/ _ \ / _` |/ _` |
  | |_____|  __/ (_) | |_  |  __/ (_| | |_| |  | | (_) | (_| | (_| |
  |_|     |_|   \___/ \__| |_|   \__,_|\__, |  |_|\___/ \__,_|\__,_|
       Server Installer                |___/
EOF
}

info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fatal() { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

usage() {
    cat <<EOF
Usage: sudo $0 [OPTIONS]

Options:
  --tpot-dir <path>  Path to T-Pot installation (default: auto-detect)
  --no-proxy         Skip NGINX proxy setup
  -y                 Skip confirmation prompts
  -h, --help         Show this help message
EOF
    exit 0
}

# ── Argument Parsing ─────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --tpot-dir) TPOT_DIR="$2"; shift 2 ;;
        --no-proxy) SKIP_PROXY=true; shift ;;
        -y)         SKIP_CONFIRM=true; shift ;;
        -h|--help)  usage ;;
        *)          fatal "Unknown option: $1" ;;
    esac
done

# ── Pre Checks ────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then fatal "This script must be run as root (sudo)."; fi
for cmd in docker openssl curl; do
    if ! command -v "$cmd" &>/dev/null; then fatal "Missing dependency: $cmd"; fi
done
if [[ ! -f "docker/docker-compose.yml" ]]; then
    fatal "Please run this script from the repository root."
fi

# ── Detect T-Pot ─────────────────────────────────────────────────────────
info "Detecting T-Pot installation ..."
if [[ -z "$TPOT_DIR" ]]; then
    for candidate in ".." "../tpotce" "$HOME/tpotce" "/home/${SUDO_USER:-}/tpotce" "/opt/tpot/tpotce" "/home/tsec/tpotce"; do
        if [[ -f "$candidate/.env" ]]; then TPOT_DIR="$candidate"; break; fi
    done
fi
if [[ -z "$TPOT_DIR" || ! -f "$TPOT_DIR/.env" ]]; then
    fatal "T-Pot .env not found. Use --tpot-dir to specify the path."
fi

TPOT_DATA_PATH=$(grep -E '^TPOT_DATA_PATH=' "$TPOT_DIR/.env" | cut -d'=' -f2 | tr -d '"'"'")
TPOT_DATA_PATH=$(cd "$TPOT_DIR" && realpath "$TPOT_DATA_PATH" 2>/dev/null || echo "$TPOT_DATA_PATH")
if [[ ! -d "$TPOT_DATA_PATH" ]]; then
    fatal "T-Pot data directory does not exist: $TPOT_DATA_PATH"
fi
ok "T-Pot data path: $TPOT_DATA_PATH"

# ── Confirmation ─────────────────────────────────────────────────────────
if [[ "$SKIP_CONFIRM" == false ]]; then
    echo
    echo -e "  ${BLUE}Installation summary:${NC}"
    echo -e "    T-Pot directory:  $TPOT_DIR"
    echo -e "    T-Pot data path: $TPOT_DATA_PATH"
    if [[ "$SKIP_PROXY" == true ]]; then
        echo -e "    HTTPS proxy:     disabled"
    else
        echo -e "    HTTPS proxy:     $PROXY_PORT"
    fi
    echo
    read -rp "Proceed with installation? [y/N] " ans
    if [[ ! "$ans" =~ ^[Yy] ]]; then echo "Cancelled."; exit 0; fi
fi

# ── TLS Certificates ─────────────────────────────────────────────────────
CERT_DIR="$TPOT_DATA_PATH/nginx/cert"
if [[ "$SKIP_PROXY" == false ]]; then
    if [[ ! -f "$CERT_DIR/nginx.crt" || ! -f "$CERT_DIR/nginx.key" ]]; then
        fatal "T-Pot TLS certificates not found at $CERT_DIR. Please ensure T-Pot is fully installed and running first."
    fi
    ok "T-Pot TLS certificates found."
fi

# ── Environment Configuration ────────────────────────────────────────────
ENV_FILE="docker/.env"
if [[ ! -f "$ENV_FILE" ]]; then
    info "Generating $ENV_FILE ..."
    API_KEY=$(openssl rand -hex 32)
    cp docker/.env.example "$ENV_FILE"
    sed -i "s|^API_KEY=.*|API_KEY=${API_KEY}|" "$ENV_FILE"
    sed -i "s|^TPOT_DATA_PATH=.*|TPOT_DATA_PATH=${TPOT_DATA_PATH}|" "$ENV_FILE"
    sed -i "s|^API_PORT=.*|API_PORT=${API_PORT}|" "$ENV_FILE"
    sed -i "s|^PROXY_PORT=.*|PROXY_PORT=${PROXY_PORT}|" "$ENV_FILE"

    echo
    echo -e "  ${YELLOW}Generated API Key:${NC} ${API_KEY}"
    echo -e "  ${RED}⚠ Save this key! It is stored in docker/.env and will not be shown again.${NC}"
    echo
else
    warn "$ENV_FILE already exists, keeping existing configuration."
fi

# ── Deployment ───────────────────────────────────────────────────────────
info "Deploying containers ..."
if [[ "$SKIP_PROXY" == true ]]; then
    docker compose -f docker/docker-compose.yml up -d tpot-payload-server
else
    docker compose -f docker/docker-compose.yml up -d
fi

echo
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║          T-Pot Payload Server — Deployment Complete          ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo
if [[ "$SKIP_PROXY" == true ]]; then
    echo -e "  ${BLUE}API endpoint:${NC}  http://localhost:${API_PORT}"
else
    echo -e "  ${BLUE}API endpoint:${NC}  https://localhost:${PROXY_PORT}"
fi
echo -e "  ${BLUE}Manage with:${NC}   docker compose -f docker/docker-compose.yml logs"
echo
