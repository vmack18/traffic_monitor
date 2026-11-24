#!/usr/bin/env bash
# =============================================================================
# setup_ubuntu.sh  --  LAPTOP 1 (Ubuntu Server VM inside VirtualBox)
# =============================================================================
# Installs the protected origin server + inline detection proxy as systemd
# services, and locks the firewall down so that ONLY the proxy port is exposed.
#
#   sudo ./setup_ubuntu.sh
#
# Result:
#   traffic-origin.service   -> 127.0.0.1:9000   (never reachable from outside)
#   traffic-guard.service    -> 0.0.0.0:8080     (the only public entry point)
# =============================================================================
set -euo pipefail

APP_DIR="/opt/traffic-guard"
SERVICE_USER="trafficguard"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ $EUID -ne 0 ]]; then
  echo "[-] Please run as root:  sudo ./setup_ubuntu.sh"
  exit 1
fi

echo "[+] Installing base packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y python3 python3-venv python3-pip ufw curl jq net-tools

echo "[+] Creating service user '${SERVICE_USER}'..."
if ! id -u "${SERVICE_USER}" >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin "${SERVICE_USER}"
fi

echo "[+] Copying application to ${APP_DIR}..."
mkdir -p "${APP_DIR}"
install -m 0644 "${SRC_DIR}/protected_server.py" "${APP_DIR}/protected_server.py"
install -m 0644 "${SRC_DIR}/detection_proxy.py"  "${APP_DIR}/detection_proxy.py"
install -m 0644 "${SRC_DIR}/malicious.py"        "${APP_DIR}/malicious.py"
install -m 0644 "${SRC_DIR}/config.json"         "${APP_DIR}/config.json"
chown -R root:"${SERVICE_USER}" "${APP_DIR}"
chmod 0750 "${APP_DIR}"

mkdir -p /var/log/traffic-guard
chown "${SERVICE_USER}":"${SERVICE_USER}" /var/log/traffic-guard

echo "[+] Installing systemd units..."
install -m 0644 "${SRC_DIR}/systemd/traffic-origin.service" /etc/systemd/system/traffic-origin.service
install -m 0644 "${SRC_DIR}/systemd/traffic-guard.service"  /etc/systemd/system/traffic-guard.service
systemctl daemon-reload
systemctl enable traffic-origin.service traffic-guard.service
systemctl restart traffic-origin.service
sleep 1
systemctl restart traffic-guard.service

echo "[+] Configuring UFW firewall..."
ufw --force reset >/dev/null
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null
ufw allow 22/tcp   comment 'ssh management' >/dev/null
ufw allow 8080/tcp comment 'traffic-guard detection proxy' >/dev/null
# NOTE: port 9000 is deliberately NOT opened - the origin is loopback-only.
ufw --force enable >/dev/null

echo
echo "=============================================================="
echo " LAPTOP 1 ready"
echo "=============================================================="
systemctl --no-pager --lines=0 status traffic-origin.service || true
systemctl --no-pager --lines=0 status traffic-guard.service  || true
echo
echo " Origin (loopback only) : http://127.0.0.1:9000"
echo " Detection proxy (LAN)  : http://<laptop1-ip>:8080"
echo " Logs                   : journalctl -u traffic-guard -f"
echo
echo " Next: edit ${APP_DIR}/config.json -> monitor.url, then"
echo "       systemctl restart traffic-guard"
echo "=============================================================="
