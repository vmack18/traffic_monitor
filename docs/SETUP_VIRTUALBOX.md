# Two-Machine Lab Setup (VirtualBox)

This guide builds the intended deployment: **Laptop 1** runs an Ubuntu Server VM that hosts the protected origin and the inline detection proxy, and **Laptop 2** runs the Python backend and the Node.js + TypeScript dashboard.

You can do this with two physical laptops, or with one host running two VirtualBox VMs. The instructions below assume the two-VM variant; the physical-laptop variant is the same minus the VM creation steps.

## 1. Network plan

Use a **Host-Only Adapter** so the two machines can talk to each other without exposing anything to the outside world.

| Host | Role | Host-only IP | Public services |
|------|------|--------------|-----------------|
| `tg-server` (Laptop 1) | Ubuntu Server VM | `192.168.56.10` | proxy `:8080` |
| `tg-monitor` (Laptop 2) | Ubuntu Desktop / host | `192.168.56.20` | backend `:8000`, dashboard `:3000` |

The origin (`:9000`) is bound to `127.0.0.1` on Laptop 1 and is never reachable from the network.

## 2. Create the VirtualBox VMs

1. Download the **Ubuntu Server 22.04/24.04 ISO**.
2. In VirtualBox: **New → Name: tg-server → Type: Linux → Version: Ubuntu (64-bit)**.
3. Give it **2 vCPU, 2–4 GB RAM, 20 GB disk**.
4. In **Settings → Network → Adapter 1**, choose **NAT** (for internet access during install) and **Adapter 2 → Host-only Adapter** (for the lab network).
5. Install Ubuntu Server. Create a user (e.g. `tg`). Enable **OpenSSH server** when prompted.
6. Repeat for `tg-monitor` if you want a second VM for the dashboard, or run Laptop 2 on the host.

### Host-only network

On the host, VirtualBox creates a host-only adapter (usually `vboxnet0`, `192.168.56.1/24`). Confirm it exists:

```bash
VBoxManage list hostonlyifs
```

If not, create it:

```bash
VBoxManage hostonlyif create
VBoxManage hostonlyif ipconfig vboxnet0 --ip 192.168.56.1 --netmask 255.255.255.0
```

## 3. Configure static IPs

On **tg-server** edit `/etc/netplan/50-cloud-init.yaml` (name may vary):

```yaml
network:
  version: 2
  ethernets:
    enp0s3:            # NAT adapter
      dhcp4: true
    enp0s8:            # host-only adapter
      dhcp4: false
      addresses: [192.168.56.10/24]
```

Apply:

```bash
sudo netplan apply
ip addr show enp0s8
```

On **tg-monitor**, set the host-only adapter to `192.168.56.20/24` the same way (or via the desktop network settings).

Verify connectivity from Laptop 2:

```bash
ping -c 3 192.168.56.10
```

## 4. Install Laptop 1 (protected server + proxy)

Copy the `laptop1-server/` directory to the VM (scp, shared folder, or git), then:

```bash
sudo ./laptop1-server/setup_ubuntu.sh
```

The script:

1. installs `python3`, `python3-venv`, `ufw`, and basic tools,
2. creates the `trafficguard` system user,
3. copies the code to `/opt/traffic-guard`,
4. installs `traffic-origin.service` and `traffic-guard.service` into systemd,
5. enables and starts both services,
6. resets UFW to **allow 22/tcp and 8080/tcp only** (9000 is never opened).

Edit the monitor URL before starting, so the proxy reports to Laptop 2:

```bash
sudo nano /opt/traffic-guard/config.json
#   "monitor": { "url": "http://192.168.56.20:8000", "enabled": true }
sudo systemctl restart traffic-guard
```

Check status and logs:

```bash
systemctl status traffic-origin traffic-guard
journalctl -u traffic-guard -f
ss -ltnp | grep -E '8080|9000'
```

You should see `0.0.0.0:8080` (proxy) and `127.0.0.1:9000` (origin). The origin must **not** appear on `0.0.0.0`.

Test from Laptop 2:

```bash
curl -s http://192.168.56.10:8080/health
```

## 5. Install Laptop 2 (monitoring backend + dashboard)

```bash
# Python backend
cd laptop2-monitor/backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install websockets          # WebSocket support for uvicorn
uvicorn main:app --host 0.0.0.0 --port 8000
```

```bash
# Node.js + TypeScript dashboard
cd laptop2-monitor/frontend
npm install
npm run build
PORT=3000 BACKEND_URL=http://127.0.0.1:8000 node dist/server.js
```

Open `http://192.168.56.20:3000` from any machine on the host-only network.

If you want the dashboard to be reachable from the NAT side as well, run the Node server on `0.0.0.0` (the default) and add a port-forward in VirtualBox (**Settings → Network → Adapter 1 → Advanced → Port Forwarding**: host `3000` → guest `3000`).

## 6. Firewall summary

**Laptop 1 (UFW):**

```bash
sudo ufw status verbose
# 22/tcp   ALLOW
# 8080/tcp ALLOW
# (9000 is intentionally absent)
```

**Laptop 2:** if UFW is enabled, allow the dashboard and backend:

```bash
sudo ufw allow 3000/tcp
sudo ufw allow 8000/tcp
```

## 7. End-to-end verification

From Laptop 2, verify the connection using low-rate benign requests to your own lab proxy:

```bash
python3 tools/benign_traffic.py --host 192.168.56.10 --port 8080 --rps 2 --duration 30
```

Watch the dashboard: the connection pill should read **Live** and the chart should move. On Laptop 1, `journalctl -u traffic-guard -f` should show traffic decisions in real time.

## 8. Optional: enable the packet sensor

The Scapy sensor needs raw-socket privileges. On Laptop 1:

```bash
sudo apt install -y python3-scapy
sudo systemctl edit traffic-guard     # add: Environment=TG_SNIFFER_ENABLED=true
sudo systemctl restart traffic-guard
```

Or run the backend with `TG_SNIFFER_ENABLED=true` if the sensor lives on Laptop 2. The sensor adds SYN/UDP/ICMP flood and packet-level port-scan detections.

## 8b. Tell the dashboard which IP is the server

The **Blocked IPs** panel has a manual block form and a **⛔ Block server IP** shortcut. Set the origin address once so the shortcut knows what to quarantine:

```bash
sudo systemctl edit traffic-guard
# [Service]
# Environment=TG_SERVER_IP=192.168.56.10
# Environment=TG_SERVER_LABEL=Ubuntu Server (VirtualBox)
sudo systemctl restart traffic-guard
```

The value is shown live in the panel (`server: 192.168.56.10`) and returned by `GET /api/config`. You can also just type any address into the form and press **Block IP** — the block is validated, persisted, and pushed to the Laptop 1 proxy on its next poll.

## 9. Troubleshooting the lab

| Symptom | Fix |
|---------|-----|
| VMs cannot ping each other | Both need the **same** host-only network name; check `VBoxManage list hostonlyifs`. |
| Proxy reachable but origin also reachable | The origin is bound to `0.0.0.0`; change `--host 127.0.0.1` and restart. |
| Dashboard "Reconnecting…" | `pip install websockets` on Laptop 2 and restart uvicorn. |
| No events on dashboard | `config.json` `monitor.url` must point at Laptop 2's host-only IP, and UFW on Laptop 2 must allow 8000. |
| Proxy reports but dashboard empty | Check `journalctl -u traffic-guard` for reporter errors; confirm `/api/health` on Laptop 2. |
