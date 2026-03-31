# VPN Client

WireGuard-based VPN client with internet routing. Linux + macOS, single binary, ~742KB.

## Quick Start

```bash
# Connect to VPN (mesh mode)
vpn-client --server <SERVER_IP>:9190 --token <TOKEN> --name my-laptop

# Connect with internet mode (all traffic through VPN)
vpn-client --server <SERVER_IP>:9190 --token <TOKEN> --name my-laptop --internet
```

## Install (Linux)

```bash
curl -fsSL https://github.com/gateway-a/vpn-client/releases/latest/download/vpn-client -o /usr/local/bin/vpn-client
chmod +x /usr/local/bin/vpn-client
```

## Install (macOS)

```bash
curl -fsSL https://github.com/gateway-a/vpn-client/releases/latest/download/vpn-client-darwin -o /usr/local/bin/vpn-client
chmod +x /usr/local/bin/vpn-client
# Requires sudo for TUN device
sudo vpn-client --server <IP>:9190 --token <TOKEN> --internet
```

## Usage

```
vpn-client [OPTIONS]

Options:
  -s, --server IP:PORT      VPN server control API address
  -t, --token TOKEN         Authentication token
  -n, --name NAME           Client name (auto-generated if empty)
  --control-port PORT       Control API port (default: 9190)
  --listen-port PORT        Local UDP port (default: random)
  --mtu SIZE                TUN MTU (default: 1420)
  --vpn-network CIDR        Additional VPN network route
  --internet               Route all internet traffic through VPN

Environment variables:
  VPN_SERVER                Server address (fallback for --server)
  VPN_TOKEN                 Auth token (fallback for --token)
  VPN_NAME                  Client name (fallback for --name)
```

## Internet Mode

When `--internet` is used:

1. Adds host routes for server IP via original gateway (preserves WireGuard UDP)
2. Adds policy routing rule to preserve SSH/inbound connections
3. Adds split-default routes: `0.0.0.0/1` + `128.0.0.0/1` via TUN
4. All outbound internet traffic goes through VPN server
5. Your public IP becomes the VPN server's IP
6. Routes auto-cleaned on exit (Ctrl+C or SIGTERM)

```bash
# Before VPN
curl https://ifconfig.me  # → your real IP

# With internet mode
sudo vpn-client -s 1.2.3.4:9190 -t mytoken --internet
curl https://ifconfig.me  # → 1.2.3.4 (VPN server IP)
```

## Systemd Service

```bash
cat > /etc/systemd/system/vpn-client.service << EOF
[Unit]
Description=VPN Client
After=network.target

[Service]
Environment=VPN_SERVER=<SERVER_IP>:9190
Environment=VPN_TOKEN=<TOKEN>
ExecStart=/usr/local/bin/vpn-client --server \${VPN_SERVER} --token \${VPN_TOKEN} --internet
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now vpn-client
```

## Platform Support

| OS | TUN | Internet | Status |
|----|-----|-----------|--------|
| Linux x86_64 | ✅ | ✅ | Full support |
| Linux ARM64 | ✅ | ✅ | Full support |
| macOS x86_64 | ✅ | ✅ | Full support (utun) |
| macOS ARM64 | ✅ | ✅ | Full support (utun) |
| Windows | ❌ | ❌ | Planned (use WSL2) |
| Android | ❌ | ❌ | Planned |
| iOS | ❌ | ❌ | Planned |

## How It Works

1. Client generates ephemeral X25519 keypair
2. Sends `POST /api/v1/join` to server with public key
3. Server assigns IP from VPN subnet, registers peer
4. Client creates TUN device, configures routes
5. WireGuard tunnel established over UDP
6. If internet mode: all traffic routed through TUN → server NATs to internet

## Build

```bash
cargo build --release

# Cross-compile
cargo zigbuild --release --target aarch64-unknown-linux-gnu
cargo zigbuild --release --target x86_64-unknown-linux-gnu
```
