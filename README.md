<p align="center">
  <img src="https://nexguard.sh/favicon.svg" width="80" height="80" alt="NexGuard">
</p>

<h1 align="center">NexGuard</h1>

<p align="center">
  <strong>Dedicated VPN infrastructure for teams.</strong><br>
  Deploy a private VPN server in 30 seconds. No shared infrastructure. No logs.
</p>

<p align="center">
  <a href="https://nexguard.sh">Website</a> &middot;
  <a href="https://nexguard.sh/download">Download</a> &middot;
  <a href="https://nexguard.sh/deploy">Deploy Server</a> &middot;
  <a href="https://nexguard.sh/#pricing">Pricing</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/platforms-macOS%20%7C%20Linux%20%7C%20Windows-blue" alt="Platforms">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT License">
  <img src="https://img.shields.io/badge/binary%20size-3.5%20MB-brightgreen" alt="Size">
  <img src="https://img.shields.io/github/v/release/NexGuard-VPN/client" alt="Release">
</p>

---

## What is NexGuard?

NexGuard gives your team a **dedicated VPN server** with a clean static IP that only you control. Unlike shared VPN services, every NexGuard server is exclusively yours — no other users, no shared bandwidth, no IP reputation issues.

**Cloud managed** (we deploy and maintain the server) or **self-hosted** (install on your own infrastructure for free).

### Who is it for?

- **Remote teams** that need secure access to internal resources
- **Companies** that require a static IP for whitelisting
- **VPN providers** building their own service (self-hosted, up to 10,000+ devices)
- **Developers** who need to bypass firewalls and DPI in restricted networks
- **Privacy-conscious users** who don't trust shared VPN services

## Quick Start

### Install

```bash
curl -fsSL https://nexguard.sh/install | sudo bash
```

Or download directly: [macOS (DMG)](https://nexguard.sh/download) | [Linux](https://nexguard.sh/download) | [Windows](https://nexguard.sh/download)

### Connect

```bash
sudo nexguard --token YOUR_TOKEN --internet
```

That's it. GUI opens, connects automatically, menubar tray icon appears.

> Don't have a server? [Deploy one in 30 seconds](https://nexguard.sh/deploy) or [self-host for free](https://nexguard.sh/download).

## Features

| Feature | Description |
|---------|-------------|
| **Dedicated static IP** | Not shared with anyone. Clean reputation. Whitelisting friendly. |
| **Zero open ports** | Server needs no inbound firewall rules. Works behind NAT, CGNAT, corporate firewalls. |
| **DPI bypass** | TLS obfuscation on port 443. Indistinguishable from normal HTTPS traffic. |
| **Kill switch** | All traffic blocked instantly if VPN drops. No IP leaks. |
| **Auto-reconnect** | Reconnects automatically with exponential backoff. Zero manual intervention. |
| **Auto key rotation** | Encryption keys rotate every 24 hours automatically. |
| **Menubar tray** | Quick connect/disconnect, server switching, live traffic stats from system tray. |
| **Multi-server profiles** | Save multiple VPN servers. Switch between them from tray or GUI. |
| **Mesh networking** | Direct P2P tunnels between team devices. Subnet routing for office networks. |
| **Self-update** | Client checks for updates on launch and can update in-place. |
| **Open source** | MIT licensed. No telemetry. No tracking. Audit the code yourself. |

## How It Works

```
┌──────────┐     TLS (port 443)     ┌──────────────┐     WireGuard     ┌──────────┐
│  Client   │ ───────────────────── │  Relay Server │ ─────────────── │ VPN Server│
│ (your PC) │  looks like HTTPS     │  (NexGuard)   │   encrypted     │ (yours)   │
└──────────┘                        └──────────────┘                  └──────────┘
```

1. **Deploy** a dedicated VPN server (cloud or self-hosted)
2. **Create device tokens** from the web dashboard for each team member
3. **Install the client** and paste the token — auto-connects in seconds
4. All traffic is encrypted and routed through your dedicated server
5. Your public IP changes to the server's static IP

No coordination servers. No metadata collection. The relay only forwards encrypted traffic.

## Comparison

| | NexGuard | Tailscale | Traditional VPN |
|---|---------|-----------|----------------|
| **Server ownership** | Yours (dedicated) | Shared infrastructure | Shared servers |
| **Setup time** | 30 seconds | ~5 minutes | 30+ minutes |
| **Open ports needed** | 0 | 0 | 1+ UDP |
| **DPI/censorship bypass** | Yes (TLS obfuscation) | No | Rarely |
| **Static IP** | Included | Via exit node | Shared/rotating |
| **Self-host option** | Free (up to 5 devices) | No (Headscale only) | N/A |
| **Max devices** | 10,000+ (self-hosted) | 100 (business) | Varies |
| **Key rotation** | 24h automatic | 180d | Manual |
| **Team pricing** | $5/mo per server | $6/user/mo | $5-12/user/mo |
| **Kill switch** | Built-in | Limited | Varies |
| **Open source client** | Yes (MIT) | Partial | Rarely |

## Platforms

| Platform | GUI | System Tray | CLI | Status |
|----------|-----|-------------|-----|--------|
| macOS ARM64 (Apple Silicon) | yes | yes | yes | Stable |
| macOS x86_64 (Intel) | yes | yes | yes | Stable |
| Linux x86_64 | yes | yes | yes | Stable |
| Linux ARM64 | yes | yes | yes | Stable |
| Windows x86_64 | yes | - | yes | Beta |

## CLI Reference

```
nexguard [OPTIONS]

Options:
  -t, --token TOKEN       Device token from dashboard
  -n, --name NAME         Server profile name (e.g. "Office VPN")
      --internet          Route all traffic through VPN
      --kill-switch       Block traffic if VPN disconnects
      --cli               Headless mode — no GUI, terminal only
  -v, --version           Print version
  -h, --help              Show help
```

### Examples

```bash
# GUI mode (default) — opens window + tray
sudo nexguard --token TOKEN --internet

# Named server profile
sudo nexguard --token TOKEN --name "Frankfurt Office" --internet

# CLI mode for headless Linux servers
sudo nexguard --cli --token TOKEN --internet --kill-switch

# Environment variables also work
export VPN_TOKEN=your_token
sudo nexguard --internet
```

## Self-Hosted

Run NexGuard on your own server completely free (up to 5 devices).

```bash
curl -fsSL https://nexguard.sh/install-server | bash
```

Need more than 5 devices? Self-hosted plans start at $29/mo for 100 devices. See [pricing](https://nexguard.sh/#pricing).

## Pricing

| Plan | Price | Devices | Best for |
|------|-------|---------|----------|
| **Self-Hosted Free** | $0/forever | 5 | Personal use, testing |
| **Cloud Personal** | $5/mo | 5 | Individuals, small teams |
| **Cloud Team** | $15/mo | 25 | Growing teams |
| **Cloud Business** | $39/mo | 100 | Organizations |
| **Self-Hosted Team** | $29/mo | 100 | Small VPN services |
| **Self-Hosted Business** | $79/mo | 1,000 | Mid-size providers |
| **Self-Hosted Enterprise** | $199/mo | 10,000 | Large-scale VPN infrastructure |

All cloud plans include a **30-day free trial**. No credit card required.

[Start free trial](https://nexguard.sh/deploy) | [View all plans](https://nexguard.sh/#pricing)

## Architecture

```
nexguard (this repo)
├── src/
│   ├── main.rs          # CLI entry, arg parsing, signal handling
│   ├── ui.rs            # Desktop GUI (eframe/egui)
│   ├── tray.rs          # System tray icon and menu
│   ├── vpn.rs           # VPN connection orchestration
│   ├── wg.rs            # WireGuard data plane over TLS
│   ├── tun.rs           # TUN device (macOS/Linux/Windows)
│   ├── route.rs         # Routing, kill switch, policy routing
│   ├── mesh.rs          # P2P mesh networking
│   ├── api.rs           # Control API, auto-update, geo lookup
│   ├── profiles.rs      # Server profile storage
│   └── fingerprint.rs   # Device fingerprinting
├── scripts/
│   └── build-dmg.sh     # macOS DMG builder
└── .github/workflows/
    └── release.yml       # Automated release pipeline
```

## Building from Source

```bash
git clone https://github.com/NexGuard-VPN/client.git
cd client
cargo build --release
```

## Release Process

Fully automated via GitHub Actions. Tag push builds all platforms, creates GitHub Release, deploys to server, and updates download links:

```bash
git tag v1.10.0
git push --tags
```

Builds: macOS ARM + Intel + DMG, Linux AMD64 + ARM64, Windows. Deploys to [nexguard.sh/download](https://nexguard.sh/download).

## Security

- End-to-end encryption (WireGuard protocol)
- Automatic key rotation every 24 hours
- No logs, no telemetry, no tracking
- Kill switch prevents traffic leaks
- TLS obfuscation hides VPN traffic from DPI
- Open source — audit the code: [github.com/NexGuard-VPN/client](https://github.com/NexGuard-VPN/client)

## Contributing

Issues and pull requests are welcome. Please open an issue first to discuss what you'd like to change.

## Links

- **Website**: [nexguard.sh](https://nexguard.sh)
- **Download**: [nexguard.sh/download](https://nexguard.sh/download)
- **Deploy a server**: [nexguard.sh/deploy](https://nexguard.sh/deploy)
- **Dashboard**: [nexguard.sh/dashboard](https://nexguard.sh/dashboard)
- **Pricing**: [nexguard.sh/#pricing](https://nexguard.sh/#pricing)
- **Contact**: [hello@nexguard.sh](mailto:hello@nexguard.sh)

## License

MIT License. See [LICENSE](LICENSE) for details.

---

<p align="center">
  <a href="https://nexguard.sh"><strong>nexguard.sh</strong></a> &mdash; Dedicated VPN infrastructure for teams.
</p>
