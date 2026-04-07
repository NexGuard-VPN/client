# NexGuard

Dedicated VPN client for teams. Desktop app with menubar tray, auto-connect, kill switch, and DPI bypass. macOS, Linux, Windows.

## Install

```bash
curl -fsSL https://nexguard.sh/install | sudo bash
```

Or download from [nexguard.sh/download](https://nexguard.sh/download) (DMG for macOS, binary for Linux/Windows).

## Connect

```bash
sudo nexguard --token TOKEN --internet
```

GUI opens automatically. Pass `--name "Office VPN"` to label the server profile.

For CLI-only (headless servers):

```bash
sudo nexguard --cli --token TOKEN --internet
```

## Features

- **Menubar tray** with connect/disconnect, server list, traffic stats
- **Auto-connect** on launch when token is provided
- **Kill switch** blocks all traffic if VPN drops
- **DPI bypass** via TLS obfuscation on port 443
- **Auto-reconnect** with exponential backoff
- **Multi-server** profiles saved locally
- **Auto key rotation** every 24 hours
- **Mesh networking** with P2P tunnels between devices
- **Zero open ports** required on server side
- **Self-update** checks for new versions on launch

## Platforms

| OS | GUI | Tray | CLI | Status |
|----|-----|------|-----|--------|
| macOS ARM64 | yes | yes | yes | stable |
| macOS x86_64 | yes | yes | yes | stable |
| Linux x86_64 | yes | yes | yes | stable |
| Linux ARM64 | yes | yes | yes | stable |
| Windows x86_64 | yes | - | yes | beta |

## Usage

```
nexguard [OPTIONS]

Options:
  -t, --token TOKEN     Device token (from dashboard)
  -n, --name NAME       Server profile name
  --internet            Route all traffic through VPN
  --kill-switch         Block traffic if VPN drops
  --cli                 Headless mode (no GUI)
  --version             Show version
```

## Release

Tag push triggers automated build and deploy for all platforms:

```bash
git tag v1.10.0
git push --tags
```

GitHub Actions builds macOS (ARM + Intel + DMG), Linux (AMD64 + ARM64), Windows, generates `version.json`, deploys to server, and creates GitHub Release.

## License

MIT
