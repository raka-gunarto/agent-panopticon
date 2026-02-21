# Panopticon – Transparent mitmproxy Sidecar

A containerised **mitmproxy** deployment that acts as a transparent inbound/outbound proxy for a co-located Docker container. The target app has **zero direct network access**; every byte flows through the proxy. Proxy + killswitch enforced via iptables rules.

Requests are also checked for configured secret placeholders and swaps them in with real secrets for allowed destinations.

## Motivation

Wanted a simple proxy to wrap around fully autonomous AI agents to have more control and visibility over its network comms and remove secrets from its environment.

### Sample Use Cases

- COMING SOON! Using this in my config for a personal deployment of OpenClaw (alongside other hardening), will publish soon.

## Architecture

```
                    ┌─────────────────────────────────────────────────┐
                    │  shared network namespace (network_mode:service)│
                    │                                                 │
                    │  ┌───────────────┐      ┌──────────────────┐    │
   external         │  │   mitmproxy   │      │   app container  │    │
   clients ────443──┼──▶  reverse:443  ├──lo──▶  :8443 (HTTP)    │    │
            ─12000──┼──▶  reverse:12000├──lo──▶  :12001 (WS)     │    │
                    │  │               │      │                  │    │
                    │  │  transparent  ◀──lo───  outbound :443   │    │
                    │  │   :8080       ├──────▶  internet        │    │
                    │  │               │      │                  │    │
                    │  │  dns :5353    ◀──lo───  DNS queries     │    │
                    │  └───────────────┘      └──────────────────┘    │
                    └─────────────────────────────────────────────────┘
```

## Quick Start

```bash
# 1. Create .env from the example
cp .env.example .env
vim .env # set real secrets in .env

# 2. Edit the domain allowlist
vim allowlist.txt

# 3. Launch
docker compose up --build
```

Open **http://127.0.0.1:8081** to view the mitmweb dashboard.

## Features Being Considered / Implemented

- [ ] mitmweb too heavy: use mitmdump and make a custom dashboard with log rotations
- [ ] Inbound traffic filtering
    - [ ] Inbound IP allowlist (either through mitmproxy or iptables rules)
    - [ ] Simple filtering of jailbreak patterns
    - [ ] Best effort detection of auth secrets and replace on the fly?
- [ ] Notify of blocks via webhook
- [ ] Editable egress allowlist
- [ ] Certificate pinning?

## Files

```
├── docker-compose.yml
├── .env.example             # sample secrets & port config
├── .gitignore
├── allowlist.txt            # outbound domain allowlist (mounted into proxy)
├── README.md
└── proxy/
    ├── Dockerfile
    ├── entrypoint.sh        # iptables rules → drop privs → exec mitmweb
    └── addons/
        └── panopticon.py    # mitmproxy addon (logging, allowlist, secrets)
```

## Configuration

### Ports

All ports are configurable via `.env`:

| Variable | Default | Description |
|---|---|---|
| `INBOUND_HTTPS_PORT` | 443 | External HTTPS reverse proxy port |
| `INBOUND_WSS_PORT` | 12000 | External WSS reverse proxy port |
| `APP_HTTP_PORT` | 8443 | App's internal HTTP listener |
| `APP_WS_PORT` | 12001 | App's internal WS listener |
| `DASHBOARD_PORT` | 8081 | mitmweb dashboard port (localhost only) |

### Domain Allowlist

Edit `allowlist.txt` (mounted read-only into the proxy). Supports exact matches and wildcards:

```
example.com        # exact match only
*.example.com      # matches sub.example.com, example.com
```

### Secret Injection

The app uses placeholder strings like `PLACEHOLDER_SECRET_VALUE_OPENAI` in its requests. The proxy replaces these with real values from `.env`, but **only** when the destination domain is authorised:

```env
PLACEHOLDER_SECRET_VALUE_OPENAI=sk-real-key
PLACEHOLDER_SECRET_DOMAINS_OPENAI=api.openai.com
```

If the placeholder is found but the destination isn't authorised, the request is blocked with HTTP 403.

## iptables Rules

| Chain | Rule | Purpose |
|---|---|---|
| nat OUTPUT | `--dport 443 → REDIRECT :8080` | Outbound HTTPS → transparent proxy |
| nat OUTPUT | `--dport 53 → REDIRECT :5353` | Outbound DNS → mitmproxy DNS |
| nat OUTPUT | `--uid-owner 1337 → RETURN` | Exempt mitmproxy (prevent loops) |
| filter OUTPUT | `--uid-owner 1337 → ACCEPT` | mitmproxy can reach internet |
| filter OUTPUT | `-o lo → ACCEPT` | Proxy ↔ app on loopback |
| filter OUTPUT | default `DROP` | Block all other app egress |
| filter INPUT | `--dport 443,12000,8081 → ACCEPT` | Allow reverse proxy + dashboard |
| filter INPUT | default `DROP` | Block direct access to app ports |
| filter FORWARD | `DROP` | No forwarding |

## Adapting for Your App

1. Replace the `app` service with your real image
2. Ensure it listens on `APP_HTTP_PORT` and `APP_WS_PORT`
3. Trust the mitmproxy CA at `/mitmproxy-certs/mitmproxy-ca-cert.pem`
4. Edit `allowlist.txt` for your required domains
5. Add `PLACEHOLDER_SECRET_*` entries to `.env`

## Testing

```bash
# Allowed outbound (should succeed):
docker exec panopticon-app wget -qO- https://pypi.org/simple/ | head -3

# Blocked domain:
docker exec panopticon-app wget -qO- https://example.com/

# Blocked IP destination:
docker exec panopticon-app wget -qO- https://1.1.1.1/

# Inbound reverse proxy:
curl -k https://localhost/

# Dashboard:
curl http://127.0.0.1:8081/
```
