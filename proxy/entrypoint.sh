#!/bin/sh
set -e

# Panopticon — iptables setup & mitmweb launcher
# Runs as root to configure iptables, then drops to mitmuser.

PROXY_UID=1337
TRANSPARENT_PORT=8080
DNS_PORT=5353

# Configurable ports (with defaults)
INBOUND_HTTPS_PORT=${INBOUND_HTTPS_PORT:-443}
INBOUND_WSS_PORT=${INBOUND_WSS_PORT:-12000}
APP_HTTP_PORT=${APP_HTTP_PORT:-8443}
APP_WS_PORT=${APP_WS_PORT:-12001}
DASHBOARD_PORT=${DASHBOARD_PORT:-8081}

# --- Port clash detection ---
check_no_clashes() {
  local seen=""
  for port in "$@"; do
    for s in $seen; do
      if [ "$port" = "$s" ]; then
        echo "[panopticon] ERROR: port clash — port $port is assigned to more than one role" >&2
        exit 1
      fi
    done
    seen="$seen $port"
  done
}

check_no_clashes \
  "${TRANSPARENT_PORT}" \
  "${DNS_PORT}" \
  "${INBOUND_HTTPS_PORT}" \
  "${INBOUND_WSS_PORT}" \
  "${APP_HTTP_PORT}" \
  "${APP_WS_PORT}" \
  "${DASHBOARD_PORT}"

echo "[panopticon] configuring iptables …"

# --- NAT: redirect app traffic to mitmproxy ---

# DNS redirect (inserted before Docker's DOCKER_OUTPUT chain); exempt mitmproxy UID
iptables -t nat -I OUTPUT 1 -p udp --dport 53 -m owner ! --uid-owner ${PROXY_UID} -j REDIRECT --to-ports ${DNS_PORT}
iptables -t nat -I OUTPUT 2 -p tcp --dport 53 -m owner ! --uid-owner ${PROXY_UID} -j REDIRECT --to-ports ${DNS_PORT}

# Exempt mitmproxy from further redirection
iptables -t nat -A OUTPUT -m owner --uid-owner ${PROXY_UID} -j RETURN

# Redirect outbound HTTPS → transparent proxy
iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-ports ${TRANSPARENT_PORT}

# --- OUTPUT: restrict app egress ---
# Block non-proxy processes from connecting to the dashboard on loopback
iptables -I OUTPUT 1 -o lo -p tcp --dport ${DASHBOARD_PORT} -m owner ! --uid-owner ${PROXY_UID} -j REJECT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -d 127.0.0.0/8 -j ACCEPT
iptables -A OUTPUT -m owner --uid-owner ${PROXY_UID} -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m owner ! --uid-owner ${PROXY_UID} -j DROP

# --- INPUT: only allow reverse-proxy + dashboard ports ---
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp --dport ${INBOUND_HTTPS_PORT} -j ACCEPT
iptables -A INPUT -p tcp --dport ${INBOUND_WSS_PORT}   -j ACCEPT
iptables -A INPUT -p tcp --dport ${DASHBOARD_PORT}     -j ACCEPT
iptables -A INPUT -j DROP

# --- FORWARD: block ---
iptables -A FORWARD -j DROP

echo "[panopticon] iptables configured ✓"

# Ensure mitmproxy home exists with correct perms
mkdir -p /home/mitmuser/.mitmproxy
chown -R ${PROXY_UID}:${PROXY_UID} /home/mitmuser/.mitmproxy

# Build and exec mitmweb
MITM_CMD="mitmweb \
  --mode transparent@${TRANSPARENT_PORT} \
  --mode reverse:http://localhost:${APP_HTTP_PORT}/@${INBOUND_HTTPS_PORT} \
  --mode reverse:http://localhost:${APP_WS_PORT}/@${INBOUND_WSS_PORT} \
  --mode dns@${DNS_PORT} \
  --showhost \
  --set block_global=false \
  --set connection_strategy=lazy \
  --web-host 0.0.0.0 \
  --web-port ${DASHBOARD_PORT} \
  --no-web-open-browser \
  -s /etc/proxy/addons/panopticon.py"

echo "[panopticon] starting mitmweb (uid ${PROXY_UID})"
echo "[panopticon] dashboard → http://<container-ip>:${DASHBOARD_PORT}/ (loopback blocked)"

exec gosu mitmuser ${MITM_CMD}
