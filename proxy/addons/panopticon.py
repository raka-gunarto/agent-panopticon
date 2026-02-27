"""Panopticon — mitmproxy addon for transparent inbound/outbound proxy inspection.

Features:
  - Request/response logging with direction tagging (INBOUND / OUTBOUND)
  - Outbound domain allowlist enforcement
  - Rejection of direct-IP destinations on egress
  - Secret placeholder replacement in outbound request headers and bodies
  - DNS query filtering and logging (blocks non-allowlisted domains)

Environment variables:
  ALLOWLIST_FILE                       Path to domain allowlist (default: /etc/proxy/config/allowlist.txt)
  PLACEHOLDER_SECRET_VALUE_<name>      Actual secret value for placeholder <name>
  PLACEHOLDER_SECRET_DOMAINS_<name>    Comma-separated domains where <name> may be injected
"""

from __future__ import annotations

import ipaddress
import os
from datetime import datetime, timezone
from typing import Any

from mitmproxy import ctx, dns, http
from mitmproxy.flow import Flow

LOG_FORMAT = "[{timestamp}] [{direction}] [{client}] {method} {url} → {status}"


def _domain_matches(host: str, patterns: set[str]) -> bool:
    """Check if host matches any pattern (exact or wildcard *.example.com)."""
    host = host.lower().rstrip(".")
    for pattern in patterns:
        pattern = pattern.lower().rstrip(".")
        if pattern.startswith("*."):
            suffix = pattern[2:]
            if host == suffix or host.endswith("." + suffix):
                return True
        elif host == pattern:
            return True
    return False


def _is_ip(host: str) -> bool:
    """Return True when host is a literal IPv4/IPv6 address."""
    try:
        ipaddress.ip_address(host.split("%")[0])
        return True
    except ValueError:
        return False


class _SecretEntry:
    __slots__ = ("name", "placeholder", "value", "allowed_domains")

    def __init__(self, name: str, value: str, allowed_domains: set[str]):
        self.name = name
        self.placeholder = f"PLACEHOLDER_SECRET_VALUE_{name}"
        self.value = value
        self.allowed_domains = allowed_domains


def _load_secrets() -> list[_SecretEntry]:
    """Parse PLACEHOLDER_SECRET_VALUE_* / PLACEHOLDER_SECRET_DOMAINS_* env vars."""
    values: dict[str, str] = {}
    domains: dict[str, set[str]] = {}
    for key, val in os.environ.items():
        if key.startswith("PLACEHOLDER_SECRET_VALUE_"):
            name = key[len("PLACEHOLDER_SECRET_VALUE_"):]
            values[name] = val
        elif key.startswith("PLACEHOLDER_SECRET_DOMAINS_"):
            name = key[len("PLACEHOLDER_SECRET_DOMAINS_"):]
            domains[name] = {d.strip().lower() for d in val.split(",") if d.strip()}
    return [
        _SecretEntry(name, val, domains.get(name, set()))
        for name, val in values.items()
    ]


def _load_allowlist(path: str) -> set[str]:
    """Read newline-delimited allowlist file; ignores blanks and # comments."""
    result: set[str] = set()
    if not os.path.isfile(path):
        ctx.log.warn(f"Allowlist file not found: {path}")
        return result
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                result.add(line.lower())
    return result


class Panopticon:
    """mitmproxy addon — transparent proxy inspector."""

    def __init__(self) -> None:
        self.allowlist: set[str] = set()
        self.secrets: list[_SecretEntry] = []

    def load(self, loader: Any) -> None:
        allowlist_path = os.environ.get("ALLOWLIST_FILE", "/etc/proxy/config/allowlist.txt")
        self.allowlist = _load_allowlist(allowlist_path)
        self.secrets = _load_secrets()
        ctx.log.info(
            f"Panopticon loaded — {len(self.allowlist)} allowlist entries, "
            f"{len(self.secrets)} secret placeholders"
        )
        for entry in self.secrets:
            masked = entry.value[:3] + "***" if len(entry.value) > 3 else "***"
            ctx.log.info(
                f"  secret [{entry.name}] value={masked} "
                f"domains={entry.allowed_domains or '(any)'}"
            )

    # Direction detection

    @staticmethod
    def _is_outbound(flow: Flow) -> bool:
        try:
            return "transparent" in str(flow.client_conn.proxy_mode)
        except Exception:
            return False

    @staticmethod
    def _direction_label(flow: Flow) -> str:
        try:
            mode = str(flow.client_conn.proxy_mode)
        except Exception:
            return "UNKNOWN"
        if "transparent" in mode:
            return "OUTBOUND"
        if "reverse" in mode:
            return "INBOUND"
        return "UNKNOWN"

    # Logging

    def _log_http(self, flow: http.HTTPFlow, phase: str = "") -> None:
        direction = self._direction_label(flow)
        client = flow.client_conn.peername[0] if flow.client_conn.peername else "?"
        status = str(flow.response.status_code) if flow.response else "…"
        ts = datetime.now(tz=timezone.utc).isoformat(timespec="milliseconds")
        msg = LOG_FORMAT.format(
            timestamp=ts, direction=direction, client=client,
            method=flow.request.method, url=flow.request.pretty_url, status=status,
        )
        if phase:
            msg = f"{msg} ({phase})"
        ctx.log.info(msg)

    # HTTP hooks

    def requestheaders(self, flow: http.HTTPFlow) -> None:
        """Enforce egress policy early (before body is streamed)."""
        if not self._is_outbound(flow):
            return

        host = flow.request.pretty_host.lower()

        if _is_ip(host):
            flow.response = http.Response.make(
                403, b"PANOPTICON: direct IP destinations are not allowed.\n",
                {"Content-Type": "text/plain"},
            )
            ctx.log.warn(f"BLOCKED (IP dest): {flow.request.method} {flow.request.pretty_url}")
            return

        if not _domain_matches(host, self.allowlist):
            flow.response = http.Response.make(
                403, f"PANOPTICON: domain '{host}' is not in the egress allowlist.\n".encode(),
                {"Content-Type": "text/plain"},
            )
            ctx.log.warn(f"BLOCKED (allowlist): {flow.request.method} {flow.request.pretty_url}")

    def request(self, flow: http.HTTPFlow) -> None:
        self._log_http(flow, phase="request")
        if not self._is_outbound(flow) or flow.response:
            return
        self._inject_secrets(flow, flow.request.pretty_host.lower())

    def response(self, flow: http.HTTPFlow) -> None:
        self._log_http(flow, phase="response")

    def websocket_message(self, flow: http.HTTPFlow) -> None:
        """Inject secrets into outbound websocket messages."""
        if not self._is_outbound(flow) or flow.websocket is None:
            return
        msg = flow.websocket.messages[-1]
        if not msg.from_client:
            return
        self._inject_secrets_ws(flow, flow.request.pretty_host.lower(), msg)

    def error(self, flow: http.HTTPFlow) -> None:
        direction = self._direction_label(flow)
        ctx.log.error(
            f"[{direction}] ERROR {flow.request.method} {flow.request.pretty_url}: "
            f"{flow.error.msg if flow.error else 'unknown'}"
        )

    # Secret injection

    def _inject_secrets(self, flow: http.HTTPFlow, host: str) -> None:
        for entry in self.secrets:
            ph = entry.placeholder
            in_headers = any(ph in v for v in flow.request.headers.values())
            in_body = flow.request.content is not None and ph.encode() in flow.request.content

            if not in_headers and not in_body:
                continue

            if entry.allowed_domains and not _domain_matches(host, entry.allowed_domains):
                flow.response = http.Response.make(
                    403,
                    f"PANOPTICON: secret '{entry.name}' not authorised for '{host}'.\n".encode(),
                    {"Content-Type": "text/plain"},
                )
                ctx.log.warn(f"BLOCKED (secret domain): {entry.name} → {host}")
                return

            if in_headers:
                for hdr in list(flow.request.headers.keys()):
                    val = flow.request.headers[hdr]
                    if ph in val:
                        flow.request.headers[hdr] = val.replace(ph, entry.value)
                        ctx.log.info(f"Injected secret [{entry.name}] into header '{hdr}'")

            if in_body and flow.request.content is not None:
                flow.request.content = flow.request.content.replace(ph.encode(), entry.value.encode())
                ctx.log.info(f"Injected secret [{entry.name}] into body")

    # WebSocket secret injection

    def _inject_secrets_ws(self, flow: http.HTTPFlow, host: str, msg: Any) -> None:
        content = msg.content
        if isinstance(content, str):
            content_bytes = content.encode()
        else:
            content_bytes = content

        for entry in self.secrets:
            ph = entry.placeholder
            if ph.encode() not in content_bytes:
                continue

            if entry.allowed_domains and not _domain_matches(host, entry.allowed_domains):
                msg.drop()
                ctx.log.warn(f"BLOCKED (ws secret domain): {entry.name} → {host}")
                return

            content_bytes = content_bytes.replace(ph.encode(), entry.value.encode())
            ctx.log.info(f"Injected secret [{entry.name}] into websocket message")

        if isinstance(msg.content, str):
            msg.content = content_bytes.decode()
        else:
            msg.content = content_bytes

    # DNS hooks

    def dns_request(self, flow: dns.DNSFlow) -> None:
        for q in flow.request.questions:
            name = q.name.rstrip(".")
            ctx.log.info(f"[DNS] query: {q.name} type={q.type}")
            if name and not _domain_matches(name, self.allowlist):
                ctx.log.warn(f"BLOCKED (DNS allowlist): {q.name}")
                flow.response = dns.Message(
                    flow.request.timestamp,   # timestamp
                    flow.request.id,          # id
                    False,                    # query (False = response)
                    flow.request.op_code,     # op_code
                    False,                    # authoritative_answer
                    False,                    # truncation
                    flow.request.recursion_desired,
                    False,                    # recursion_available
                    0,                        # reserved
                    5,                        # response_code (REFUSED)
                    list(flow.request.questions),
                    [],                       # answers
                    [],                       # authorities
                    [],                       # additionals
                )
                return

    def dns_response(self, flow: dns.DNSFlow) -> None:
        if flow.response:
            for a in flow.response.answers:
                ctx.log.info(f"[DNS] answer: {a.name} type={a.type} → {a.data}")

    def dns_error(self, flow: dns.DNSFlow) -> None:
        ctx.log.error(
            f"[DNS] error: {', '.join(q.name for q in flow.request.questions)}: "
            f"{flow.error.msg if flow.error else 'unknown'}"
        )


addons = [Panopticon()]
