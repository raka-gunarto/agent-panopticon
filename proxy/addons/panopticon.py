"""Panopticon — mitmproxy addon for transparent inbound/outbound proxy inspection.

Features:
  - Request/response logging with direction tagging (INBOUND / OUTBOUND)
  - Outbound domain allowlist enforcement
  - Rejection of direct-IP destinations on egress
  - Secret placeholder replacement in outbound request headers and bodies
  - Best-effort inbound secret detection and redaction
  - DNS query filtering and logging (blocks non-allowlisted domains)

Environment variables:
  ALLOWLIST_FILE                       Path to domain allowlist (default: /etc/proxy/config/allowlist.txt)
  PLACEHOLDER_SECRET_VALUE_<name>      Actual secret value for placeholder <name>
  PLACEHOLDER_SECRET_DOMAINS_<name>    Comma-separated domains where <name> may be injected
"""

from __future__ import annotations

import ipaddress
import os
import secrets as strong_prng
import string
from datetime import datetime, timezone
from typing import Any

from mitmproxy import ctx, dns, http
from mitmproxy.flow import Flow

LOG_FORMAT = "[{timestamp}] [{direction}] [{client}] {method} {url} → {status}"

# Header names (lowercase) commonly used to carry secrets / tokens / keys.
_SECRET_HEADER_NAMES: frozenset[str] = frozenset({
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "api-key",
    "apikey",
    "x-auth-token",
    "x-access-token",
    "x-secret-key",
    "x-token",
    "x-session-token",
    "x-api-secret",
    "x-webhook-secret",
    "x-signing-secret",
})


def _extract_apex_domain(host: str) -> str:
    """Apex domain extraction (last two domain labels)."""
    host = host.lower().rstrip(".").split(":")[0]  # strip port & trailing dot
    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def _strip_auth_prefix(value: str) -> tuple[str, str]:
    """Separate an auth-scheme prefix (e.g. 'Bearer ') from the token."""
    for prefix in ("Bearer ", "Basic ", "Token ", "token "):
        if value.startswith(prefix):
            return prefix, value[len(prefix):]
    return "", value

def _generate_placeholder() -> str:
    """Generate a random placeholder token string."""
    rand = "".join(
        strong_prng.choice(string.ascii_uppercase + string.digits)
        for _ in range(32)
    )
    return f"PANOPTICON_CAPTURED_{rand}"


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
        # Dynamically captured inbound secrets
        self._captured_secrets: list[_SecretEntry] = []
        self._captured_value_map: dict[str, _SecretEntry] = {}  # token → entry

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
        if self._is_outbound(flow):
            self._log_http(flow, phase="request")
            if not flow.response:
                self._inject_secrets(flow, flow.request.pretty_host.lower())
        else:
            # Inbound: capture secrets *before* logging so the log shows
            # redacted values rather than real secrets.
            self._capture_inbound_secrets(flow)
            self._log_http(flow, phase="request")

    def response(self, flow: http.HTTPFlow) -> None:
        self._log_http(flow, phase="response")

    def error(self, flow: http.HTTPFlow) -> None:
        direction = self._direction_label(flow)
        ctx.log.error(
            f"[{direction}] ERROR {flow.request.method} {flow.request.pretty_url}: "
            f"{flow.error.msg if flow.error else 'unknown'}"
        )

    # Inbound secret capture

    def _capture_inbound_secrets(self, flow: http.HTTPFlow) -> None:
        """Detect and redact secrets in inbound request headers (best effort).

        Detected secrets are replaced with random placeholders and registered
        in ``self.secrets`` so that the normal outbound injection path can
        substitute them back — but only when the outbound destination matches
        the apex domain of the original inbound request's Host header.
        """
        host = flow.request.pretty_host.lower()
        apex = _extract_apex_domain(host)

        for hdr_name in list(flow.request.headers.keys()):
            if hdr_name.lower() not in _SECRET_HEADER_NAMES:
                continue

            hdr_value = flow.request.headers[hdr_name]

            # Separate any auth-scheme prefix so we only replace the token
            prefix, token = _strip_auth_prefix(hdr_value)

            # Deduplicate: reuse existing placeholder for an identical token
            if token in self._captured_value_map:
                existing = self._captured_value_map[token]
                flow.request.headers[hdr_name] = prefix + existing.placeholder
                ctx.log.info(
                    f"Replaced known secret in header '{hdr_name}' "
                    f"with existing placeholder"
                )
                continue

            # Generate new placeholder and register as a secret entry
            placeholder = _generate_placeholder()
            name = f"captured_{len(self._captured_secrets)}"
            entry = _SecretEntry(name, token, {f"*.{apex}"})
            entry.placeholder = placeholder  # override default placeholder

            self.secrets.append(entry)
            self._captured_secrets.append(entry)
            self._captured_value_map[token] = entry

            flow.request.headers[hdr_name] = prefix + placeholder

            masked = token[:4] + "***" if len(token) > 4 else "***"
            ctx.log.info(
                f"Captured secret from header '{hdr_name}' ({masked}), "
                f"locked to '*.{apex}' → {placeholder}"
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
