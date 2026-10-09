"""Validated connection parsing for the shared engine; no provider rules or I/O."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Connection:
    start: int
    end: int
    endpoint_start: int
    endpoint_end: int
    authentication: tuple[tuple[int, int], ...] = ()
    proxy_scheme: bool = False


_HOST = r"(?:\[[0-9a-fA-F:.%\w\-]+\]|[A-Za-z0-9](?:[A-Za-z0-9.\-]*[A-Za-z0-9])?)"
_AUTH = r"[^\s@/\"'<>\[\]{},;]+"
_CONNECTION = re.compile(
    r"(?<![\w.\-])(?:(?P<scheme>https?|socks[45]h?)://)?"
    r"(?:(?P<user>" + _AUTH + r")[ \t]*:[ \t]*(?P<password>" + _AUTH + r")[ \t]*@[ \t]*)?"
    r"(?P<host>" + _HOST + r")\s*:\s*(?P<port>\d{1,5})(?!\d)"
    r"(?:[ \t]*:[ \t]*(?P<tail_user>[^\s:@/\"'<>\[\]{},;]+)[ \t]*:[ \t]*(?P<tail_pass>[^\s@/\"'<>\[\]{},;]+))?"
    r"(?=$|[\s/\"'<>{},;?&#)\]])", re.I)


def valid_host(host: str, *, context: bool = False) -> bool:
    if host.startswith('[') and host.endswith(']'):
        try:
            ipaddress.IPv6Address(host[1:-1])
            return True
        except ValueError:
            return False
    if re.fullmatch(r"[0-9.]+", host):
        try:
            ipaddress.IPv4Address(host)
            return True
        except ValueError:
            return False
    if len(host) > 253 or not all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", part)
                                  for part in host.rstrip('.').split('.')):
        return False
    # Single labels are ambiguous (e.g. retry:3). Require proxy/URL/auth context.
    return context or host.lower() == 'localhost' or '.' in host


def parse_connections(text: str, *, proxy_context: bool = False) -> list[Connection]:
    connections = []
    for match in _CONNECTION.finditer(text):
        scheme = match.group('scheme')
        credentials = bool(match.group('user') or match.group('tail_user'))
        if not 1 <= int(match.group('port')) <= 65535:
            continue
        if not valid_host(match.group('host'), context=proxy_context or bool(scheme) or credentials):
            continue
        auth = []
        for name in ('user', 'password', 'tail_user', 'tail_pass'):
            if match.group(name):
                auth.append(match.span(name))
        connections.append(Connection(match.start(), match.end(), match.start('host'), match.end('port'),
                                      tuple(auth), bool(scheme and scheme.lower().startswith('socks'))))
    return connections


def proxy_name(name: str) -> bool:
    compact = re.sub(r"[^a-z0-9]", "", name.lower())
    # Semantic concepts, including previously unseen provider prefixes.
    return 'proxy' in compact or 'proxies' in compact


def proxy_role(name: str) -> str | None:
    compact = re.sub(r"[^a-z0-9]", "", name.lower())
    for role, endings in (
        ('username', ('username', 'user', 'login', 'userid')),
        ('password', ('password', 'passwd', 'pwd', 'pass')),
        ('auth', ('authorization', 'authentication', 'credentials', 'auth')),
        ('host', ('hostname', 'address', 'host', 'ip')),
        ('port', ('port',)),
    ):
        if any(compact.endswith(ending) for ending in endings):
            return role
    return None
