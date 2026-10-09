"""Shared local credential detection, safe findings, and redaction policy.

Adapters supply source spans. Rules live here, never in JSON or UI handlers.
Findings intentionally contain no matched text; offsets refer to original input.
"""
from __future__ import annotations

import base64
import json
import math
import re
from pathlib import Path
from collections import Counter
from dataclasses import asdict, dataclass, field, replace
from typing import Literal
from src.connections import parse_connections, proxy_name, proxy_role


class DetectionError(ValueError):
    """Safe error whose message must never include input content."""


class CredentialBlocked(DetectionError):
    pass


REDACTION_CATEGORIES = (
    ('USERNAME', 'Usernames'), ('API_KEY', 'API keys'), ('TOKEN', 'Tokens'),
    ('PASSWORD', 'Passwords'), ('COOKIE', 'Cookies'),
    ('PRIVATE_KEY', 'Private keys'), ('AUTHORIZATION', 'Authorization headers'),
    ('PROXY_CONNECTION_SECRET', 'Proxy authentication'), ('SECRET', 'Other secrets'),
)


@dataclass(frozen=True)
class CustomPattern:
    name: str
    expression: str = field(repr=False)
    category: str = "SECRET"
    confidence: float = 0.95


@dataclass(frozen=True)
class CredentialPolicy:
    names: bool = True
    values: bool = True
    context: bool = True
    threshold: float = 0.7
    action: Literal["redact", "block", "warn", "report"] = "redact"
    replacement: str = "[REDACTED]"
    custom_names: tuple[str, ...] = ()
    # Exact case-sensitive field names or adapter paths, never wildcards.
    exceptions: tuple[str, ...] = ()
    custom_patterns: tuple[CustomPattern, ...] = ()
    formats: tuple[str, ...] = ("json", "chat", "config")
    pattern_timeout: float = 0.025
    connections: bool = True
    proxy_mode: Literal["standard", "strict"] = "standard"
    proxy_fields: tuple[str, ...] = ()
    disabled_categories: tuple[str, ...] = ()

    def __post_init__(self):
        if set(self.disabled_categories) - {item[0] for item in REDACTION_CATEGORIES}:
            raise DetectionError('Unsupported redaction category.')
        if not any((self.names, self.values, self.context)):
            raise DetectionError("At least one credential detection strategy must be enabled.")
        if not 0 <= self.threshold <= 1 or not 0 < self.pattern_timeout <= 1:
            raise DetectionError("Invalid detection threshold or pattern timeout.")
        if self.action not in {"redact", "block", "warn", "report"}:
            raise DetectionError("Invalid credential policy action.")
        if self.proxy_mode not in {"standard", "strict"}:
            raise DetectionError("Invalid proxy privacy mode.")
        if not self.formats or set(self.formats) - {"json", "chat", "config"}:
            raise DetectionError("Unsupported credential input format.")
        if any(not item or item in {"*", "/", "**"} for item in self.exceptions):
            raise DetectionError("Exceptions must name a specific field or source path.")
        for pattern in self.custom_patterns:
            if not 0 <= pattern.confidence <= 1 or len(pattern.expression) > 4096:
                raise DetectionError("Invalid custom credential pattern.")


@dataclass(frozen=True)
class Finding:
    category: str
    start: int
    end: int
    confidence: float
    strategy: str
    source: str = "text"
    location: str = ""
    sensitive: bool = True

    def audit(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class DetectionResult:
    text: str = field(repr=False)
    findings: tuple[Finding, ...] = ()
    action: str = "redact"

    def audit(self) -> dict:
        return {"action": self.action, "count": len(self.findings),
                "sensitive_count": sum(finding.sensitive for finding in self.findings),
                "findings": [finding.audit() for finding in self.findings]}


def identifier_words(name: str) -> tuple[str, ...]:
    split = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name)
    split = re.sub(r"([A-Z])([A-Z][a-z])", r"\1 \2", split)
    return tuple(re.findall(r"[a-z0-9]+", split.lower()))


_METADATA = {"count", "length", "size", "enabled", "disabled", "required", "type",
             "name", "description", "hint", "label", "expires", "expiry", "expiration",
             "ttl", "algorithm", "format", "example", "documentation", "status", "id"}
_SENSITIVE = ("apikey", "apitoken", "accesskey", "secretkey", "privatekey", "signingkey",
              "encryptionkey", "clientsecret", "webhooksecret", "signingsecret", "password",
              "passwd", "passphrase", "passcode", "refreshtoken", "accesstoken", "authtoken",
              "sessiontoken", "sessionkey", "sessionid", "credential", "credentials")


def name_category(name: str) -> str | None:
    """Use concepts and compound identifiers, not an inventory of providers."""
    words = identifier_words(name)
    if not words:
        return None
    compact = "".join(words)
    if compact in {'username', 'user', 'login', 'loginname', 'userid', 'accountusername'} or compact.endswith(('username', 'loginname')):
        return 'USERNAME'
    if compact.endswith(("accesskeyid", "sessionid")):
        return "API_KEY"
    if words[-1] in _METADATA or any(compact.endswith(suffix) for suffix in _METADATA):
        return None
    if compact.endswith(('cookie', 'cookies', 'cookiejar')):
        return 'COOKIE'
    if 'privatekey' in compact:
        return 'PRIVATE_KEY'
    if compact in {'auth', 'authorization'} or compact.endswith('authorizationheader'):
        return 'AUTHORIZATION'
    if compact.endswith('token'):
        return 'TOKEN'
    if compact in {"pin", "pwd", "pass", "auth", "authorization", "cookie", "cookies"}:
        return "PASSWORD" if compact in {"pwd", "pass"} else "SECRET"
    if words[-1] in {"pwd", "pass"}:
        return "PASSWORD"
    if set(words) & {"api", "auth", "oauth", "access", "refresh", "session", "client", "signing"}:
        if set(words) & {"tok", "k", "sec", "key", "token", "secret"}:
            return "API_KEY"
    if any(concept in compact for concept in _SENSITIVE):
        return "PASSWORD" if any(word in compact for word in ("password", "passwd", "passphrase", "passcode")) else "API_KEY"
    if words[-1] in {"token", "secret", "pin", "cookie", "cookies", "pwd"}:
        return "PASSWORD" if words[-1] == "pwd" else "SECRET"
    if compact.endswith(("token", "secret", "password")) and compact not in {"token", "secret"}:
        return "SECRET"
    if compact in {"token", "secret", "connectionstring", "databaseurl", "dsn"}:
        return "SECRET"
    return None


_FORMATS = (
    ("API_KEY", r"\bsk-(?:proj-|svcacct-|ant-|live-|test-)?[A-Za-z0-9_\-]{16,}\b"),
    ("API_KEY", r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b"),
    ("API_KEY", r"\bgh[pousr]_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    ("API_KEY", r"\b(?:glpat-|sntrys_)[A-Za-z0-9_\-]{20,}\b"),
    ("API_KEY", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|\bAIza[0-9A-Za-z_\-]{35}\b"),
    ("API_KEY", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    ("API_KEY", r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"),
    ("AUTHORIZATION", r"(?i)\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=\-]+"),
    ("PRIVATE_KEY", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"),
)
_COMPILED_FORMATS = tuple((category, re.compile(pattern)) for category, pattern in _FORMATS)
_JWT = re.compile(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b")
_URL_AUTH = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s/@:\"'<>]+:([^\s/@\"'<>]+)@")
_URL_QUERY = re.compile(r"[?&]([A-Za-z0-9_\-]+)=([^&\s\"'<>]+)")
_DB_PASSWORD = re.compile(r"(?i)\b(?:Password|Pwd)\s*=\s*([^;\r\n]+)")
_ASSIGNMENT = re.compile(
    r"(?<![\w.\-])(?P<label>[\w][\w.\-]*(?:[ \t]+[\w.\-]+){0,5})[ \t]*[\"'`]?[ \t]*"
    r"(?:[:=]|\bis\b|\s+->)[ \t]*(?:\r?\n[ \t]*)?"
    r"(?P<value>\"(?:[^\"\\]|\\.)*\"|'[^']*'|`[^`]*`|[^\s\"'`,;{}\[\]]+)", re.UNICODE)
_ENTROPY_TOKEN = re.compile(r"(?<!\w)[A-Za-z0-9_./+~!@#$%^&*=\-]{8,128}(?!\w)")


def _entropy(value: str) -> float:
    return -sum((count / len(value)) * math.log2(count / len(value))
                for count in Counter(value).values()) if value else 0


def short_chat_credential(value: str) -> bool:
    """Compatibility heuristic limited to a standalone chat-message body."""
    token = value.strip().lstrip(":- ")
    if not 4 <= len(token) <= 64 or any(char.isspace() for char in token):
        return False
    if token.lower().startswith(("http", "www.")) or token.isalpha():
        return False
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}|\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4}", token):
        return False
    return any(not char.isalnum() for char in token) or (any(char.isdigit() for char in token) and len(token) <= 20)


def resolve_findings(findings: list[Finding]) -> list[Finding]:
    """Union intersecting spans so no overlapping detection can expose a tail."""
    result: list[Finding] = []
    observations = [finding for finding in findings if not finding.sensitive]
    for finding in sorted((finding for finding in findings if finding.sensitive), key=lambda item: (item.start, item.end)):
        if result and finding.start < result[-1].end:
            previous = result.pop()
            strongest = max((previous, finding), key=lambda item: item.confidence)
            result.append(Finding(strongest.category, previous.start, max(previous.end, finding.end),
                                  strongest.confidence, strongest.strategy, strongest.source, strongest.location))
        else:
            result.append(finding)
    return sorted(result + list(dict.fromkeys(observations)), key=lambda item: (item.start, item.end))


class CredentialEngine:
    def __init__(self, policy: CredentialPolicy | None = None):
        self.policy = policy or CredentialPolicy()
        self._custom = []
        for pattern in self.policy.custom_patterns:
            try:
                import regex
                self._custom.append((pattern, regex.compile(pattern.expression)))
            except Exception:
                raise DetectionError("Invalid custom credential pattern.") from None

    def require_format(self, source: str):
        if source not in self.policy.formats:
            raise DetectionError("This input format is disabled by the credential policy.")

    def filter_categories(self, findings):
        return [finding for finding in findings if finding.category not in self.policy.disabled_categories]

    @staticmethod
    def classify_value(value: object) -> str:
        """Classify primitive types before examining credential names or context."""
        if type(value) is bool:
            return "configuration-boolean"
        if isinstance(value, str):
            return "string"
        if value is None:
            return "configuration-null"
        if isinstance(value, (int, float)):
            return "configuration-number"
        return "other"

    def classify_literal(self, raw: str, *, source: str) -> str:
        """Unquoted boolean literals in supported text/config assignments.

        Quoted strings and serialized credential contents remain strings, even
        when their contents happen to spell true or false.
        """
        literal = raw.strip()
        if (literal in {"true", "false"} or
                (source in {"chat", "config"} and literal.lower() in {"true", "false"})):
            return self.classify_value(literal.lower() == "true")
        if literal in {"null", "None"}:
            return self.classify_value(None)
        if re.fullmatch(r"-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?", literal):
            return "configuration-number"
        return self.classify_value(raw)

    def excluded(self, name: str, location: str = "") -> bool:
        return name in self.policy.exceptions or bool(location and location in self.policy.exceptions)

    def classify_name(self, name: str, location: str = "") -> str | None:
        if self.excluded(name, location) or not self.policy.names:
            return None
        if name in self.policy.custom_names:
            return "SECRET"
        return name_category(name)

    def proxy_context(self, name: str) -> bool:
        return self.policy.connections and (proxy_name(name) or name in self.policy.proxy_fields)

    def connection_findings(self, value: str, *, offset=0, context="", source="text", location="") -> list[Finding]:
        if not self.policy.connections:
            return []
        findings = []
        for connection in parse_connections(value, proxy_context=self.proxy_context(context)):
            if self.policy.threshold > 0.95:
                continue
            for index, (start, end) in enumerate(connection.authentication):
                category = 'USERNAME' if index == 0 and len(connection.authentication) == 2 else 'PROXY_CONNECTION_SECRET'
                findings.append(Finding(category, offset + start, offset + end, .95,
                                        "connection-auth", source, location))
            findings.append(Finding("PROXY_ENDPOINT", offset + connection.endpoint_start,
                                    offset + connection.endpoint_end, .95, "connection-endpoint", source, location,
                                    self.policy.proxy_mode == "strict"))
        return findings

    def proxy_field_finding(self, name: str, value: object, start: int, end: int, *,
                            context="", source="json", location="") -> Finding | None:
        if not self.policy.connections or self.excluded(name, location) or not isinstance(value, str) or not value:
            return None
        if not (self.proxy_context(name) or self.proxy_context(context)):
            return None
        role = proxy_role(name)
        if role in {"username", "password", "auth"}:
            return Finding('USERNAME' if role == 'username' else "PROXY_CONNECTION_SECRET", start, end, .95, "proxy-field", source, location)
        if role in {"host", "port"}:
            # Separate host/port values are infrastructure only, never passwords.
            return Finding("PROXY_ENDPOINT", start, end, .95, "proxy-field", source, location,
                           self.policy.proxy_mode == "strict")
        return None

    def object_context(self, names: list[str], parent: str = "") -> str:
        if self.proxy_context(parent):
            return parent
        roles = {proxy_role(name) for name in names}
        if {"host", "port"} <= roles and roles & {"username", "password", "auth"}:
            return "proxy"
        return parent

    def labeled_findings(self, text: str, *, offset=0, source="text", location="") -> list[Finding]:
        findings = []
        if not (self.policy.names or self.policy.context):
            return findings
        sections = list(re.finditer(r"(?m)^[ \t]*\[([\w.\-]+)\][ \t]*$", text))
        for match in _ASSIGNMENT.finditer(text):
            label = match.group("label")
            if self.excluded(label) or any(self.excluded(word) for word in label.split()):
                continue
            classify = self.classify_name if self.policy.names else name_category
            category = classify(label)
            if not category:
                category = next((classify(word) for word in reversed(label.split())
                                 if classify(word)), None)
            section = next((header.group(1) for header in reversed(sections) if header.end() <= match.start()), '')
            context = label if self.proxy_context(label) else section if self.proxy_context(section) else ''
            if not category and not context:
                continue
            raw = match.group("value")
            if self.classify_literal(raw, source=source).startswith("configuration-"):
                continue
            start, end = match.span("value")
            if raw.startswith(('"', "'", '`')):
                start += 1
                end -= 1
            connection_findings = self.connection_findings(text[start:end], offset=offset + start,
                                                           context=context, source=source, location=location)
            findings.extend(connection_findings)
            proxy_field = self.proxy_field_finding(label, text[start:end], offset + start, offset + end,
                                                   context=context, source=source, location=location)
            if proxy_field and proxy_field.confidence >= self.policy.threshold:
                findings.append(proxy_field)
                continue
            if category and end > start and self.policy.threshold <= 0.95:
                findings.append(Finding(category, offset + start, offset + end, 0.95,
                                        "labeled-context", source, location))
        return findings

    def value_findings(self, value: str, *, offset: int = 0, context: str = "",
                       source: str = "text", location: str = "") -> list[Finding]:
        findings = []
        findings.extend(self.connection_findings(value, offset=offset, context=context, source=source, location=location))

        def emit(category, start, end, confidence, strategy):
            if end > start and confidence >= self.policy.threshold:
                findings.append(Finding(category, offset + start, offset + end, confidence,
                                        strategy, source, location))

        if self.policy.values:
            for category, pattern in _COMPILED_FORMATS:
                for match in pattern.finditer(value):
                    emit(category, match.start(), match.end(), 0.95, "value-format")
            for match in _JWT.finditer(value):
                try:
                    header, payload, signature = match.group().split('.')
                    decode = lambda item: json.loads(base64.urlsafe_b64decode(item + '=' * (-len(item) % 4)))
                    header_data, payload_data = decode(header), decode(payload)
                    if isinstance(header_data, dict) and header_data.get("alg") and isinstance(payload_data, dict) and signature:
                        emit("TOKEN", match.start(), match.end(), 0.95, "jwt-format")
                except (ValueError, UnicodeError, TypeError):
                    pass
            for match in _URL_AUTH.finditer(value):
                user_start = value.index('://', match.start(), match.end()) + 3
                emit('USERNAME', user_start, match.start(1) - 1, .99, 'url-userinfo')
                if not any(finding.strategy == "connection-auth" and finding.start - offset <= match.start(1)
                           and match.end(1) <= finding.end - offset for finding in findings):
                    emit("PASSWORD", match.start(1), match.end(1), 0.99, "url-userinfo")
            for match in _URL_QUERY.finditer(value):
                if not self.excluded(match.group(1)) and name_category(match.group(1)):
                    emit(name_category(match.group(1)), match.start(2), match.end(2), 0.95, "url-query")
            for match in _DB_PASSWORD.finditer(value):
                # A database connection string carries string-valued credentials;
                # a standalone typed setting such as password=false does not.
                prefix = value[max(0, value.rfind('\n', 0, match.start()) + 1):match.start()]
                if re.search(r"(?i)\b(?:server|host|data\s+source|uid|user\s+id|database)\s*=", prefix) and ';' in prefix:
                    emit("PASSWORD", match.start(1), match.end(1), 0.95, "connection-string")
            for pattern, compiled in self._custom:
                try:
                    for match in compiled.finditer(value, timeout=self.policy.pattern_timeout):
                        emit(pattern.category, match.start(), match.end(), pattern.confidence, "custom-pattern")
                except Exception:
                    raise DetectionError("Custom credential pattern failed or exceeded its time limit.") from None
        findings.extend(self.labeled_findings(value, offset=offset, source=source, location=location))
        if self.policy.context:
            for match in _ENTROPY_TOKEN.finditer(value):
                token = match.group()
                if re.match(r"^\w+=.+", token):
                    continue
                prefix = (context + " " + value[max(0, match.start() - 70):match.start()]).strip()
                # Require a nearby credential concept AND non-language token shape.
                words = identifier_words(prefix)
                nearby = any(name_category(word) and name_category(word) != 'USERNAME'
                             and name_category(word) not in self.policy.disabled_categories for word in words[-10:])
                if nearby and _entropy(token) >= 3 and any(char.isdigit() for char in token) and not token.isdigit():
                    emit("SECRET", match.start(), match.end(), 0.85, "context-entropy")
        excluded_spans = [match.span('value') for match in _ASSIGNMENT.finditer(value)
                          if self.excluded(match.group('label')) or
                          any(self.excluded(word) for word in match.group('label').split())]
        boolean_spans = [match.span('value') for match in _ASSIGNMENT.finditer(value)
                         if self.classify_literal(match.group('value'), source=source).startswith("configuration-")]
        findings = [finding for finding in findings if not any(
            start <= finding.start - offset and finding.end - offset <= end
            for start, end in excluded_spans)]
        findings = [finding for finding in findings if finding.strategy == "connection-string" or not any(
            start <= finding.start - offset and finding.end - offset <= end
            for start, end in boolean_spans)]
        return resolve_findings(self.filter_categories(findings))

    def detect_text(self, text: str, *, source: str = "chat") -> list[Finding]:
        self.require_format(source)
        findings = self.value_findings(text, source=source)
        findings.extend(self.structured_findings(text, source=source))
        if self.policy.context:
            if source == "chat":
                # The adapter extracts message bodies; the core applies the rule.
                from src.whatsapp import iter_whatsapp_messages
                recent = []
                for message in iter_whatsapp_messages(text):
                    body = message.body.strip()
                    context = any(name_category(word) for previous in recent[-2:]
                                  for word in identifier_words(previous))
                    if short_chat_credential(body) and not body.isdigit() and (context or len(body) <= 24):
                        start = message.body_start + len(message.body) - len(message.body.lstrip(":\t -"))
                        confidence = 0.92 if context else 0.75
                        if confidence >= self.policy.threshold:
                            findings.append(Finding("PASSWORD", start, message.body_end, confidence,
                                                    "chat-message-context", source))
                    recent.append(body)
        return resolve_findings(self.filter_categories(findings))

    def structured_findings(self, text: str, *, source="chat") -> list[Finding]:
        """Reuse the lossless JSON adapter for objects embedded in text/logs."""
        from src.json_redactor import redact_json_result
        if 'json' not in self.policy.formats:
            return []
        findings = []
        decoder = json.JSONDecoder()
        cursor, attempts = 0, 0
        inspection_engine = CredentialEngine(replace(self.policy, action="report"))
        while attempts < 128:
            opening = re.search(r"[\[{]", text[cursor:])
            if not opening:
                break
            start = cursor + opening.start()
            attempts += 1
            try:
                _, consumed = decoder.raw_decode(text[start:])
                result = redact_json_result(text[start:start + consumed], engine=inspection_engine)
            except DetectionError:
                cursor = start + 1
                continue
            except (ValueError, RecursionError):
                cursor = start + 1
                continue
            for finding in result.findings:
                begin, end = finding.start, finding.end
                if finding.strategy in {"field-name", "proxy-field"} and text[start + begin:start + end].startswith('"'):
                    begin, end = begin + 1, end - 1
                findings.append(replace(finding, start=start + begin, end=start + end,
                                        source=source, strategy="json-" + finding.strategy))
            cursor = start + consumed
        return findings

    def apply_text(self, text: str, findings: list[Finding]) -> DetectionResult:
        findings = resolve_findings(self.filter_categories(findings))
        if any(finding.sensitive for finding in findings) and self.policy.action == "block":
            raise CredentialBlocked("Input blocked: credentials were detected.")
        if self.policy.action == "redact":
            for finding in reversed(findings):
                if not finding.sensitive:
                    continue
                replacement = self.policy.replacement
                if finding.strategy.startswith("json-"):
                    replacement = json.dumps(replacement, ensure_ascii=False)[1:-1]
                text = text[:finding.start] + replacement + text[finding.end:]
        return DetectionResult(text, tuple(findings), self.policy.action)


def load_policy(path: str | Path) -> CredentialPolicy:
    """Load a local settings file with content-free failure messages."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
        if not isinstance(data, dict):
            raise ValueError()
        allowed = set(CredentialPolicy.__dataclass_fields__)
        if set(data) - allowed:
            raise ValueError()
        for key in ("names", "values", "context", "connections"):
            if key in data and type(data[key]) is not bool:
                raise ValueError()
        for key in ("custom_names", "exceptions", "formats", "proxy_fields", "disabled_categories"):
            if key in data:
                if not isinstance(data[key], list) or not all(isinstance(item, str) for item in data[key]):
                    raise ValueError()
                data[key] = tuple(data[key])
        if "custom_patterns" in data:
            data["custom_patterns"] = tuple(CustomPattern(**item) for item in data["custom_patterns"])
        if "replacement" in data and not isinstance(data["replacement"], str):
            raise ValueError()
        policy = CredentialPolicy(**data)
        CredentialEngine(policy)  # Compile custom patterns before accepting settings.
        return policy
    except Exception:
        raise DetectionError("Could not load credential policy: check the settings schema.") from None
