"""PII detectors: Presidio analyzer plus comprehensive chat-oriented recognizers."""

from __future__ import annotations

import math
import re
from collections import Counter
from functools import lru_cache

from presidio_analyzer import (
    AnalyzerEngine,
    EntityRecognizer,
    Pattern,
    PatternRecognizer,
    RecognizerRegistry,
    RecognizerResult,
)
from presidio_analyzer.nlp_engine import NlpEngineProvider

from src.whatsapp import WhatsAppBodyRecognizer


# Broad default set for scrubbing support / sales chats before sharing.
DEFAULT_ENTITIES = [
    # Presidio built-ins
    "PERSON",
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "CREDIT_CARD",
    "CRYPTO",
    "IBAN_CODE",
    "IP_ADDRESS",
    "LOCATION",
    # Prefer our sensitive-URL recognizer over Presidio's noisy URL matcher
    "SENSITIVE_URL",
    "US_SSN",
    "US_BANK_NUMBER",
    "US_DRIVER_LICENSE",
    "US_ITIN",
    "US_PASSPORT",
    "MEDICAL_LICENSE",
    "NRP",
    # Custom
    "CHAT_HANDLE",
    "API_KEY",
    "PASSWORD",
    "VERIFICATION_CODE",
    "SECRET",
    "UUID",
    "MAC_ADDRESS",
    "STREET_ADDRESS",
    "ACCOUNT_ID",
    "REMOTE_DESKTOP_ID",
]


_SECRET_CONTEXT = re.compile(
    r"(?i)\b("
    r"password|passwd|pwd|passphrase|passcode|pass\b|"
    r"secret|token|api[_\s-]?key|access[_\s-]?key|private[_\s-]?key|"
    r"credential|auth|bearer|session|cookie|jwt|"
    r"temp(?:orary)?\s*(?:password|pass|pwd|code)|"
    r"reset|login|signin|sign-in"
    r")\b"
)

_CODE_CONTEXT = re.compile(
    r"(?i)\b("
    r"otp|2fa|mfa|totp|hotp|"
    r"verif(?:y|ication)|confirm(?:ation)?|"
    r"one[-\s]?time|auth(?:entication)?\s*code|"
    r"security\s*code|sms\s*code|pin(?:\s*code)?|"
    r"access\s*code|login\s*code|reset\s*code|"
    r"code\s*(?:is|was|:)|enter\s*(?:the\s*)?code"
    r")\b"
)

_COMMON_WORDS = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "token",
        "example",
        "customer",
        "support",
        "please",
        "thanks",
        "hello",
        "slack",
        "discord",
        "teams",
        "email",
        "phone",
        "account",
        "number",
        "verification",
        "confirm",
        "temporary",
        "rotated",
        "update",
        "ticket",
        "workspace",
        "message",
        "something",
        "nothing",
        "everything",
        "anything",
        "someone",
        "anyone",
        "localhost",
        "https",
        "http",
    }
)

# spaCy often tags these as PERSON in chat logs.
_PERSON_DENYLIST = frozenset(
    {
        "email",
        "mail",
        "phone",
        "slack",
        "discord",
        "teams",
        "zoom",
        "support",
        "customer",
        "agent",
        "user",
        "admin",
        "account",
        "ticket",
        "password",
        "token",
        "secret",
        "code",
        "otp",
        "api",
        "key",
        "address",
        "office",
        "thanks",
        "hello",
        "hey",
        "hi",
        "ok",
        "okay",
        "yes",
        "no",
    }
)


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _near_context(text: str, start: int, end: int, pattern: re.Pattern[str], window: int = 40) -> bool:
    left = max(0, start - window)
    right = min(len(text), end + window)
    return bool(pattern.search(text[left:right]))


class CaptureGroupRecognizer(EntityRecognizer):
    """Regex recognizer that emits only the first capturing group as the entity span."""

    def __init__(
        self,
        supported_entity: str,
        name: str,
        patterns: list[tuple[re.Pattern[str], float]],
    ) -> None:
        # No Presidio context list — patterns already encode labels, and empty
        # context avoids analysis_explanation requirements in score enhancement.
        super().__init__(
            supported_entities=[supported_entity],
            name=name,
            context=[],
        )
        self._patterns = patterns
        self.supported_entity = supported_entity

    def load(self) -> None:
        return None

    def analyze(
        self,
        text: str,
        entities: list[str],
        nlp_artifacts=None,
    ) -> list[RecognizerResult]:
        if self.supported_entity not in entities:
            return []

        results: list[RecognizerResult] = []
        for pattern, score in self._patterns:
            for match in pattern.finditer(text):
                if match.lastindex and match.lastindex >= 1:
                    start, end = match.start(1), match.end(1)
                else:
                    start, end = match.start(), match.end()
                if start == end:
                    continue
                result = RecognizerResult(
                    entity_type=self.supported_entity,
                    start=start,
                    end=end,
                    score=score,
                )
                result.recognition_metadata = {
                    RecognizerResult.RECOGNIZER_NAME_KEY: self.name,
                    RecognizerResult.RECOGNIZER_IDENTIFIER_KEY: self.id,
                }
                results.append(result)
        return results


def _password_recognizer() -> CaptureGroupRecognizer:
    """Labeled passwords and temporary credentials pasted in chat."""
    patterns = [
        # password: value / password=value / pwd is value
        (
            re.compile(
                r"(?i)\b(?:password|passwd|pwd|passphrase|passcode|temp(?:orary)?\s*(?:password|pass|pwd))"
                r"\s*(?:is|=|:|->)\s*[\"'`]?([^\s\"'`]{4,128})[\"'`]?"
            ),
            0.95,
        ),
        # "password" "value" / password "value"
        (
            re.compile(
                r"(?i)\b(?:password|passwd|pwd|passphrase)\b[^A-Za-z0-9]{0,12}"
                r"[\"'`]([^\s\"'`]{4,128})[\"'`]"
            ),
            0.9,
        ),
        # my password is FooBar1!
        (
            re.compile(
                r"(?i)\b(?:my|the|their|his|her|our)?\s*password\s+is\s+"
                r"[\"'`]?([^\s\"'`,.;:]{4,128})[\"'`]?"
            ),
            0.9,
        ),
        # new password Abc123!xyz / temp password: ...
        (
            re.compile(
                r"(?i)\b(?:new|old|temp(?:orary)?|reset)\s+password\s*[:=]?\s*"
                r"[\"'`]?([^\s\"'`]{4,128})[\"'`]?"
            ),
            0.9,
        ),
        # AnyDesk / TeamViewer password: ...
        (
            re.compile(
                r"(?i)\b(?:anydesk|teamviewer|splashtop|rustdesk|tv|ad)\s*"
                r"(?:password|pass|pwd|code)\s*[:=]?\s*"
                r"[\"'`]?([^\s\"'`]{4,32})[\"'`]?"
            ),
            0.95,
        ),
    ]
    return CaptureGroupRecognizer(
        supported_entity="PASSWORD",
        name="PasswordRecognizer",
        patterns=patterns,
    )


def _verification_code_recognizer() -> CaptureGroupRecognizer:
    """OTP / 2FA / SMS / email verification codes."""
    patterns = [
        # OTP: 847291 / OTP code is 847291 / 2FA code = 123456
        (
            re.compile(
                r"(?i)\b(?:otp|2fa|mfa|totp|hotp|pin|passcode)\b"
                r"(?:\s*codes?)?\s*(?:is|=|:)?\s*[\"'`]?"
                r"([0-9]{4,8}(?:[-\s][0-9]{3,4})?)[\"'`]?"
            ),
            0.95,
        ),
        # verification/security/sms/auth/access/login/reset code: 123456
        (
            re.compile(
                r"(?i)\b(?:verification|security|sms|auth(?:entication)?|access|login|reset|"
                r"confirm(?:ation)?|one[-\s]?time)\s+codes?\s*(?:is|=|:)?\s*[\"'`]?"
                r"([0-9]{4,8}(?:[-\s][0-9]{3,4})?)[\"'`]?"
            ),
            0.95,
        ),
        # enter/use/sent the code 123456
        (
            re.compile(
                r"(?i)\b(?:enter|use|sent|received|got)\s+(?:the\s+)?(?:code|otp|pin)\s+"
                r"[\"'`]?([0-9]{4,8}(?:[-\s][0-9]{3,4})?)[\"'`]?"
            ),
            0.9,
        ),
        # code is 123456 / code: 123456 / code 123456
        (
            re.compile(
                r"(?i)\bcode\b\s*(?:is|=|:)?\s*[\"'`]?([0-9]{4,8}(?:[-\s][0-9]{3,4})?)[\"'`]?"
            ),
            0.8,
        ),
        # short alphanumeric codes that include a digit (e.g. A1B2C3)
        (
            re.compile(
                r"(?i)\b(?:otp|verification\s*code|auth\s*code|access\s*code)\s*[:=]?\s*"
                r"[\"'`]?((?=[A-Za-z0-9]*\d)[A-Za-z0-9]{4,10})[\"'`]?"
            ),
            0.8,
        ),
    ]
    return CaptureGroupRecognizer(
        supported_entity="VERIFICATION_CODE",
        name="VerificationCodeRecognizer",
        patterns=patterns,
    )


def _six_digit_otp_recognizer() -> PatternRecognizer:
    """
    Redact ANY standalone 6-digit number (common OTP shape), including leading zeros.

    Skips digits that are part of longer numbers (IDs, phones, etc.) via word boundaries.
    """
    return PatternRecognizer(
        supported_entity="VERIFICATION_CODE",
        name="SixDigitOtpRecognizer",
        patterns=[
            Pattern(
                name="six_digit_otp",
                # Not preceded/followed by another digit. Allows 002793, 847291.
                regex=r"(?<!\d)\d{6}(?!\d)",
                score=0.8,
            ),
        ],
    )


def _email_recognizer() -> PatternRecognizer:
    """Catch emails including reserved TLDs (.example / .test / .invalid) Presidio may miss."""
    return PatternRecognizer(
        supported_entity="EMAIL_ADDRESS",
        name="BroadEmailRecognizer",
        patterns=[
            Pattern(
                name="broad_email",
                regex=(
                    r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\."
                    r"(?:[A-Za-z]{2,24}|example|test|invalid|localhost)\b"
                ),
                score=0.9,
            ),
        ],
        context=["email", "mail", "contact", "@"],
    )


def _chat_handle_recognizer() -> PatternRecognizer:
    """Slack / Discord / Teams-style @handles (no trailing punctuation)."""
    return PatternRecognizer(
        supported_entity="CHAT_HANDLE",
        name="ChatHandleRecognizer",
        patterns=[
            Pattern(
                name="at_handle",
                # Require the handle to end on an alnum so trailing "." isn't included.
                regex=r"(?<!\w)@[A-Za-z](?:[A-Za-z0-9._-]*[A-Za-z0-9])?(?=[\s,!?;:.)\]}]|$)",
                score=0.7,
            ),
        ],
        context=["slack", "discord", "mention", "ping", "handle"],
    )


def _api_key_recognizer() -> PatternRecognizer:
    """Vendor API keys, JWTs, bearer tokens, and similar shaped secrets."""
    return PatternRecognizer(
        supported_entity="API_KEY",
        name="ApiKeyRecognizer",
        patterns=[
            Pattern("openai_sk", r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{16,}\b", 0.9),
            Pattern("openai_sk_live_test", r"\bsk-(?:live|test)-[A-Za-z0-9]{16,}\b", 0.95),
            Pattern("anthropic_key", r"\bsk-ant-[A-Za-z0-9\-_]{16,}\b", 0.95),
            Pattern("stripe_key", r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b", 0.95),
            Pattern("github_pat", r"\bgh[pousr]_[A-Za-z0-9]{20,}\b", 0.95),
            Pattern("github_fine_grained", r"\bgithub_pat_[A-Za-z0-9_]{20,}\b", 0.95),
            Pattern("gitlab_pat", r"\bglpat-[A-Za-z0-9\-_]{20,}\b", 0.95),
            Pattern("sentry_token", r"\bsntrys_[A-Za-z0-9_\-]{20,}\b", 0.95),
            Pattern("aws_access_key", r"\bAKIA[0-9A-Z]{16}\b", 0.95),
            Pattern("slack_token", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", 0.95),
            Pattern("google_api_key", r"\bAIza[0-9A-Za-z\-_]{35}\b", 0.95),
            Pattern("sendgrid", r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b", 0.95),
            Pattern("twilio_sid", r"\bAC[a-f0-9]{32}\b", 0.85),
            Pattern("jwt", r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b", 0.9),
            Pattern("bearer_header", r"(?i)\bBearer\s+[A-Za-z0-9\-._~+/]+=*", 0.85),
            Pattern("long_hex_secret", r"\b[a-f0-9]{32,128}\b", 0.45),
        ],
        context=["key", "token", "secret", "api", "credential", "bearer", "auth"],
    )


def _remote_desktop_recognizer() -> CaptureGroupRecognizer:
    """AnyDesk / TeamViewer / similar remote-support IDs."""
    patterns = [
        (
            re.compile(
                r"(?i)\b(?:anydesk|teamviewer|splashtop|rustdesk)\s*(?:id|number|#)?\s*[:=]?\s*"
                r"[\"'`]?(\d{3}(?:[\s\-]?\d{3}){2,3})[\"'`]?"
            ),
            0.95,
        ),
        (
            re.compile(r"(?i)\b(?:tv|ad)\s*id\s*[:=]\s*[\"'`]?(\d{6,12})[\"'`]?"),
            0.85,
        ),
    ]
    return CaptureGroupRecognizer(
        supported_entity="REMOTE_DESKTOP_ID",
        name="RemoteDesktopRecognizer",
        patterns=patterns,
    )


def _sensitive_url_recognizer() -> PatternRecognizer:
    """Full http(s) URLs and common tracking/pixel endpoints — not JS fragments."""
    return PatternRecognizer(
        supported_entity="SENSITIVE_URL",
        name="SensitiveUrlRecognizer",
        patterns=[
            Pattern(
                "https_url",
                r"https?://[^\s\"'<>\]]+",
                0.85,
            ),
            Pattern(
                "www_url",
                r"\bwww\.[A-Za-z0-9.\-]+(?:/[^\s\"'<>\]]*)?",
                0.7,
            ),
            Pattern(
                "fb_pixel_init",
                r"(?i)\bfbq\(\s*['\"]init['\"]\s*,\s*['\"]\d{10,20}['\"]\s*\)",
                0.9,
            ),
        ],
    )


def _uuid_recognizer() -> PatternRecognizer:
    return PatternRecognizer(
        supported_entity="UUID",
        name="UuidRecognizer",
        patterns=[
            Pattern(
                "uuid",
                r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b",
                0.85,
            ),
        ],
    )


def _mac_address_recognizer() -> PatternRecognizer:
    return PatternRecognizer(
        supported_entity="MAC_ADDRESS",
        name="MacAddressRecognizer",
        patterns=[
            Pattern("mac_colon", r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b", 0.85),
            Pattern("mac_dash", r"\b(?:[0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}\b", 0.85),
        ],
    )


def _street_address_recognizer() -> PatternRecognizer:
    """US-ish street addresses commonly pasted in chats."""
    return PatternRecognizer(
        supported_entity="STREET_ADDRESS",
        name="StreetAddressRecognizer",
        patterns=[
            Pattern(
                "street_address",
                r"\b\d{1,5}\s+[A-Za-z0-9.'\-]+\s+"
                r"(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\.?\b",
                0.7,
            ),
        ],
        context=["address", "office", "hq", "located", "street"],
    )


def _account_id_recognizer() -> CaptureGroupRecognizer:
    """Customer / account / tenant / org IDs called out in chat."""
    patterns = [
        (
            re.compile(
                r"(?i)\b(?:account|customer|tenant|org(?:anization)?|user|client|member|workspace)"
                r"\s*(?:id|number|#)\s*[:=]?\s*[\"'`]?([A-Za-z0-9\-_]{4,64})[\"'`]?"
            ),
            0.85,
        ),
        (
            re.compile(r"(?i)\b(?:acct|cust|tenant|org)[_-]?id\s*[:=]\s*([A-Za-z0-9\-_]{4,64})"),
            0.85,
        ),
    ]
    return CaptureGroupRecognizer(
        supported_entity="ACCOUNT_ID",
        name="AccountIdRecognizer",
        patterns=patterns,
    )


def _ticket_id_recognizer() -> PatternRecognizer:
    return PatternRecognizer(
        supported_entity="TICKET_ID",
        name="TicketIdRecognizer",
        patterns=[
            Pattern("project_ticket", r"\b[A-Z]{2,10}-\d{1,6}\b", 0.45),
        ],
        context=["ticket", "jira", "issue", "case"],
    )


class HighEntropySecretRecognizer(EntityRecognizer):
    """
    Catch unlabeled random passwords / tokens: high-entropy alphanumerics,
    especially near password/secret/token language.
    """

    TOKEN_RE = re.compile(r"(?<![A-Za-z0-9])([A-Za-z0-9\-._~+/=!@#$%^&*]{8,128})(?![A-Za-z0-9])")

    def __init__(self) -> None:
        # Context matching is done manually; leave Presidio context empty.
        super().__init__(
            supported_entities=["SECRET"],
            name="HighEntropySecretRecognizer",
            context=[],
        )

    def load(self) -> None:
        return None

    def analyze(
        self,
        text: str,
        entities: list[str],
        nlp_artifacts=None,
    ) -> list[RecognizerResult]:
        if "SECRET" not in entities:
            return []

        results: list[RecognizerResult] = []
        for match in self.TOKEN_RE.finditer(text):
            token = match.group(1)
            if token.lower() in _COMMON_WORDS:
                continue
            if token.startswith(("http://", "https://", "www.")):
                continue
            if "@" in token:
                continue
            if token.isdigit():
                continue
            # Dates / times look "random" to entropy checks but aren't secrets.
            if re.fullmatch(r"\d{4}-\d{2}-\d{2}", token):
                continue
            if re.fullmatch(r"\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4}", token):
                continue
            if re.fullmatch(r"\d{1,2}:\d{2}(?::\d{2})?", token):
                continue
            # Snake_case chat usernames / channel names (alex_support) — skip unless spicy.
            if re.fullmatch(r"[A-Za-z]+(?:_[A-Za-z]+)+", token):
                continue
            # JS / HTML-ish identifiers — leave script dumps alone.
            if re.search(
                r"(?i)(createElement|getElementById|querySelector|addEventListener|function|window|document)",
                token,
            ):
                continue
            if token.startswith(("http://", "https://", "www.", "https:", "http:")):
                continue

            entropy = _shannon_entropy(token)
            has_digit = any(c.isdigit() for c in token)
            has_upper = any(c.isupper() for c in token)
            has_lower = any(c.islower() for c in token)
            has_symbol = any(c in "-._~+/=!@#$%^&*" for c in token)
            charset_variety = sum([has_digit, has_upper, has_lower, has_symbol])

            near_secret = _near_context(text, match.start(1), match.end(1), _SECRET_CONTEXT)
            near_code = _near_context(text, match.start(1), match.end(1), _CODE_CONTEXT)

            score = 0.0
            length = len(token)

            if near_secret and length >= 8 and (charset_variety >= 2 or entropy >= 3.0):
                score = 0.85
            elif near_secret and length >= 6 and has_digit:
                score = 0.75
            elif near_code and 6 <= length <= 16 and charset_variety >= 2 and has_digit:
                score = 0.7
            elif length >= 16 and charset_variety >= 3 and entropy >= 3.5:
                score = 0.65
            elif length >= 20 and charset_variety >= 2 and entropy >= 3.2:
                score = 0.55
            elif length >= 24 and entropy >= 3.5:
                score = 0.5

            if score <= 0:
                continue

            result = RecognizerResult(
                entity_type="SECRET",
                start=match.start(1),
                end=match.end(1),
                score=score,
            )
            result.recognition_metadata = {
                RecognizerResult.RECOGNIZER_NAME_KEY: self.name,
                RecognizerResult.RECOGNIZER_IDENTIFIER_KEY: self.id,
            }
            results.append(result)
        return results


def build_registry(*, include_ticket_ids: bool = False) -> RecognizerRegistry:
    registry = RecognizerRegistry()
    registry.load_predefined_recognizers()
    registry.add_recognizer(_email_recognizer())
    registry.add_recognizer(_chat_handle_recognizer())
    registry.add_recognizer(_api_key_recognizer())
    registry.add_recognizer(_password_recognizer())
    registry.add_recognizer(_verification_code_recognizer())
    registry.add_recognizer(_six_digit_otp_recognizer())
    registry.add_recognizer(_remote_desktop_recognizer())
    registry.add_recognizer(_sensitive_url_recognizer())
    registry.add_recognizer(WhatsAppBodyRecognizer())
    registry.add_recognizer(HighEntropySecretRecognizer())
    registry.add_recognizer(_uuid_recognizer())
    registry.add_recognizer(_mac_address_recognizer())
    registry.add_recognizer(_street_address_recognizer())
    registry.add_recognizer(_account_id_recognizer())
    if include_ticket_ids:
        registry.add_recognizer(_ticket_id_recognizer())
    return registry


@lru_cache(maxsize=2)
def get_analyzer(*, include_ticket_ids: bool = False) -> AnalyzerEngine:
    """
    Build (and cache) an AnalyzerEngine.

    Uses spaCy en_core_web_lg when available; falls back to en_core_web_sm.
    """
    registry = build_registry(include_ticket_ids=include_ticket_ids)

    for model_name in ("en_core_web_lg", "en_core_web_sm"):
        try:
            provider = NlpEngineProvider(
                nlp_configuration={
                    "nlp_engine_name": "spacy",
                    "models": [{"lang_code": "en", "model_name": model_name}],
                }
            )
            nlp_engine = provider.create_engine()
            return AnalyzerEngine(nlp_engine=nlp_engine, registry=registry)
        except OSError:
            continue

    return AnalyzerEngine(registry=registry)


def _is_denied_person(text: str, result) -> bool:
    if result.entity_type != "PERSON":
        return False
    value = text[result.start : result.end].strip().lower()
    return value in _PERSON_DENYLIST


def detect(
    text: str,
    *,
    language: str = "en",
    entities: list[str] | None = None,
    include_ticket_ids: bool = False,
    score_threshold: float = 0.4,
):
    """Run PII / secret detection and return Presidio RecognizerResult list."""
    analyzer = get_analyzer(include_ticket_ids=include_ticket_ids)
    entity_list = list(entities) if entities is not None else list(DEFAULT_ENTITIES)
    if include_ticket_ids and "TICKET_ID" not in entity_list:
        entity_list.append("TICKET_ID")

    results = analyzer.analyze(
        text=text,
        language=language,
        entities=entity_list,
        score_threshold=score_threshold,
    )
    return [r for r in results if not _is_denied_person(text, r)]
