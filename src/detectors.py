"""PII detectors: Presidio analyzer plus comprehensive chat-oriented recognizers."""

from __future__ import annotations

import re
import spacy
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
    "USERNAME",
    "TOKEN",
    "COOKIE",
    "PRIVATE_KEY",
    "AUTHORIZATION",
    "VERIFICATION_CODE",
    "SECRET",
    "PROXY_CONNECTION_SECRET",
    "PROXY_ENDPOINT",
    "UUID",
    "MAC_ADDRESS",
    "STREET_ADDRESS",
    "ACCOUNT_ID",
    "REMOTE_DESKTOP_ID",
]


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


class SharedCredentialRecognizer(EntityRecognizer):
    """Presidio adapter: all credential decisions come from CredentialEngine."""
    def __init__(self, entities=None, policy=None):
        from src.credentials import CredentialEngine
        super().__init__(supported_entities=entities or ["API_KEY", "PASSWORD", "USERNAME", "TOKEN", "COOKIE", "PRIVATE_KEY", "AUTHORIZATION", "SECRET", "PROXY_CONNECTION_SECRET", "PROXY_ENDPOINT"],
                         name="SharedCredentialRecognizer", context=[])
        self.engine = CredentialEngine(policy)

    def load(self):
        return None

    def analyze(self, text, entities, nlp_artifacts=None):
        results = []
        for finding in self.engine.detect_text(text):
            if not finding.sensitive:
                continue
            if finding.category not in entities or finding.category not in self.supported_entities:
                continue
            result = RecognizerResult(entity_type=finding.category, start=finding.start,
                                      end=finding.end, score=finding.confidence)
            result.recognition_metadata = {
                RecognizerResult.RECOGNIZER_NAME_KEY: self.name,
                RecognizerResult.RECOGNIZER_IDENTIFIER_KEY: self.id,
            }
            results.append(result)
        return results


def _labeled_api_key_recognizer():
    return SharedCredentialRecognizer(["API_KEY"])


def _password_recognizer():
    return SharedCredentialRecognizer(["PASSWORD"])


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


def _api_key_recognizer():
    return SharedCredentialRecognizer(["API_KEY"])


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


class HighEntropySecretRecognizer(SharedCredentialRecognizer):
    """Compatibility adapter for context-supported shared secret detection."""
    def __init__(self):
        super().__init__(["SECRET"])


def build_registry(*, include_ticket_ids: bool = False, credential_policy=None) -> RecognizerRegistry:
    registry = RecognizerRegistry()
    registry.load_predefined_recognizers()
    registry.add_recognizer(_email_recognizer())
    registry.add_recognizer(_chat_handle_recognizer())
    if credential_policy is None or credential_policy.action == "redact":
        registry.add_recognizer(SharedCredentialRecognizer(policy=credential_policy))
    registry.add_recognizer(_verification_code_recognizer())
    registry.add_recognizer(_six_digit_otp_recognizer())
    registry.add_recognizer(_remote_desktop_recognizer())
    registry.add_recognizer(_sensitive_url_recognizer())
    registry.add_recognizer(WhatsAppBodyRecognizer())
    registry.add_recognizer(_uuid_recognizer())
    registry.add_recognizer(_mac_address_recognizer())
    registry.add_recognizer(_street_address_recognizer())
    registry.add_recognizer(_account_id_recognizer())
    if include_ticket_ids:
        registry.add_recognizer(_ticket_id_recognizer())
    return registry


@lru_cache(maxsize=2)
def get_analyzer(*, include_ticket_ids: bool = False, credential_policy=None) -> AnalyzerEngine:
    """
    Build (and cache) an AnalyzerEngine.

    Uses spaCy en_core_web_lg when available; falls back to en_core_web_sm.
    """
    registry = build_registry(include_ticket_ids=include_ticket_ids, credential_policy=credential_policy)

    for model_name in ("en_core_web_lg", "en_core_web_sm"):
        # Presidio otherwise attempts to download absent models at runtime.
        if not spacy.util.is_package(model_name):
            continue
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

    raise RuntimeError(
        "English model missing. Install en_core_web_sm or en_core_web_lg, "
        "or use the executable built with build.ps1."
    )


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
    credential_policy=None,
):
    """Run PII / secret detection and return Presidio RecognizerResult list."""
    analyzer = get_analyzer(include_ticket_ids=include_ticket_ids, credential_policy=credential_policy)
    entity_list = list(entities) if entities is not None else list(DEFAULT_ENTITIES)
    if include_ticket_ids and "TICKET_ID" not in entity_list:
        entity_list.append("TICKET_ID")

    results = analyzer.analyze(
        text=text,
        language=language,
        entities=entity_list,
        score_threshold=score_threshold,
    )
    # The shared connection policy owns proxy URL/endpoint privacy; do not let
    # generic IP/URL recognizers override standard mode or collapse a whole URL.
    from src.credentials import CredentialEngine
    connection_regions = [finding for finding in CredentialEngine(credential_policy).detect_text(text)
                          if finding.category == "PROXY_ENDPOINT"]
    results = [result for result in results if not (
        result.entity_type in {"IP_ADDRESS", "SENSITIVE_URL", "URL"} and any(
            result.start < finding.end and result.end > finding.start for finding in connection_regions))]
    return [r for r in results if not _is_denied_person(text, r)]
