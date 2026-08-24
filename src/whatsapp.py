"""WhatsApp-export helpers and line-aware secret detection (local only)."""

from __future__ import annotations

import re
from dataclasses import dataclass

from presidio_analyzer import EntityRecognizer, RecognizerResult


# 04/02/2025, 13:46 - Fa Mgmt: message
# Also tolerates DD-MM-YYYY and optional seconds.
WA_LINE_RE = re.compile(
    r"(?m)^(?P<full>"
    r"(?P<date>\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4}),\s*"
    r"(?P<time>\d{1,2}:\d{2}(?::\d{2})?)\s*-\s*"
    r"(?P<sender>[^:\n]+):\s*"
    r"(?P<body>.*)"
    r")$"
)

_PASSWORD_ASK_RE = re.compile(
    r"(?i)\b("
    r"password|passwd|pwd|passcode|passphrase|"
    r"teamviewer|anydesk|splashtop|chrome\s*remote|"
    r"login|signin|sign-in|credentials?"
    r")\b"
)

_HARMLESS_BODY = frozenset(
    {
        "yes",
        "no",
        "ok",
        "okay",
        "ready",
        "retry",
        "thanks",
        "thank you",
        "please",
        "hi",
        "hey",
        "hello",
        "sure",
        "done",
        "wait",
        "asap",
        "lol",
        "haha",
        "cool",
        "great",
        "perfect",
        "received",
        "sent",
        "checking",
        "one sec",
        "one second",
        "media omitted",
        "<media omitted>",
    }
)

_MEDIA_OMITTED_RE = re.compile(r"(?i)^<?media omitted>?$")


@dataclass(frozen=True)
class WaMessage:
    start: int
    end: int
    body: str
    body_start: int
    body_end: int
    sender: str


def iter_whatsapp_messages(text: str) -> list[WaMessage]:
    messages: list[WaMessage] = []
    for match in WA_LINE_RE.finditer(text):
        body = match.group("body")
        messages.append(
            WaMessage(
                start=match.start("full"),
                end=match.end("full"),
                body=body,
                body_start=match.start("body"),
                body_end=match.end("body"),
                sender=match.group("sender").strip(),
            )
        )
    return messages


def looks_like_credential(value: str) -> bool:
    """Heuristic for short random passwords / codes pasted as their own message."""
    raw = value.strip()
    if not raw or len(raw) < 4 or len(raw) > 64:
        return False
    # Strip a single leading decorative colon/punctuation often typed mid-chat.
    token = re.sub(r"^[:\-\s]+", "", raw).strip()
    if not token or len(token) < 4:
        return False
    if token.lower() in _HARMLESS_BODY:
        return False
    if _MEDIA_OMITTED_RE.match(token):
        return False
    # Multi-word chat sentences are not raw passwords (spaces ≠ symbols).
    if any(c.isspace() for c in token):
        return False
    if token.lower().startswith(("http://", "https://", "www.")):
        return False

    has_digit = any(c.isdigit() for c in token)
    has_symbol = any(not c.isalnum() for c in token)
    has_upper = any(c.isupper() for c in token)
    has_lower = any(c.islower() for c in token)
    if token.isalpha() and not has_digit:
        return False
    # cssss1, ezpd3zzb, SnowByrds4545, :h@2323, $sdsdsdsd{Fj
    if has_symbol and len(token) >= 4:
        return True
    if has_digit and 4 <= len(token) <= 20:
        return True
    if has_digit and has_upper and has_lower and len(token) >= 6:
        return True
    return False


def preprocess_chat(
    text: str,
    *,
    dedupe_lines: bool = False,
    drop_media_omitted: bool = False,
) -> str:
    """Optional local cleanup before detection."""
    lines = text.splitlines(keepends=True)
    out: list[str] = []
    prev_norm: str | None = None
    for line in lines:
        stripped = line.strip()
        if drop_media_omitted:
            wa = WA_LINE_RE.match(stripped)
            body = wa.group("body").strip() if wa else stripped
            if re.search(r"(?i)media\s+omitted", body) and (
                wa is not None or _MEDIA_OMITTED_RE.match(stripped)
            ):
                # Drop WhatsApp media placeholder lines only.
                if wa is None or re.fullmatch(r"(?i)<?media\s+omitted>?", body):
                    continue
        if dedupe_lines:
            norm = stripped
            if norm and norm == prev_norm:
                continue
            if norm:
                prev_norm = norm
        out.append(line)
    return "".join(out)


class WhatsAppBodyRecognizer(EntityRecognizer):
    """
    Detect secrets that are entire WhatsApp message bodies, plus password
    lookback across the previous 1–2 messages (local heuristics only).
    """

    def __init__(self) -> None:
        super().__init__(
            supported_entities=[
                "VERIFICATION_CODE",
                "PASSWORD",
                "SECRET",
                "REMOTE_DESKTOP_ID",
            ],
            name="WhatsAppBodyRecognizer",
            context=[],
        )

    def load(self) -> None:
        return None

    def _emit(self, entity: str, start: int, end: int, score: float) -> RecognizerResult:
        result = RecognizerResult(entity_type=entity, start=start, end=end, score=score)
        result.recognition_metadata = {
            RecognizerResult.RECOGNIZER_NAME_KEY: self.name,
            RecognizerResult.RECOGNIZER_IDENTIFIER_KEY: self.id,
        }
        return result

    def analyze(self, text: str, entities: list[str], nlp_artifacts=None) -> list[RecognizerResult]:
        wanted = set(entities) & {
            "VERIFICATION_CODE",
            "PASSWORD",
            "SECRET",
            "REMOTE_DESKTOP_ID",
        }
        if not wanted:
            return []

        messages = iter_whatsapp_messages(text)
        if not messages:
            return []

        results: list[RecognizerResult] = []
        recent_bodies: list[str] = []

        for msg in messages:
            body = msg.body.strip()
            password_context = any(_PASSWORD_ASK_RE.search(prev) for prev in recent_bodies[-2:])

            # Bare OTP / PIN pasted alone: 002793, 847291
            if "VERIFICATION_CODE" in wanted and re.fullmatch(r"\d{4,8}", body):
                results.append(
                    self._emit("VERIFICATION_CODE", msg.body_start, msg.body_end, 0.9)
                )
            # AnyDesk-style numeric IDs (9–10 digits) as solo messages
            elif "REMOTE_DESKTOP_ID" in wanted and re.fullmatch(r"\d{9,12}", body):
                results.append(
                    self._emit("REMOTE_DESKTOP_ID", msg.body_start, msg.body_end, 0.85)
                )
            # Spaced remote IDs / phone-like: 1 222 222 177
            elif "REMOTE_DESKTOP_ID" in wanted and re.fullmatch(
                r"\d{1,4}(?:\s+\d{1,4}){2,4}", body
            ):
                results.append(
                    self._emit("REMOTE_DESKTOP_ID", msg.body_start, msg.body_end, 0.8)
                )
            # Password lookback: prior lines asked for password / remote desktop
            elif password_context and looks_like_credential(body):
                entity = "PASSWORD" if "PASSWORD" in wanted else "SECRET"
                if entity in wanted:
                    start, end = self._credential_span(msg)
                    results.append(self._emit(entity, start, end, 0.92))
            # Solo short random password-looking bodies (ezpd3zzb, SnowByrds4545, :h@2323)
            elif looks_like_credential(body) and 4 <= len(body.strip()) <= 24:
                # Prefer PASSWORD label for remote-support style short secrets.
                entity = "PASSWORD" if "PASSWORD" in wanted else "SECRET"
                if entity in wanted:
                    start, end = self._credential_span(msg)
                    results.append(self._emit(entity, start, end, 0.75))

            recent_bodies.append(body)

        return results

    @staticmethod
    def _credential_span(msg: WaMessage) -> tuple[int, int]:
        """Skip a leading ':' / dash often typed before a password."""
        body = msg.body
        rel = 0
        while rel < len(body) and body[rel] in ":\t -":
            rel += 1
        if rel >= len(body):
            return msg.body_start, msg.body_end
        return msg.body_start + rel, msg.body_end
