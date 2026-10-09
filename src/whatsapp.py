"""WhatsApp parsing, cleanup, and non-credential code/remote-ID adapters."""

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
    """Compatibility wrapper for the shared engine's chat-body rule."""
    from src.credentials import short_chat_credential
    return short_chat_credential(value)


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
    Detect standalone verification codes and remote desktop IDs.
    Credential rules are supplied by the shared CredentialEngine.
    """

    def __init__(self) -> None:
        super().__init__(
            supported_entities=[
                "VERIFICATION_CODE",
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
            "REMOTE_DESKTOP_ID",
        }
        if not wanted:
            return []

        messages = iter_whatsapp_messages(text)
        if not messages:
            return []

        results: list[RecognizerResult] = []

        for msg in messages:
            body = msg.body.strip()

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

        return results
