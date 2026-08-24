"""Consistent chat anonymization on top of Presidio detections."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.detectors import DEFAULT_ENTITIES, detect
from src.whatsapp import preprocess_chat


@dataclass
class AnonymizeResult:
    text: str
    entities_found: list[dict[str, Any]] = field(default_factory=list)
    mapping: dict[str, str] = field(default_factory=dict)


class ChatAnonymizer:
    """
    Anonymize chat text with stable placeholders per unique value.

    Example: every occurrence of "Ada Lovelace" -> PERSON_1 in the same run.
    The replacement map can be saved locally for reversible workflows — do not
    commit maps that contain real client data.
    """

    def __init__(
        self,
        *,
        entities: list[str] | None = None,
        include_ticket_ids: bool = False,
        score_threshold: float = 0.4,
        mapping: dict[str, str] | None = None,
        dedupe_lines: bool = True,
        drop_media_omitted: bool = False,
    ) -> None:
        self.entities = list(entities) if entities is not None else list(DEFAULT_ENTITIES)
        self.include_ticket_ids = include_ticket_ids
        self.score_threshold = score_threshold
        self.dedupe_lines = dedupe_lines
        self.drop_media_omitted = drop_media_omitted
        # original_span_text -> PLACEHOLDER
        self.mapping: dict[str, str] = dict(mapping or {})
        self._counts: dict[str, int] = {}
        self._rebuild_counts_from_mapping()

    def _rebuild_counts_from_mapping(self) -> None:
        self._counts.clear()
        for placeholder in self.mapping.values():
            if "_" not in placeholder:
                continue
            entity_type, _, index = placeholder.rpartition("_")
            if index.isdigit():
                self._counts[entity_type] = max(self._counts.get(entity_type, 0), int(index))

    def _placeholder_for(self, entity_type: str, original: str) -> str:
        key = original
        if key in self.mapping:
            return self.mapping[key]

        # Case-insensitive reuse for names/emails when exact key differs only by case.
        lowered = key.lower()
        for existing, placeholder in self.mapping.items():
            if existing.lower() == lowered:
                self.mapping[key] = placeholder
                return placeholder

        next_index = self._counts.get(entity_type, 0) + 1
        self._counts[entity_type] = next_index
        placeholder = f"{entity_type}_{next_index}"
        self.mapping[key] = placeholder
        return placeholder

    def anonymize(self, text: str) -> AnonymizeResult:
        text = preprocess_chat(
            text,
            dedupe_lines=self.dedupe_lines,
            drop_media_omitted=self.drop_media_omitted,
        )
        results = detect(
            text,
            entities=self.entities,
            include_ticket_ids=self.include_ticket_ids,
            score_threshold=self.score_threshold,
        )

        # Prefer higher score, then longer span, then earlier start when resolving overlaps.
        ordered = sorted(
            results,
            key=lambda r: (-float(r.score), -(r.end - r.start), r.start),
        )
        filtered = self._drop_overlaps(ordered)

        entities_found: list[dict[str, Any]] = []
        pieces: list[str] = []
        cursor = len(text)

        for result in sorted(filtered, key=lambda r: r.start, reverse=True):
            original = text[result.start : result.end]
            placeholder = self._placeholder_for(result.entity_type, original)
            pieces.append(text[result.end : cursor])
            pieces.append(placeholder)
            cursor = result.start
            entities_found.append(
                {
                    "entity_type": result.entity_type,
                    "start": result.start,
                    "end": result.end,
                    "score": round(float(result.score), 4),
                    "original": original,
                    "replacement": placeholder,
                }
            )

        pieces.append(text[:cursor])
        anonymized = "".join(reversed(pieces))
        entities_found.reverse()

        return AnonymizeResult(
            text=anonymized,
            entities_found=entities_found,
            mapping=dict(self.mapping),
        )

    @staticmethod
    def _drop_overlaps(results: list) -> list:
        """Keep higher-priority (earlier, longer) spans; drop overlaps."""
        kept: list = []
        occupied: list[tuple[int, int]] = []
        for result in results:
            if any(result.start < end and result.end > start for start, end in occupied):
                continue
            kept.append(result)
            occupied.append((result.start, result.end))
        return kept

    def anonymize_file(self, path: str | Path) -> AnonymizeResult:
        content = Path(path).read_text(encoding="utf-8")
        return self.anonymize(content)

    def save_map(self, path: str | Path) -> None:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps(self.mapping, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    def load_map(self, path: str | Path) -> None:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("Replacement map must be a JSON object of original -> placeholder")
        self.mapping = {str(k): str(v) for k, v in data.items()}
        self._rebuild_counts_from_mapping()

    def deanonymize(self, text: str) -> str:
        """Reverse placeholders using the current map (local use only)."""
        # Longest placeholders first to avoid partial swaps.
        inverted = sorted(
            ((placeholder, original) for original, placeholder in self.mapping.items()),
            key=lambda item: len(item[0]),
            reverse=True,
        )
        restored = text
        for placeholder, original in inverted:
            restored = restored.replace(placeholder, original)
        return restored
