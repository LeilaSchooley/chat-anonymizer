"""Read a dropped batch atomically and stack input contents without headers."""
from __future__ import annotations

from pathlib import Path

from src.credentials import DetectionError


def read_file_batch(paths: list[str]) -> tuple[str, bool]:
    """All files must be readable before the caller changes the input widget."""
    if not paths:
        raise DetectionError("No files were provided.")
    contents = []
    all_json = True
    try:
        for filename in paths:
            path = Path(filename)
            if not path.is_file():
                raise OSError()
            with path.open(encoding="utf-8-sig", newline="") as stream:
                contents.append(stream.read())
            all_json = all_json and path.suffix.lower() == '.json'
    except (OSError, UnicodeError):
        raise DetectionError("Could not read the dropped batch. Use readable UTF-8 text or JSON files.") from None
    return '\n\n'.join(contents), all_json


def read_json_batch(paths):
    """Validate boundaries independently; one broken file cannot consume another."""
    from src.json_inputs import parse_inputs
    documents = []
    repaired = False
    for path in paths:
        content, _ = read_file_batch([path])
        values, changed = parse_inputs(content)
        documents.extend(values)
        repaired = repaired or changed
    return documents, repaired
