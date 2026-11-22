"""Read a dropped batch atomically and stack input contents without headers."""
from __future__ import annotations

from pathlib import Path

from src.credentials import DetectionError

SUPPORTED_INPUT_SUFFIXES = {'.json', '.txt', '.log', '.env', '.ini', '.cfg', '.conf', '.yaml', '.yml', '.csv', '.tsv'}


def folder_files(directory):
    """Import supported direct children in stable order; do not traverse subfolders."""
    try:
        root = Path(directory)
        if not root.is_dir():
            raise OSError()
        paths = sorted((path for path in root.iterdir() if path.is_file() and
                        (path.suffix.lower() in SUPPORTED_INPUT_SUFFIXES or path.name.lower() == '.env')),
                       key=lambda path: (path.name.casefold(), path.name))
    except OSError:
        raise DetectionError('Could not read the selected folder.') from None
    if not paths:
        raise DetectionError('No supported text or JSON files were found in this folder.')
    return [str(path) for path in paths]


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
