"""Read a dropped batch atomically and stack input contents without headers."""
from __future__ import annotations

from pathlib import Path

from src.credentials import DetectionError
from src.spreadsheet_inputs import TABLE_SUFFIXES, WORKBOOK_SUFFIXES

JSON_SUFFIXES = {'.json', '.jsonc', '.jsonl', '.ndjson'}
SUPPORTED_INPUT_SUFFIXES = TABLE_SUFFIXES | JSON_SUFFIXES | {
    '.txt', '.text', '.log', '.env', '.ini', '.cfg', '.conf', '.config', '.properties',
    '.yaml', '.yml', '.xml', '.toml', '.md', '.sql', '.html', '.htm', '.css',
    '.js', '.ts', '.py', '.sh', '.bat', '.ps1',
}
TEXT_ENCODINGS = {'Auto': None, 'UTF-8': 'utf-8-sig', 'UTF-16': 'utf-16', 'Windows-1252': 'cp1252'}


def supported_input(path):
    path = Path(path)
    return path.suffix.lower() in SUPPORTED_INPUT_SUFFIXES or path.name.lower() == '.env' or path.name.lower().startswith('.env.')


def read_text_file(path, encoding='Auto'):
    try:
        if Path(path).suffix.lower() in WORKBOOK_SUFFIXES:
            raise DetectionError('Open workbook files separately and choose a worksheet.')
        data = Path(path).read_bytes()
        codec = TEXT_ENCODINGS[encoding]
        if codec is None:
            if data.startswith((b'\xff\xfe\x00\x00', b'\x00\x00\xfe\xff')):
                codec = 'utf-32'
            elif data.startswith((b'\xff\xfe', b'\xfe\xff')):
                codec = 'utf-16'
            else:
                codec = 'utf-8-sig'
        text = data.decode(codec)
        if '\x00' in text:
            raise DetectionError('This file contains binary data or needs a different text encoding.')
        return text
    except DetectionError:
        raise
    except (OSError, UnicodeError, KeyError):
        raise DetectionError('Could not read the file. Choose the correct text encoding or use a supported workbook.') from None


def folder_files(directory):
    """Import supported direct children in stable order; do not traverse subfolders."""
    try:
        root = Path(directory)
        if not root.is_dir():
            raise OSError()
        paths = sorted((path for path in root.iterdir() if path.is_file() and
                        supported_input(path)),
                       key=lambda path: (path.name.casefold(), path.name))
    except OSError:
        raise DetectionError('Could not read the selected folder.') from None
    if not paths:
        raise DetectionError('No supported text, JSON, table, or workbook files were found in this folder.')
    return [str(path) for path in paths]


def read_file_batch(paths: list[str], encoding='Auto') -> tuple[str, bool]:
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
            contents.append(read_text_file(path, encoding))
            all_json = all_json and path.suffix.lower() in JSON_SUFFIXES
    except (OSError, UnicodeError):
        raise DetectionError("Could not read the dropped batch. Use readable UTF-8 text or JSON files.") from None
    return '\n\n'.join(contents), all_json


def read_json_batch(paths, encoding='Auto'):
    """Validate boundaries independently; one broken file cannot consume another."""
    from src.json_inputs import parse_inputs
    documents = []
    repaired = False
    for path in paths:
        content, _ = read_file_batch([path], encoding)
        values, changed = parse_inputs(content)
        documents.extend(values)
        repaired = repaired or changed
    return documents, repaired
