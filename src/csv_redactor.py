"""Selective CSV/TSV redaction without rewriting unselected source characters."""
from __future__ import annotations

from dataclasses import dataclass
import re

from src.credentials import DetectionError

DELIMITERS = {'Auto': None, 'Comma': ',', 'Tab': '\t', 'Semicolon': ';', 'Pipe': '|'}
EMAIL = re.compile(r'[^\s@<>;,"\\]+@[^\s@<>;,"\\]+\.[^\s@<>;,"\\]+')


@dataclass(frozen=True)
class Cell:
    start: int
    end: int
    value: str
    quoted: bool


@dataclass(frozen=True)
class CsvResult:
    text: str
    count: int
    delimiter: str


def parse_columns(value: str) -> tuple[int, ...]:
    """Accept explicit one-based column numbers, never guesses about order IDs."""
    if not value.strip():
        return ()
    parts = value.split(',')
    if any(not part.strip().isascii() or not part.strip().isdigit() or int(part) < 1 for part in parts):
        raise DetectionError('CSV columns must be positive numbers separated by commas, for example 1,2.')
    return tuple(sorted({int(part) for part in parts}))


def _rows(text: str, delimiter: str) -> list[list[Cell]]:
    rows = []
    i = 1 if text.startswith('\ufeff') else 0
    while i < len(text):
        row = []
        while True:
            start = i
            quoted = i < len(text) and text[i] == '"'
            if quoted:
                i += 1
                while True:
                    if i >= len(text):
                        raise DetectionError('CSV contains an unclosed quoted field. Check the delimiter and quoting.')
                    if text[i] == '"':
                        if i + 1 < len(text) and text[i + 1] == '"':
                            i += 2
                            continue
                        i += 1
                        break
                    i += 1
                value = text[start + 1:i - 1].replace('""', '"')
                if i < len(text) and text[i] not in (delimiter, '\r', '\n'):
                    raise DetectionError('Unexpected characters after a quoted CSV field. Check the delimiter.')
            else:
                while i < len(text) and text[i] not in (delimiter, '\r', '\n'):
                    if text[i] == '"':
                        raise DetectionError('CSV quotes must surround the whole field. Check the delimiter and quoting.')
                    i += 1
                value = text[start:i]
            row.append(Cell(start, i, value, quoted))
            if i < len(text) and text[i] == delimiter:
                i += 1
                continue
            if i < len(text):
                i += 2 if text[i:i + 2] == '\r\n' else 1
            break
        # A blank physical line has no columns; preserve it without counting it.
        if len(row) != 1 or row[0].end != row[0].start:
            rows.append(row)
    return rows


def _table(text: str, delimiter: str | None):
    if delimiter is not None:
        if delimiter not in (',', '\t', ';', '|'):
            raise DetectionError('Choose comma, tab, semicolon, or pipe as the CSV delimiter.')
        rows, detected = _rows(text, delimiter), delimiter
        if rows and any(len(row) != len(rows[0]) for row in rows):
            raise DetectionError('CSV rows have different column counts. Check the delimiter and input files.')
        return rows, detected
    candidates = []
    for candidate in ',\t;|':
        try:
            rows = _rows(text, candidate)
        except DetectionError:
            continue
        candidates.append((max((len(row) for row in rows), default=0), rows, candidate))
    if not candidates:
        raise DetectionError('Could not read CSV/TSV. Choose the delimiter and check column counts and quoting.')
    separated = [item for item in candidates if item[0] > 1 and
                 all(len(row) == item[0] for row in item[1])]
    if len(separated) > 1:
        raise DetectionError('More than one CSV delimiter fits this table. Choose the delimiter explicitly.')
    _, rows, detected = separated[0] if separated else max(candidates, key=lambda item: item[0])
    if rows and any(len(row) != len(rows[0]) for row in rows):
        raise DetectionError('CSV rows have different column counts. Choose the delimiter and check the input.')
    return rows, detected


def redact_csv(text: str, *, emails: bool = True, columns: tuple[int, ...] = (),
               header: bool = False, delimiter: str | None = None) -> CsvResult:
    """Replace whole selected cells. Equal values share a placeholder per column."""
    if any(not isinstance(column, int) or isinstance(column, bool) or column < 1 for column in columns):
        raise DetectionError('CSV column numbers start at 1.')
    rows, detected = _table(text, delimiter)
    width = len(rows[0]) if rows else 0
    if columns and (not rows or max(columns) > width):
        raise DetectionError(f'Selected column is outside the table, which has {width} column(s).')
    if not emails and not columns:
        raise DetectionError('Select email cells or at least one CSV column to redact.')
    mappings: dict[str, dict[str, str]] = {}
    edits = []
    for row in rows[1:] if header else rows:
        for number, cell in enumerate(row, 1):
            if not cell.value.strip():
                continue
            is_email = emails and EMAIL.fullmatch(cell.value.strip()) is not None
            if number not in columns and not is_email:
                continue
            category = 'EMAIL' if is_email else f'COLUMN_{number}'
            mapping = mappings.setdefault(category, {})
            value = cell.value.strip() if is_email else cell.value
            if value not in mapping:
                mapping[value] = f'[{category}_{len(mapping) + 1}]'
            replacement = mapping[value]
            if cell.quoted:
                replacement = '"' + replacement + '"'
            edits.append((cell.start, cell.end, replacement))
    parts = []
    previous = 0
    for start, end, replacement in edits:
        parts.extend((text[previous:start], replacement))
        previous = end
    parts.append(text[previous:])
    return CsvResult(''.join(parts), len(edits), detected)
