"""Read workbook cell values into a selected-sheet CSV preview, locally."""
from __future__ import annotations

import csv
from datetime import date, datetime, time
import io
from pathlib import Path

from src.credentials import DetectionError

WORKBOOK_SUFFIXES = {'.xlsx', '.xls', '.xlsm', '.xlsb', '.ods', '.xltx', '.xltm'}
DELIMITED_SUFFIXES = {'.csv', '.tsv', '.tab', '.psv', '.ssv'}
TABLE_SUFFIXES = WORKBOOK_SUFFIXES | DELIMITED_SUFFIXES
MAX_SHEET_CELLS = 2_000_000


def _cell_text(value):
    if value is None:
        return ''
    if isinstance(value, bool):
        return 'true' if value else 'false'
    if isinstance(value, (datetime, date, time)):
        return value.isoformat(sep=' ') if isinstance(value, datetime) else value.isoformat()
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


class WorkbookInput:
    """Keep one read-only workbook open while the user selects worksheets."""

    def __init__(self, path):
        self._book = None
        try:
            self.path = Path(path).resolve()
            from python_calamine import CalamineWorkbook, SheetTypeEnum
            if Path(path).suffix.lower() not in WORKBOOK_SUFFIXES:
                raise DetectionError('Unsupported workbook format.')
            self._book = CalamineWorkbook.from_path(self.path)
            self.sheets = tuple(sheet.name for sheet in self._book.sheets_metadata
                                if sheet.typ == SheetTypeEnum.WorkSheet)
            if not self.sheets:
                raise DetectionError('The workbook has no readable worksheets.')
        except Exception:
            self.close()
            raise DetectionError('Could not open this workbook. Use an unencrypted Excel or OpenDocument file.') from None

    def preview(self, name):
        try:
            if name not in self.sheets or self._book is None:
                raise DetectionError('Choose a worksheet from the loaded workbook.')
            sheet = self._book.get_sheet_by_name(name)
            if sheet.total_height * sheet.total_width > MAX_SHEET_CELLS:
                raise DetectionError('This worksheet is too large. Export a smaller table first (maximum 2 million cells).')
            rows = sheet.to_python(skip_empty_area=False)
            width = max((len(row) for row in rows), default=0)
            output = io.StringIO(newline='')
            writer = csv.writer(output, lineterminator='\n')
            for row in rows:
                writer.writerow([_cell_text(value) for value in row] + [''] * (width - len(row)))
            return output.getvalue()
        except DetectionError:
            raise
        except Exception:
            raise DetectionError('Could not read the selected worksheet. Workbook values are omitted from diagnostics.') from None

    def close(self):
        if self._book is not None:
            try:
                self._book.close()
            finally:
                self._book = None


def table_delimiter(path):
    return {'.tsv': 'Tab', '.tab': 'Tab', '.psv': 'Pipe', '.ssv': 'Semicolon'}.get(Path(path).suffix.lower(), 'Auto')
