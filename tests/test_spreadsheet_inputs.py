import csv
import io
from pathlib import Path

import pytest

from src.credentials import DetectionError
from src.csv_redactor import redact_csv
from src.file_inputs import read_text_file, folder_files
from src.spreadsheet_inputs import WorkbookInput, table_delimiter
from tests.workbook_fixtures import make_xlsx

FIXTURES = Path(__file__).parent / 'fixtures'


@pytest.mark.parametrize('extension', ['.xlsx', '.xlsm', '.xltx', '.xltm'])
def test_office_formats_sheet_selection_and_email_redaction(tmp_path, extension):
    path = make_xlsx(tmp_path / ('synthetic' + extension))
    before = path.read_bytes()
    workbook = WorkbookInput(path)
    try:
        assert workbook.sheets == ('Orders', 'Other sheet')
        table = workbook.preview('Orders')
        result = redact_csv(table, header=True, delimiter=',')
        assert result.text == table.replace('buyer@example.test', '[EMAIL_1]')
        assert result.count == 2
        assert list(csv.reader(io.StringIO(result.text)))[1] == ['synthetic-id', '1001', '[EMAIL_1]', '14999', 'false']
        other = workbook.preview('Other sheet')
        assert other == ',record,email\n,other-id,other@example.test\n'
        assert path.read_bytes() == before
    finally:
        workbook.close()


@pytest.mark.parametrize('extension', ['xls', 'xlsb', 'ods'])
def test_real_legacy_binary_and_opendocument_files(extension):
    workbook = WorkbookInput(FIXTURES / f'calamine-base.{extension}')
    try:
        assert workbook.sheets[:2] == ('Sheet1', 'Sheet2')
        rows = list(csv.reader(io.StringIO(workbook.preview('Sheet1'))))
        assert rows[0] == [''] * 10
        assert rows[1][:6] == ['String', '1', '1.1', 'true', 'false', '2010-10-10']
        assert workbook.preview('Sheet2') == ''
    finally:
        workbook.close()


def test_corrupt_workbook_error_never_echoes_content(tmp_path):
    path = tmp_path / 'private.xlsx'
    path.write_bytes(b'private@example.test invalid workbook')
    with pytest.raises(DetectionError) as error:
        WorkbookInput(path)
    assert 'private' not in str(error.value)


def test_missing_sheet_closed_workbook_and_size_limit(monkeypatch):
    workbook = WorkbookInput(FIXTURES / 'workbook.xlsx')
    try:
        with pytest.raises(DetectionError):
            workbook.preview('missing')
        monkeypatch.setattr('src.spreadsheet_inputs.MAX_SHEET_CELLS', 1)
        with pytest.raises(DetectionError, match='too large'):
            workbook.preview('Orders')
    finally:
        workbook.close()
    workbook.close()
    with pytest.raises(DetectionError):
        workbook.preview('Orders')


@pytest.mark.parametrize('encoding', ['utf-8-sig', 'utf-16', 'utf-32'])
def test_unicode_bom_imports_preserve_text_and_newlines(tmp_path, encoding):
    text = 'name,email\r\nSynthetic café,a@example.test\r\n'
    path = tmp_path / 'encoded.csv'
    path.write_bytes(text.encode(encoding))
    assert read_text_file(path) == text


def test_old_encoding_requires_explicit_selection_and_binary_is_rejected(tmp_path):
    path = tmp_path / 'old.csv'
    text = 'Synthetic café,a@example.test\r\n'
    path.write_bytes(text.encode('cp1252'))
    with pytest.raises(DetectionError):
        read_text_file(path)
    assert read_text_file(path, 'Windows-1252') == text
    path.write_bytes(b'\x00binary')
    with pytest.raises(DetectionError):
        read_text_file(path)


def test_workbook_cannot_be_read_as_text():
    with pytest.raises(DetectionError):
        read_text_file(FIXTURES / 'workbook.xlsx')


def test_folder_and_delimited_extensions(tmp_path):
    for name in ['a.xlsx', 'b.xls', 'c.xlsb', 'd.ods', 'e.tab', 'f.psv', 'g.ssv', 'h.jsonl', 'i.xml', 'j.toml']:
        (tmp_path / name).touch()
    (tmp_path / 'ignore.exe').touch()
    assert len(folder_files(tmp_path)) == 10
    assert table_delimiter('a.tab') == 'Tab'
    assert table_delimiter('b.psv') == 'Pipe'
    assert table_delimiter('c.ssv') == 'Semicolon'


def test_cli_selected_workbook_sheet_and_output(tmp_path, capsys):
    from src.cli import main
    source = make_xlsx(tmp_path / 'orders.xlsx')
    assert main([str(source), '--sheet', 'Other sheet', '--header', '--stdout']) == 0
    assert capsys.readouterr().out == ',record,email\n,other-id,[EMAIL_1]\n'
    output = tmp_path / 'orders.anon.csv'
    assert main([str(source), '--header', '-o', str(output)]) == 0
    assert b'synthetic-id,1001,[EMAIL_1],14999,false' in output.read_bytes()
    assert b'buyer@example.test' not in output.read_bytes()


def test_cli_delimited_old_encoding_and_columns(tmp_path, capsys):
    from src.cli import main
    source = tmp_path / 'orders.ssv'
    source.write_bytes('synthetic-id;1001;café;a@example.test\r\n'.encode('cp1252'))
    assert main([str(source), '--encoding', 'Windows-1252', '--columns', '1,2', '--stdout']) == 0
    assert capsys.readouterr().out == '[COLUMN_1_1];[COLUMN_2_1];café;[EMAIL_1]\r\n'


def test_cli_table_cannot_overwrite_input_or_mislabel_workbook_output(tmp_path, capsys):
    from src.cli import main
    source = make_xlsx(tmp_path / 'orders.xlsx')
    original = source.read_bytes()
    assert main([str(source), '-o', str(source)]) == 1
    assert source.read_bytes() == original
    assert main([str(source), '-o', str(tmp_path / 'other.xlsx')]) == 1
    assert not (tmp_path / 'other.xlsx').exists()
    assert 'buyer@example.test' not in capsys.readouterr().err
