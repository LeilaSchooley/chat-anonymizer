import csv
import io

import pytest

from src.credentials import DetectionError
from src.csv_redactor import parse_columns, redact_csv


@pytest.mark.parametrize('delimiter', [',', '\t', ';', '|'])
def test_email_only_preserves_all_other_fields_and_duplicate_rows(delimiter):
    row = delimiter.join(['record-demo', '1001', 'Synthetic Name', 'buyer@example.test', '', 'GB', '14999'])
    source = row + '\r\n' + row + '\r\n'
    result = redact_csv(source)
    assert result.text == source.replace('buyer@example.test', '[EMAIL_1]')
    assert result.count == 2
    assert result.delimiter == delimiter


def test_selected_ids_header_and_repeated_values():
    source = 'uuid,order,email,amount\nabc,123,a@example.test,14999\nabc,456,b@example.test,14999\n'
    result = redact_csv(source, columns=(1, 2), header=True)
    assert result.text == ('uuid,order,email,amount\n'
                           '[COLUMN_1_1],[COLUMN_2_1],[EMAIL_1],14999\n'
                           '[COLUMN_1_1],[COLUMN_2_2],[EMAIL_2],14999\n')
    assert result.count == 6


def test_quotes_multiline_escaped_quotes_and_empty_cells_are_preserved():
    source = '\ufeff"record","note","email","empty"\r\n"abc","line one,\r\nline ""two""","a@example.test",\r\n\r\n'
    result = redact_csv(source, header=True)
    assert result.text == source.replace('a@example.test', '[EMAIL_1]')
    assert list(csv.reader(io.StringIO(result.text.removeprefix('\ufeff'), newline='')))[1][1] == 'line one,\r\nline "two"'


def test_headerless_first_row_redacted_and_email_detection_can_be_disabled():
    source = 'abc,123,a@example.test\n'
    assert redact_csv(source).text == 'abc,123,[EMAIL_1]\n'
    assert redact_csv(source, emails=False, columns=(2,)).text == 'abc,[COLUMN_2_1],a@example.test\n'


def test_selected_quoted_whole_cell_with_delimiters_remains_valid():
    source = '"one,two",a@example.test\n'
    result = redact_csv(source, emails=False, columns=(1,))
    assert result.text == '"[COLUMN_1_1]",a@example.test\n'
    assert next(csv.reader(io.StringIO(result.text))) == ['[COLUMN_1_1]', 'a@example.test']


@pytest.mark.parametrize('source', ['abc,private@example.test\nabc,2,private@example.test',
                                   'abc,"private@example.test', '"private@example.test"oops,123',
                                   'abc,pri"vate@example.test'])
def test_bad_tables_rejected_without_echoing_values(source):
    with pytest.raises(DetectionError) as error:
        redact_csv(source)
    assert 'private' not in str(error.value)
    assert '@example.test' not in str(error.value)


def test_explicit_delimiter_disambiguates_embedded_separators():
    source = 'abc\tone,two,three\ta@example.test\r\n'
    with pytest.raises(DetectionError, match='delimiter'):
        redact_csv(source)
    assert redact_csv(source, delimiter='\t').text == source.replace('a@example.test', '[EMAIL_1]')


def test_inconsistent_incidental_separator_does_not_override_table_delimiter():
    source = 'abc\tone,two,three\ta@example.test\nxyz\tone,two\tb@example.test\n'
    assert redact_csv(source).text == source.replace('a@example.test', '[EMAIL_1]').replace('b@example.test', '[EMAIL_2]')


@pytest.mark.parametrize('columns', [(0,), (-1,), (4,), (True,)])
def test_invalid_column_rejected(columns):
    with pytest.raises(DetectionError):
        redact_csv('abc,123,a@example.test', columns=columns)


@pytest.mark.parametrize('value', ['0', '-1', '1,,2', 'email', '1;2', '١'])
def test_invalid_column_entry(value):
    with pytest.raises(DetectionError):
        parse_columns(value)


def test_column_entry_and_no_selection():
    assert parse_columns(' 1, 2,1 ') == (1, 2)
    assert parse_columns('') == ()
    with pytest.raises(DetectionError):
        redact_csv('a,b', emails=False)


def test_single_column_empty_input_and_trailing_empty_fields():
    assert redact_csv('a@example.test\n').text == '[EMAIL_1]\n'
    assert redact_csv('').text == ''
    assert redact_csv('a@example.test,,').text == '[EMAIL_1],,'
    assert redact_csv('a@example.test,,', columns=(3,)).count == 1
