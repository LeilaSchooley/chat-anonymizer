import json
import time
from types import SimpleNamespace

import pytest

from src.credentials import CredentialEngine, CredentialPolicy, DetectionError
from src.file_inputs import read_file_batch
from src.gui import App, create_root
from src.json_redactor import redact_json_documents


def wait_for_output(root, app):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline and not app.status.get().startswith('Done:'):
        root.update()
        time.sleep(.01)
    assert app.status.get().startswith('Done:')


@pytest.fixture(scope='module')
def shared_app():
    root = create_root()
    root.withdraw()
    app = App(root)
    yield app
    root.destroy()


@pytest.fixture
def app(shared_app):
    # Like the desktop application, keep one native Tk/TkDND interpreter alive.
    shared_app.input.delete('1.0', 'end')
    shared_app.output.configure(state='normal')
    shared_app.output.delete('1.0', 'end')
    shared_app.output.configure(state='disabled')
    shared_app.mode.set('JSON values under keys')
    shared_app.action.set('redact')
    shared_app.proxy_mode.set('standard')
    shared_app.csv_emails.set(True)
    shared_app.csv_uuid.set(False)
    shared_app.csv_order_id.set(False)
    shared_app.csv_header.set(False)
    shared_app.csv_columns.set('')
    shared_app.csv_delimiter.set('Auto')
    shared_app.threshold.set('0.7')
    shared_app.text_encoding.set('Auto')
    shared_app.clear_workbook()
    return shared_app


def five_files(tmp_path):
    paths = []
    contents = []
    for index in range(5):
        path = tmp_path / f'input with spaces {index}.json'
        content = '{\r\n "index": ' + str(index) + ', "token": "synthetic-' + str(index) + '", "preserve_cookies": false\r\n}'
        with path.open('w', encoding='utf-8', newline='') as stream:
            stream.write(content)
        paths.append(str(path))
        contents.append(content)
    return paths, contents


def test_read_five_files_in_order_with_exact_contents(tmp_path):
    paths, contents = five_files(tmp_path)
    text, all_json = read_file_batch(paths)
    assert all_json
    assert text == '\n\n'.join(contents)


def test_native_drop_binding_and_five_file_callback(tmp_path, app):
    paths, contents = five_files(tmp_path)
    assert app.root.TkdndVersion
    assert app.input.dnd_bind('<<Drop>>')
    payload = app.root.tk.call('format', '%s', tuple(paths))
    assert app.drop_files(SimpleNamespace(data=payload)) == 'copy'
    assert json.loads(app.input.get('1.0', 'end-1c')) == [json.loads(item) for item in contents]
    assert app.mode.get() == 'JSON values under keys'
    app.redact()
    wait_for_output(app.root, app)
    expected = app.input.get('1.0', 'end-1c')
    for index in range(5):
        expected = expected.replace('"synthetic-' + str(index) + '"', '"[REDACTED]"')
    assert app.output.get('1.0', 'end-1c') == expected


def test_file_picker_accepts_multiple_files(tmp_path, app, monkeypatch):
    paths, contents = five_files(tmp_path)
    monkeypatch.setattr('src.gui.filedialog.askopenfilenames', lambda **kwargs: tuple(paths))
    app.open_file()
    assert json.loads(app.input.get('1.0', 'end-1c')) == [json.loads(item) for item in contents]


def test_repeated_drop_appends_and_invalid_batch_is_atomic(tmp_path, app, monkeypatch):
    paths, contents = five_files(tmp_path)
    assert app.add_files(paths[:2])
    assert app.add_files(paths[2:])
    before = app.input.get('1.0', 'end-1c')
    assert json.loads(before) == [json.loads(item) for item in contents]
    errors = []
    monkeypatch.setattr('src.gui.messagebox.showerror', lambda title, message: errors.append(message))
    assert not app.add_files([paths[0], str(tmp_path / 'missing.json')])
    assert app.input.get('1.0', 'end-1c') == before
    assert len(errors) == 1


def test_mixed_files_switch_to_credential_text_mode(tmp_path, app):
    path = tmp_path / 'config.env'
    path.write_text('PROXY_PASSWORD=synthetic\n', encoding='utf-8')
    json_path = tmp_path / 'settings.json'
    json_path.write_text('{"token":"synthetic"}', encoding='utf-8')
    assert app.add_files([str(path), str(json_path)])
    assert app.mode.get() == 'Credentials in text / config'


def test_unreadable_batch_error_never_includes_content(tmp_path):
    good = tmp_path / 'good.json'
    good.write_text('{"token":"do-not-show"}')
    bad = tmp_path / 'bad.json'
    bad.write_bytes(b'\xff\xfe\xff')
    with pytest.raises(DetectionError) as error:
        read_file_batch([str(good), str(bad)])
    assert 'do-not-show' not in str(error.value)


def test_stacked_json_offsets_and_whitespace_preservation():
    source = ' \r\n{"token":"first"}\r\n\r\n[ {"password":"second","enabled":true} ]  \n'
    result = redact_json_documents(source)
    assert result.text == source.replace('"first"', '"[REDACTED]"').replace('"second"', '"[REDACTED]"')
    for finding in result.findings:
        assert source[finding.start:finding.end] in {'"first"', '"second"'}
    assert [finding.location for finding in result.findings] == ['document/0/0', 'document/1/0/0']


def test_stacked_json_malformed_later_document_and_blocking_are_safe():
    with pytest.raises(DetectionError):
        redact_json_documents('{"token":"first"}\n{"token":"bad",')
    engine = CredentialEngine(CredentialPolicy(action='block'))
    with pytest.raises(DetectionError):
        redact_json_documents('{"enabled":false}\n{"token":"first"}', engine=engine)


def test_gui_proxy_privacy_control_applies_policy(app):
    app.input.insert('1.0', '{"proxy":"192.0.2.59:6491","enabled":false}')
    app.proxy_mode.set('strict')
    app.redact()
    wait_for_output(app.root, app)
    assert json.loads(app.output.get('1.0', 'end-1c')) == {'proxy':'[REDACTED]','enabled':False}


def test_drop_repairs_and_polish_pasted_input(tmp_path, app):
    path = tmp_path / 'repair.json'
    path.write_text('{"token":"synthetic", "enabled":false,}//comment')
    assert app.add_files([str(path)])
    assert 'repaired' in app.status.get()
    assert json.loads(app.input.get('1.0', 'end-1c')) == {'token':'synthetic','enabled':False}
    app.input.delete('1.0', 'end')
    app.input.insert('1.0', '{"id":1,}\n{"id":2}')
    app.polish_json()
    assert json.loads(app.input.get('1.0', 'end-1c')) == [{'id':1},{'id':2}]


def test_invalid_file_cannot_borrow_closing_brace(tmp_path, app, monkeypatch):
    first = tmp_path / 'first.json'
    second = tmp_path / 'second.json'
    first.write_text('{"token":"synthetic"')
    second.write_text('}')
    monkeypatch.setattr('src.gui.messagebox.showerror', lambda *args: None)
    app.input.insert('1.0', '{"existing":true}')
    assert not app.add_files([str(first),str(second)])
    assert app.input.get('1.0','end-1c') == '{"existing":true}'


def test_gui_category_settings_control_redaction(app):
    app.restore_categories()
    app.keys.set('')
    assert all(variable.get() for variable in app.categories.values())

    app.categories['USERNAME'].set(False)
    app.categories['API_KEY'].set(False)
    app.input.insert('1.0', '{"username":"alice","api_key":"synthetic","password":"synthetic","enabled":false}')
    app.redact()
    wait_for_output(app.root, app)
    assert json.loads(app.output.get('1.0','end-1c')) == {
        'username':'alice','api_key':'synthetic','password':'[REDACTED]','enabled':False}
    assert 'disabled' in app.status.get()
    app.restore_categories()
    assert all(variable.get() for variable in app.categories.values())


def test_open_folder_imports_five_json_files(tmp_path, app, monkeypatch):
    paths, contents = five_files(tmp_path)
    (tmp_path / 'ignore.exe').write_bytes(b'\xff')
    nested = tmp_path / 'nested'
    nested.mkdir()
    (nested / 'hidden.json').write_text('{"nested":true}')
    monkeypatch.setattr('src.gui.filedialog.askdirectory', lambda **kwargs: str(tmp_path))
    app.open_folder()
    assert json.loads(app.input.get('1.0','end-1c')) == [json.loads(item) for item in contents]


def test_drop_folder_and_empty_folder_atomic(tmp_path, app, monkeypatch):
    paths, contents = five_files(tmp_path)
    payload = app.root.tk.call('format', '%s', (str(tmp_path),))
    assert app.drop_files(SimpleNamespace(data=payload)) == 'copy'
    assert json.loads(app.input.get('1.0','end-1c')) == [json.loads(item) for item in contents]
    before = app.input.get('1.0','end-1c')
    empty = tmp_path / 'empty'
    empty.mkdir()
    monkeypatch.setattr('src.gui.messagebox.showerror', lambda *args: None)
    monkeypatch.setattr('src.gui.filedialog.askdirectory', lambda **kwargs: str(empty))
    app.open_folder()
    assert app.input.get('1.0','end-1c') == before


def test_tsv_import_email_only_then_optional_order_columns(tmp_path, app):
    source = 'record\torder\temail\tamount\r\nsynthetic-id\t1001\ta@example.test\t14999\r\n'
    path = tmp_path / 'orders.tsv'
    with path.open('w', encoding='utf-8', newline='') as stream:
        stream.write(source)
    assert app.add_files([str(path)])
    assert app.mode.get() == 'CSV / TSV columns'
    assert app.csv_options.winfo_manager() == 'pack'
    assert not app.credential_settings.winfo_manager()
    app.csv_header.set(True)
    app.action.set('warn')
    app.threshold.set('not-a-number')  # Credential settings do not affect CSV mode.
    app.redact()
    wait_for_output(app.root, app)
    assert app.output.get('1.0', 'end-1c') == source.replace('a@example.test', '[EMAIL_1]')
    app.csv_uuid.set(True)
    app.csv_order_id.set(True)
    app.redact()
    wait_for_output(app.root, app)
    assert app.output.get('1.0', 'end-1c') == source.replace('a@example.test', '[EMAIL_1]').replace('synthetic-id', '[COLUMN_1_1]').replace('1001', '[COLUMN_2_1]')


def test_csv_multi_import_is_atomic_and_single_import_replaces_table(tmp_path, app, monkeypatch):
    first, second = tmp_path / 'first.csv', tmp_path / 'second.csv'
    first.write_text('a@example.test,1001\n', encoding='utf-8')
    second.write_text('b@example.test,1002\n', encoding='utf-8')
    assert app.add_files([str(first)])
    before = app.input.get('1.0', 'end-1c')
    monkeypatch.setattr('src.gui.messagebox.showerror', lambda *args: None)
    assert not app.add_files([str(first), str(second)])
    assert app.input.get('1.0', 'end-1c') == before
    assert app.add_files([str(second)])
    assert app.input.get('1.0', 'end-1c') == second.read_bytes().decode('utf-8')


def test_csv_save_uses_tsv_extension_and_exact_output(tmp_path, app, monkeypatch):
    source = 'record\ta@example.test\t14999\n'
    app.mode.set('CSV / TSV columns')
    app.input.insert('1.0', source)
    app.redact()
    wait_for_output(app.root, app)
    options = {}
    path = tmp_path / 'saved.tsv'
    def choose(**kwargs):
        options.update(kwargs)
        return str(path)
    monkeypatch.setattr('src.gui.filedialog.asksaveasfilename', choose)
    app.save()
    assert options['defaultextension'] == '.tsv'
    assert path.read_bytes() == source.replace('a@example.test', '[EMAIL_1]').encode()


def test_pasted_csv_mode_switch_hides_and_restores_settings(app):
    app.mode.set('CSV / TSV columns')
    app.input.insert('1.0', 'record,1001,a@example.test,14999')
    app.csv_columns.set('2')
    app.csv_emails.set(False)
    app.redact()
    wait_for_output(app.root, app)
    assert app.output.get('1.0', 'end-1c') == 'record,[COLUMN_2_1],a@example.test,14999'
    app.mode.set('Chat PII')
    assert not app.csv_options.winfo_manager()
    assert app.credential_settings.winfo_manager() == 'pack'


def test_workbook_import_sheet_switch_and_export(app, tmp_path, monkeypatch):
    from pathlib import Path
    source = Path(__file__).parent / 'fixtures/workbook.xlsx'
    assert app.add_files([str(source)])
    assert app.mode.get() == 'CSV / TSV columns'
    assert app.csv_delimiter.get() == 'Comma'
    assert tuple(app.sheet_picker['values']) == ('Orders', 'Other sheet')
    app.csv_header.set(True)
    app.redact()
    wait_for_output(app.root, app)
    assert 'buyer@example.test' not in app.output.get('1.0', 'end-1c')
    app.workbook_sheet.set('Other sheet')
    app.select_workbook_sheet()
    assert app.output.get('1.0', 'end-1c') == ''
    assert app.input.get('1.0', 'end-1c') == ',record,email\n,other-id,other@example.test\n'
    app.redact()
    wait_for_output(app.root, app)
    output = tmp_path / 'selected.csv'
    monkeypatch.setattr('src.gui.filedialog.asksaveasfilename', lambda **kwargs: str(output))
    app.save()
    assert output.read_bytes() == b',record,email\n,other-id,[EMAIL_1]\n'


def test_failed_workbook_import_and_sheet_selection_preserve_current_input(app, tmp_path, monkeypatch):
    from pathlib import Path
    from src.spreadsheet_inputs import WorkbookInput
    source = Path(__file__).parent / 'fixtures/workbook.xlsx'
    assert app.add_files([str(source)])
    before = app.input.get('1.0', 'end-1c')
    monkeypatch.setattr('src.gui.messagebox.showerror', lambda *args: None)
    invalid = tmp_path / 'broken.xlsb'
    invalid.write_bytes(b'private@example.test')
    assert not app.add_files([str(invalid)])
    assert app.input.get('1.0', 'end-1c') == before
    assert app.workbook is not None
    monkeypatch.setattr(WorkbookInput, 'preview', lambda *args: (_ for _ in ()).throw(DetectionError('Cannot read worksheet.')))
    app.workbook_sheet.set('Other sheet')
    app.select_workbook_sheet()
    assert app.workbook_sheet.get() == 'Orders'
    assert app.input.get('1.0', 'end-1c') == before


@pytest.mark.parametrize('extension,separator,label', [('.tab', '\t', 'Tab'), ('.psv', '|', 'Pipe'), ('.ssv', ';', 'Semicolon')])
def test_more_delimited_extensions(app, tmp_path, extension, separator, label):
    source = separator.join(['id', 'a@example.test', '14999'])
    path = tmp_path / ('orders' + extension)
    path.write_bytes(source.encode())
    assert app.add_files([str(path)])
    assert app.csv_delimiter.get() == label
    app.redact()
    wait_for_output(app.root, app)
    assert app.output.get('1.0', 'end-1c') == source.replace('a@example.test', '[EMAIL_1]')


def test_workbook_batch_and_unsupported_file_are_rejected_atomically(app, tmp_path, monkeypatch):
    from pathlib import Path
    source = str(Path(__file__).parent / 'fixtures/workbook.xlsx')
    app.input.insert('1.0', 'keep this input')
    monkeypatch.setattr('src.gui.messagebox.showerror', lambda *args: None)
    assert not app.add_files([source, source])
    unknown = tmp_path / 'file.pdf'
    unknown.write_bytes(b'not a text import')
    assert not app.add_files([str(unknown)])
    assert app.input.get('1.0', 'end-1c') == 'keep this input'


def test_json_lines_and_explicit_old_encoding(app, tmp_path):
    path = tmp_path / 'rows.ndjson'
    path.write_bytes(b'{"token":"synthetic"}\n{"enabled":true}\n')
    assert app.add_files([str(path)])
    assert app.mode.get() == 'JSON values under keys'
    assert json.loads(app.input.get('1.0', 'end-1c')) == [{'token': 'synthetic'}, {'enabled': True}]
    app.input.delete('1.0', 'end')
    path = tmp_path / 'old.json'
    path.write_bytes('{"label":"café","token":"synthetic"}'.encode('cp1252'))
    app.text_encoding.set('Windows-1252')
    assert app.add_files([str(path)])
    assert json.loads(app.input.get('1.0', 'end-1c'))['label'] == 'café'


def test_workbook_save_cannot_overwrite_original(app, tmp_path, monkeypatch):
    from tests.workbook_fixtures import make_xlsx
    source = make_xlsx(tmp_path / 'orders.xlsx')
    before = source.read_bytes()
    assert app.add_files([str(source)])
    app.redact()
    wait_for_output(app.root, app)
    errors = []
    monkeypatch.setattr('src.gui.filedialog.asksaveasfilename', lambda **kwargs: str(source))
    monkeypatch.setattr('src.gui.messagebox.showerror', lambda *args: errors.append(args))
    app.save()
    assert source.read_bytes() == before
    assert errors


def test_sheet_cannot_switch_during_redaction(app):
    from pathlib import Path
    assert app.add_files([str(Path(__file__).parent / 'fixtures/workbook.xlsx')])
    app.redact()
    app.workbook_sheet.set('Other sheet')
    app.select_workbook_sheet()
    assert app.workbook_sheet.get() == 'Orders'
    wait_for_output(app.root, app)
    assert 'other-id' not in app.output.get('1.0', 'end-1c')
