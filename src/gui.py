"""Local desktop interface for chat and JSON redaction."""
from __future__ import annotations

import queue
import threading
import tkinter as tk
from pathlib import Path
from dataclasses import replace
import json
from tkinter import filedialog, messagebox, scrolledtext, ttk

from src.json_redactor import redact_json_documents
from src.credentials import CredentialEngine, CredentialPolicy, DetectionError, load_policy, REDACTION_CATEGORIES
from src.file_inputs import read_file_batch, read_json_batch, folder_files, TEXT_ENCODINGS, SUPPORTED_INPUT_SUFFIXES, supported_input
from src.spreadsheet_inputs import WorkbookInput, WORKBOOK_SUFFIXES, TABLE_SUFFIXES, table_delimiter
from src.json_inputs import parse_inputs, format_inputs
from src.csv_redactor import redact_csv, parse_columns, DELIMITERS


def create_root():
    try:
        from tkinterdnd2 import TkinterDnD
        return TkinterDnD.Tk()
    except (ImportError, tk.TclError):
        root = tk.Tk()
        root.drop_unavailable = True
        return root


class App:
    def __init__(self, root):
        self.root = root
        root.title("Chat Anonymizer")
        root.geometry("1100x720")
        self.events = queue.Queue()
        self.import_snapshot = None
        self.import_documents = []
        self.mode = tk.StringVar(value="JSON values under keys")
        self.keys = tk.StringVar(value="")
        self.categories = {key: tk.BooleanVar(value=True) for key, _ in REDACTION_CATEGORIES}
        self.chat_pii = tk.BooleanVar(value=True)
        self.auto_sensitive = tk.BooleanVar(value=True)
        self.policy = CredentialPolicy()
        self.action = tk.StringVar(value="redact")
        self.threshold = tk.StringVar(value="0.7")
        self.proxy_mode = tk.StringVar(value="standard")
        self.csv_emails = tk.BooleanVar(value=True)
        self.csv_uuid = tk.BooleanVar(value=False)
        self.csv_order_id = tk.BooleanVar(value=False)
        self.csv_columns = tk.StringVar(value='')
        self.csv_header = tk.BooleanVar(value=False)
        self.csv_delimiter = tk.StringVar(value='Auto')
        self.text_encoding = tk.StringVar(value='Auto')
        self.workbook = None
        self.workbook_sheet = tk.StringVar(value='')
        self.loaded_sheet = ''
        self.status = tk.StringVar(value="Paste text, open files, or drop files into the input box. Processing stays local.")
        toolbar = ttk.Frame(root, padding=10)
        toolbar.pack(fill="x")
        ttk.Button(toolbar, text="Open files", command=self.open_file).pack(side="left")
        ttk.Button(toolbar, text="Open folder", command=self.open_folder).pack(side="left", padx=5)
        ttk.Button(toolbar, text="Polish JSON", command=self.polish_json).pack(side="left", padx=5)
        ttk.Combobox(toolbar, textvariable=self.mode, state="readonly", width=28,
                     values=["JSON values under keys", "JSON key names", "Credentials in text / config", "Chat PII", "CSV / TSV columns"]).pack(side="left", padx=10)
        self.run_button = ttk.Button(toolbar, text="Redact", command=self.redact)
        self.run_button.pack(side="left")
        ttk.Button(toolbar, text="Copy output", command=self.copy).pack(side="right")
        ttk.Button(toolbar, text="Save output", command=self.save).pack(side="right", padx=10)
        options = ttk.Frame(root, padding=(10, 0, 10, 10))
        self.json_options = options
        options.pack(fill="x")
        ttk.Label(options, text="JSON keys (comma-separated, case-sensitive):").pack(side="left")
        ttk.Entry(options, textvariable=self.keys).pack(side="left", fill="x", expand=True, padx=10)
        self.auto_checkbox = ttk.Checkbutton(root, text="Automatically detect credentials in JSON (names, values, and context)",
                        variable=self.auto_sensitive)
        self.auto_checkbox.pack(anchor="w", padx=10)
        self.csv_options = ttk.Frame(root, padding=10)
        self.workbook_options = ttk.Frame(self.csv_options)
        ttk.Label(self.workbook_options, text='Worksheet:').pack(side='left')
        self.sheet_picker = ttk.Combobox(self.workbook_options, textvariable=self.workbook_sheet,
                                        state='readonly', width=24)
        self.sheet_picker.pack(side='left', padx=8)
        self.sheet_picker.bind('<<ComboboxSelected>>', lambda _: self.select_workbook_sheet())
        ttk.Label(self.workbook_options, text='Selected sheet only. Values exported as CSV/TSV; styles and formulas are not exported.').pack(side='left')
        csv_choices = ttk.Frame(self.csv_options)
        self.csv_choices = csv_choices
        csv_choices.pack(fill='x')
        ttk.Checkbutton(csv_choices, text='Email cells', variable=self.csv_emails).pack(side='left')
        ttk.Checkbutton(csv_choices, text='Order UUID (column 1)', variable=self.csv_uuid).pack(side='left', padx=12)
        ttk.Checkbutton(csv_choices, text='Order ID (column 2)', variable=self.csv_order_id).pack(side='left')
        ttk.Checkbutton(csv_choices, text='First row is a header', variable=self.csv_header).pack(side='left', padx=12)
        csv_fields = ttk.Frame(self.csv_options)
        csv_fields.pack(fill='x', pady=(6, 0))
        ttk.Label(csv_fields, text='Other columns (numbers, e.g. 3,5):').pack(side='left')
        ttk.Entry(csv_fields, textvariable=self.csv_columns, width=16).pack(side='left', padx=8)
        ttk.Label(csv_fields, text='Delimiter:').pack(side='left')
        ttk.Combobox(csv_fields, textvariable=self.csv_delimiter, state='readonly', width=12,
                     values=list(DELIMITERS)).pack(side='left', padx=8)
        ttk.Label(self.csv_options, text='Only selected cells change. Column numbers start at 1; order controls refer to your export layout.').pack(anchor='w', pady=(6, 0))
        import_settings = ttk.Frame(root, padding=(10, 4))
        import_settings.pack(fill='x')
        ttk.Label(import_settings, text='Text file encoding:').pack(side='left')
        ttk.Combobox(import_settings, textvariable=self.text_encoding, state='readonly', width=16,
                     values=list(TEXT_ENCODINGS)).pack(side='left', padx=8)
        ttk.Label(import_settings, text='Auto reads UTF-8 and Unicode BOMs. For older exports choose Windows-1252 before opening.').pack(side='left')
        settings = ttk.Frame(root, padding=10)
        self.credential_settings = settings
        settings.pack(fill="x")
        ttk.Label(settings, text="Credential action:").pack(side="left")
        ttk.Combobox(settings, textvariable=self.action, state="readonly", width=10,
                     values=["redact", "block", "warn", "report"]).pack(side="left", padx=8)
        ttk.Label(settings, text="Confidence:").pack(side="left")
        ttk.Spinbox(settings, textvariable=self.threshold, from_=0, to=1, increment=0.05, width=6).pack(side="left", padx=8)
        ttk.Button(settings, text="Load credential policy", command=self.load_settings).pack(side="left")
        ttk.Button(settings, text="Redaction settings", command=self.redaction_settings).pack(side="left", padx=8)
        ttk.Label(settings, text="Proxy privacy:").pack(side="left", padx=(12, 4))
        ttk.Combobox(settings, textvariable=self.proxy_mode, state="readonly", width=10,
                     values=["standard", "strict"]).pack(side="left")
        panels = ttk.Panedwindow(root, orient="horizontal")
        self.panels = panels
        panels.pack(fill="both", expand=True, padx=10)
        self.input = self.panel(panels, "Input — paste text / JSON or drop files here")
        self.output = self.panel(panels, "Redacted output")
        self.output.configure(state="disabled")
        if hasattr(self.input, 'drop_target_register') and hasattr(root, 'TkdndVersion'):
            from tkinterdnd2 import DND_FILES
            self.input.drop_target_register(DND_FILES)
            self.input.dnd_bind('<<Drop>>', self.drop_files)
        else:
            self.status.set('Drag-and-drop is unavailable in this build. Use Open files / Open folder.')
        ttk.Label(root, textvariable=self.status, padding=10).pack(fill="x")
        self.mode.trace_add('write', lambda *_: self.update_mode())
        root.bind('<Destroy>', lambda event: self.workbook.close() if event.widget == root and self.workbook else None, add='+')
        root.after(100, self.poll)

    def update_mode(self):
        for widget in (self.json_options, self.auto_checkbox, self.csv_options, self.credential_settings):
            widget.pack_forget()
        if self.mode.get() == 'CSV / TSV columns':
            self.csv_options.pack(fill='x', before=self.panels)
        else:
            self.json_options.pack(fill='x', before=self.panels)
            self.auto_checkbox.pack(anchor='w', padx=10, before=self.panels)
            self.credential_settings.pack(fill='x', before=self.panels)

    def panel(self, parent, label):
        frame = ttk.Frame(parent)
        ttk.Label(frame, text=label).pack(anchor="w", pady=5)
        widget = scrolledtext.ScrolledText(frame, wrap="word", undo=True, font=("Consolas", 11))
        widget.pack(fill="both", expand=True)
        parent.add(frame, weight=1)
        return widget

    def open_file(self):
        paths = filedialog.askopenfilenames(filetypes=[
            ('Supported files', ' '.join('*' + suffix for suffix in sorted(SUPPORTED_INPUT_SUFFIXES)) + ' .env .env.*'),
            ('Excel / OpenDocument', '*.xlsx *.xls *.xlsm *.xlsb *.ods *.xltx *.xltm'),
            ('Delimited tables', '*.csv *.tsv *.tab *.psv *.ssv'),
            ('All files', '*.*')])
        if paths:
            self.add_files(list(paths))

    def open_folder(self):
        directory = filedialog.askdirectory(title='Open folder — import supported files')
        if not directory:
            return
        try:
            paths = folder_files(directory)
        except DetectionError as exc:
            messagebox.showerror('Cannot open folder', str(exc))
            return
        self.add_files(paths)

    def drop_files(self, event):
        try:
            paths = list(self.root.tk.splitlist(event.data))
            expanded = []
            for path in paths:
                expanded.extend(folder_files(path) if Path(path).is_dir() else [path])
            return 'copy' if self.add_files(expanded) else 'none'
        except DetectionError as exc:
            messagebox.showerror('Cannot drop folder', str(exc))
            return 'none'
        except tk.TclError:
            messagebox.showerror("Cannot drop files", "The dropped file list could not be read.")
            return 'none'

    def add_files(self, paths):
        if str(self.run_button['state']) == 'disabled':
            messagebox.showerror('Processing', 'Wait for redaction to finish before opening another file.')
            return False
        try:
            if any(not supported_input(path) and Path(path).suffix for path in paths):
                raise DetectionError('Unsupported file type. Open a supported text, JSON, delimited table, or workbook file.')
            table_mode = bool(paths) and any(Path(path).suffix.lower() in TABLE_SUFFIXES for path in paths)
            if table_mode and len(paths) != 1:
                raise DetectionError('Open one table or workbook at a time so sheets, headers, and columns stay aligned.')
            if paths and Path(paths[0]).suffix.lower() in WORKBOOK_SUFFIXES:
                return self.open_workbook(paths[0])
            content, all_json = read_file_batch(paths, self.text_encoding.get())
            current = self.input.get('1.0', 'end-1c')
            json_mode = all_json and (not current or self.mode.get().startswith('JSON'))
            repaired = False
            if json_mode:
                documents, repaired = read_json_batch(paths, self.text_encoding.get())
                if current:
                    if current == self.import_snapshot:
                        previous = self.import_documents
                    else:
                        previous, changed = parse_inputs(current)
                        repaired = repaired or changed
                    documents = previous + documents
                content = format_inputs(documents)
        except DetectionError as exc:
            messagebox.showerror("Cannot open files", str(exc))
            return False
        self.clear_workbook()
        if table_mode:
            self.input.delete('1.0', 'end')
            self.input.insert('1.0', content)
            self.import_snapshot = None
            self.import_documents = []
        elif json_mode:
            self.input.delete('1.0', 'end')
            self.input.insert('1.0', content)
            self.import_snapshot = content
            self.import_documents = documents
        else:
            separator = '\n\n' if current else ''
            self.input.insert('end-1c', separator + content)
            self.import_snapshot = None
        self.output.configure(state='normal')
        self.output.delete('1.0', 'end')
        self.output.configure(state='disabled')
        if json_mode:
            self.mode.set('JSON values under keys')
        elif table_mode:
            self.csv_delimiter.set(table_delimiter(paths[0]))
            self.mode.set('CSV / TSV columns')
        else:
            self.mode.set('Credentials in text / config')
        detail = 'loaded as one table; select the header option if needed' if table_mode else ('combined and pretty-printed' if json_mode else 'stacked in input order')
        repair = ' Comments / trailing commas repaired; review the input.' if repaired else ''
        self.status.set(f"Added {len(paths)} file(s), {detail}.{repair} You can edit before redacting.")
        return True

    def clear_workbook(self):
        if self.workbook is not None:
            self.workbook.close()
            self.workbook = None
        self.loaded_sheet = ''
        self.workbook_sheet.set('')
        self.workbook_options.pack_forget()

    def open_workbook(self, path):
        workbook = WorkbookInput(path)
        try:
            name = workbook.sheets[0]
            content = workbook.preview(name)
        except Exception:
            workbook.close()
            raise
        self.clear_workbook()
        self.workbook = workbook
        self.sheet_picker.configure(values=workbook.sheets)
        self.workbook_options.pack(fill='x', pady=(0, 8), before=self.csv_choices)
        self.show_workbook_sheet(name, content)
        return True

    def show_workbook_sheet(self, name, content):
        self.workbook_sheet.set(name)
        self.loaded_sheet = name
        self.input.delete('1.0', 'end')
        self.input.insert('1.0', content)
        self.import_snapshot = None
        self.import_documents = []
        self.output.configure(state='normal')
        self.output.delete('1.0', 'end')
        self.output.configure(state='disabled')
        self.csv_delimiter.set('Comma')
        self.mode.set('CSV / TSV columns')
        self.status.set(f'Loaded worksheet {self.workbook.sheets.index(name) + 1} of {len(self.workbook.sheets)}. '
                        'Choose a sheet, review values and header setting, then redact. Only the selected sheet is exported.')

    def select_workbook_sheet(self):
        if self.workbook is None:
            return
        if str(self.run_button['state']) == 'disabled':
            self.workbook_sheet.set(self.loaded_sheet)
            self.status.set('Wait for redaction to finish before choosing another worksheet.')
            return
        try:
            name = self.workbook_sheet.get()
            content = self.workbook.preview(name)
        except DetectionError as exc:
            self.workbook_sheet.set(self.loaded_sheet)
            messagebox.showerror('Cannot open worksheet', str(exc))
            return
        self.show_workbook_sheet(name, content)

    def polish_json(self):
        try:
            current = self.input.get('1.0', 'end-1c')
            if current == self.import_snapshot:
                documents, repaired = self.import_documents, False
            else:
                documents, repaired = parse_inputs(current)
            formatted = format_inputs(documents)
        except DetectionError as exc:
            messagebox.showerror('Cannot polish JSON', str(exc))
            return
        self.input.delete('1.0', 'end')
        self.input.insert('1.0', formatted)
        self.import_snapshot, self.import_documents = formatted, documents
        self.mode.set('JSON values under keys')
        self.output.configure(state='normal')
        self.output.delete('1.0', 'end')
        self.output.configure(state='disabled')
        self.status.set('JSON combined and pretty-printed.' + (' Comments / trailing commas repaired; review before redacting.' if repaired else ''))

    def redact(self):
        text = self.input.get("1.0", "end-1c")
        mode = self.mode.get()
        keys = [key.strip() for key in self.keys.get().split(",") if key.strip()]
        auto_sensitive = self.auto_sensitive.get()
        chat_pii = self.chat_pii.get()
        csv_mode = mode == 'CSV / TSV columns'
        try:
            csv_columns = parse_columns(self.csv_columns.get()) if csv_mode else ()
            if csv_mode:
                csv_columns = tuple(sorted(set(csv_columns) | ({1} if self.csv_uuid.get() else set()) |
                                           ({2} if self.csv_order_id.get() else set())))
            csv_emails, csv_header = self.csv_emails.get(), self.csv_header.get()
            csv_delimiter = DELIMITERS[self.csv_delimiter.get()] if csv_mode else None
            if not csv_mode:
                policy = replace(self.policy, action=self.action.get(), threshold=float(self.threshold.get()),
                                 proxy_mode=self.proxy_mode.get(),
                                 disabled_categories=tuple(key for key, variable in self.categories.items() if not variable.get()))
                engine = CredentialEngine(policy)
        except Exception:
            messagebox.showerror("Invalid settings", "Check CSV column numbers and delimiter." if csv_mode else "Check the confidence threshold and credential policy.")
            return
        self.output.configure(state="normal")
        self.output.delete("1.0", "end")
        self.output.configure(state="disabled")
        self.run_button.configure(state="disabled")
        self.status.set("Processing…")

        def work():
            try:
                if csv_mode:
                    result = redact_csv(text, emails=csv_emails, columns=csv_columns,
                                        header=csv_header, delimiter=csv_delimiter)
                    self.events.put((result.text, f'Done: {result.count} cell(s) redacted. Other cells and row order preserved.'))
                    return
                elif mode == "Chat PII":
                    from src.anonymizer import ChatAnonymizer
                    from src.detectors import DEFAULT_ENTITIES
                    entities = DEFAULT_ENTITIES if chat_pii else [key for key, _ in REDACTION_CATEGORIES] + ['PROXY_ENDPOINT']
                    result = ChatAnonymizer(dedupe_lines=False, credential_policy=policy, entities=entities).anonymize(text)
                    output, count = result.text, len(result.entities_found)
                    if policy.action == "report":
                        output = json.dumps({"entities": result.entities_found}, indent=2)
                elif mode == "Credentials in text / config":
                    result = engine.apply_text(text, engine.detect_text(text, source="config"))
                    output, count = result.text, len(result.findings)
                    if policy.action == "report":
                        output = json.dumps(result.audit(), indent=2)
                else:
                    result = redact_json_documents(text, keys, key_names=mode == "JSON key names",
                                                auto_sensitive=auto_sensitive, engine=engine)
                    output, count = result.text, len(result.findings)
                    if policy.action == "report":
                        output = json.dumps(result.audit(), indent=2)
                suffix = " Warning only: credentials remain in the output." if policy.action == "warn" else ""
                if mode == "JSON key names":
                    suffix += " Key names only: values remain in the output."
                if policy.disabled_categories or (mode == 'Chat PII' and not chat_pii):
                    suffix += ' Some categories are disabled in Redaction settings.'
                self.events.put((output, f"Done: {count} finding(s); action: {policy.action}." + suffix))
            except Exception as exc:
                self.events.put((None, str(exc) if isinstance(exc, DetectionError) else
                                 "Processing failed. Input was not saved or included in diagnostics."))
        threading.Thread(target=work, daemon=True).start()

    def redaction_settings(self):
        window = tk.Toplevel(self.root)
        window.title('Redaction settings')
        window.transient(self.root)
        body = ttk.Frame(window, padding=16)
        body.pack(fill='both', expand=True)
        ttk.Label(body, text='Choose what to redact. All categories are enabled by default.').pack(anchor='w')
        for key, label in REDACTION_CATEGORIES:
            ttk.Checkbutton(body, text=label, variable=self.categories[key]).pack(anchor='w', pady=2)
        ttk.Checkbutton(body, text='Other personal information (Chat PII mode)', variable=self.chat_pii).pack(anchor='w', pady=6)
        ttk.Label(body, text='Unchecked categories may remain visible. Proxy endpoints use the proxy privacy setting.\nAdditional JSON keys are explicit selections; boolean configuration stays intact.').pack(anchor='w', pady=8)
        ttk.Button(body, text='Restore defaults', command=self.restore_categories).pack(side='left')
        ttk.Button(body, text='Done', command=window.destroy).pack(side='right')

    def restore_categories(self):
        for variable in self.categories.values():
            variable.set(True)
        self.chat_pii.set(True)

    def load_settings(self):
        path = filedialog.askopenfilename(filetypes=[("Credential policy", "*.json")])
        if path:
            try:
                self.policy = load_policy(path)
                self.action.set(self.policy.action)
                self.threshold.set(str(self.policy.threshold))
                self.proxy_mode.set(self.policy.proxy_mode)
                for key, variable in self.categories.items():
                    variable.set(key not in self.policy.disabled_categories)
                self.status.set("Credential policy loaded.")
            except DetectionError as exc:
                messagebox.showerror("Invalid policy", str(exc))

    def poll(self):
        try:
            output, status = self.events.get_nowait()
            self.run_button.configure(state="normal")
            if output is None:
                self.status.set("Redaction failed.")
                messagebox.showerror("Redaction failed", status)
            else:
                self.output.configure(state="normal")
                self.output.insert("1.0", output)
                self.output.configure(state="disabled")
                self.status.set(status)
        except queue.Empty:
            pass
        self.root.after(100, self.poll)

    def copy(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.output.get("1.0", "end-1c"))

    def save(self):
        csv_mode = self.mode.get() == 'CSV / TSV columns'
        extension = '.json' if self.mode.get().startswith('JSON') else '.txt'
        if csv_mode:
            try:
                extension = '.tsv' if redact_csv(self.input.get('1.0', 'end-1c'), delimiter=DELIMITERS[self.csv_delimiter.get()]).delimiter == '\t' else '.csv'
            except DetectionError:
                extension = '.csv'
        path = filedialog.asksaveasfilename(defaultextension=extension,
                                          filetypes=[("CSV", "*.csv"), ("TSV", "*.tsv")] if csv_mode else [("JSON", "*.json"), ("Text", "*.txt")])
        if path:
            try:
                if self.workbook is not None and Path(path).resolve() == self.workbook.path:
                    raise DetectionError('Choose a separate CSV/TSV output file. The original workbook is not overwritten.')
                if csv_mode and Path(path).suffix.lower() not in {'.csv', '.tsv', '.txt'}:
                    raise DetectionError('Table output contains cell values. Save it as CSV, TSV, or text.')
                with open(path, "w", encoding="utf-8", newline="") as stream:
                    stream.write(self.output.get("1.0", "end-1c"))
                self.status.set(f"Saved to {path}")
            except OSError:
                messagebox.showerror("Cannot save file", "Could not write the output file.")
            except DetectionError as exc:
                messagebox.showerror('Cannot save file', str(exc))


def main():
    root = create_root()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
