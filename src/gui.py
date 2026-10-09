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
from src.file_inputs import read_file_batch, read_json_batch
from src.json_inputs import parse_inputs, format_inputs


def create_root():
    try:
        from tkinterdnd2 import TkinterDnD
        return TkinterDnD.Tk()
    except ImportError:
        return tk.Tk()


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
        self.status = tk.StringVar(value="Paste text, open files, or drop files into the input box. Processing stays local.")
        toolbar = ttk.Frame(root, padding=10)
        toolbar.pack(fill="x")
        ttk.Button(toolbar, text="Open files", command=self.open_file).pack(side="left")
        ttk.Button(toolbar, text="Polish JSON", command=self.polish_json).pack(side="left", padx=5)
        ttk.Combobox(toolbar, textvariable=self.mode, state="readonly", width=28,
                     values=["JSON values under keys", "JSON key names", "Credentials in text / config", "Chat PII"]).pack(side="left", padx=10)
        self.run_button = ttk.Button(toolbar, text="Redact", command=self.redact)
        self.run_button.pack(side="left")
        ttk.Button(toolbar, text="Copy output", command=self.copy).pack(side="right")
        ttk.Button(toolbar, text="Save output", command=self.save).pack(side="right", padx=10)
        options = ttk.Frame(root, padding=(10, 0, 10, 10))
        options.pack(fill="x")
        ttk.Label(options, text="JSON keys (comma-separated, case-sensitive):").pack(side="left")
        ttk.Entry(options, textvariable=self.keys).pack(side="left", fill="x", expand=True, padx=10)
        ttk.Checkbutton(root, text="Automatically detect credentials in JSON (names, values, and context)",
                        variable=self.auto_sensitive).pack(anchor="w", padx=10)
        settings = ttk.Frame(root, padding=10)
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
        panels.pack(fill="both", expand=True, padx=10)
        self.input = self.panel(panels, "Input — paste text / JSON or drop files here")
        self.output = self.panel(panels, "Redacted output")
        self.output.configure(state="disabled")
        if hasattr(self.input, 'drop_target_register') and hasattr(root, 'TkdndVersion'):
            from tkinterdnd2 import DND_FILES
            self.input.drop_target_register(DND_FILES)
            self.input.dnd_bind('<<Drop>>', self.drop_files)
        ttk.Label(root, textvariable=self.status, padding=10).pack(fill="x")
        root.after(100, self.poll)

    def panel(self, parent, label):
        frame = ttk.Frame(parent)
        ttk.Label(frame, text=label).pack(anchor="w", pady=5)
        widget = scrolledtext.ScrolledText(frame, wrap="word", undo=True, font=("Consolas", 11))
        widget.pack(fill="both", expand=True)
        parent.add(frame, weight=1)
        return widget

    def open_file(self):
        paths = filedialog.askopenfilenames(filetypes=[("Text / JSON", "*.txt *.json"), ("All files", "*.*")])
        if paths:
            self.add_files(list(paths))

    def drop_files(self, event):
        try:
            paths = list(self.root.tk.splitlist(event.data))
            return 'copy' if self.add_files(paths) else 'none'
        except tk.TclError:
            messagebox.showerror("Cannot drop files", "The dropped file list could not be read.")
            return 'none'

    def add_files(self, paths):
        try:
            content, all_json = read_file_batch(paths)
            current = self.input.get('1.0', 'end-1c')
            json_mode = all_json and (not current or self.mode.get().startswith('JSON'))
            repaired = False
            if json_mode:
                documents, repaired = read_json_batch(paths)
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
        if json_mode:
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
        else:
            self.mode.set('Credentials in text / config')
        detail = 'combined and pretty-printed' if json_mode else 'stacked in input order'
        repair = ' Comments / trailing commas repaired; review the input.' if repaired else ''
        self.status.set(f"Added {len(paths)} file(s), {detail}.{repair} You can edit before redacting.")
        return True

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
        try:
            policy = replace(self.policy, action=self.action.get(), threshold=float(self.threshold.get()),
                             proxy_mode=self.proxy_mode.get(),
                             disabled_categories=tuple(key for key, variable in self.categories.items() if not variable.get()))
            engine = CredentialEngine(policy)
        except Exception:
            messagebox.showerror("Invalid settings", "Check the confidence threshold and credential policy.")
            return
        self.output.configure(state="normal")
        self.output.delete("1.0", "end")
        self.output.configure(state="disabled")
        self.run_button.configure(state="disabled")
        self.status.set("Processing…")

        def work():
            try:
                if mode == "Chat PII":
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
        path = filedialog.asksaveasfilename(defaultextension=".json" if self.mode.get().startswith("JSON") else ".txt",
                                          filetypes=[("JSON", "*.json"), ("Text", "*.txt")])
        if path:
            try:
                with open(path, "w", encoding="utf-8", newline="") as stream:
                    stream.write(self.output.get("1.0", "end-1c"))
                self.status.set(f"Saved to {path}")
            except OSError:
                messagebox.showerror("Cannot save file", "Could not write the output file.")


def main():
    root = create_root()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
