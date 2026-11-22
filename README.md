# Chat Anonymizer

Deterministic PII anonymizer for chat transcripts. Built for scrubbing client conversations before sharing them with AI tools or teammates.

**v1 is Presidio-only** — no local LLM. Get detection coverage solid first; add a model layer later for misses.

## Safety

This repo is designed so **real client chats never land in git**:

- Put working files under `input/`, `output/`, or `data/` (all gitignored)
- Only synthetic samples live in `tests/fixtures/` and `examples/`
- Replacement maps (`*_map.json`) are gitignored — they can reverse anonymization

## Setup

```powershell
# once: install uv if needed
# winget install astral-sh.uv

uv sync
uv run python -m spacy download en_core_web_lg
```

Uses Python 3.12 (pinned). No need to activate a venv — prefix commands with `uv run`.

## Usage

### Desktop GUI and Windows executable

Run `uv run python -m src.gui` (or `python gui_launcher.py` for JSON-only
usage without the chat dependencies). Paste input or open a UTF-8 file, choose
a mode, then click **Redact**. Copy or save the output from the window.
Drop multiple files directly into the left input box, or select several with
**Open files**. JSON imports are pretty-printed and combined into one valid JSON
array, with one entry per document in supplied order (a single document keeps its
original root type). Additional drops append entries without flattening arrays or
merging overlapping keys. Comments and trailing commas are repaired automatically;
review the left preview before redacting. **Polish JSON** also formats pasted JSON
or combines pasted JSON documents. Duplicate keys and other invalid syntax are
rejected rather than guessing values. Mixed text/JSON files stack in text/config
mode. A failed import leaves the input intact. Original files are never rewritten.

- **JSON values under keys** detects credential names, formats, and context at
  every nesting level. Selected scalar values become `"[REDACTED]"`. For example,
  `{"api_key":"fake-secret","count":2}` becomes
  `{"api_key":"[REDACTED]","count":2}`.
- **JSON key names** replaces selected field names with stable names such as
  `REDACTED_KEY_1`, leaving their values untouched.
- **Chat PII** uses the existing Presidio detector (requires the English model).
- **Credentials in text / config** uses the shared engine without NLP and leaves
  text outside credential spans intact. It supports labeled prose, logs, code
  snippets, environment variables, and INI-style assignments.
- **CSV / TSV columns** replaces email cells by default, keeping every other
  cell and the row order intact. Open or drop one `.csv` or `.tsv` file, or paste
  a table and select this mode. Opening a table replaces the current input;
  multiple table files must be processed separately to keep their headers aligned.
  Check **First row is a header** if your export has column names; leave it off
  for a headerless export. **Order UUID (column 1)** and **Order ID (column 2)**
  are optional shortcuts for that export layout, not automatic ID detection.
  Use **Other columns** for any other one-based column numbers, such as `3,5`.
  Leave both order checkboxes off to change just email cells. Disable **Email
  cells** to redact only explicitly selected columns.
  Repeated emails use the same `[EMAIL_1]` placeholder within a run; selected
  order fields use placeholders such as `[COLUMN_1_1]`. Empty cells stay empty.
  CSV mode always redacts the selected cells, independently of credential policy
  actions and confidence. It needs no language model. Comma, tab, semicolon, and
  pipe separators are detected automatically; choose one explicitly if your table
  contains several possible separators. Quotes, embedded newlines, original line
  endings, and unselected characters are preserved. Uneven rows or malformed
  quotes produce an error. **Save output** offers CSV/TSV, matching the delimiter.

### File imports

The Windows app supports these input formats through **Open files** and
drag-and-drop:

| Input | Extensions | Import behavior |
| --- | --- | --- |
| Excel workbooks and templates | `.xlsx`, `.xls`, `.xlsm`, `.xlsb`, `.xltx`, `.xltm` | Choose a worksheet; cell values appear as a CSV preview |
| OpenDocument spreadsheets | `.ods` | Choose a worksheet; cell values appear as a CSV preview |
| Delimited tables | `.csv`, `.tsv`, `.tab`, `.psv`, `.ssv` | Email-only and selected-column redaction |
| JSON and JSON Lines | `.json`, `.jsonc`, `.jsonl`, `.ndjson` | JSON documents are validated, repaired where supported, and combined for review |
| Text, logs, configuration, and source snippets | `.txt`, `.text`, `.log`, `.env`, `.env.*`, `.ini`, `.cfg`, `.conf`, `.config`, `.properties`, `.yaml`, `.yml`, `.xml`, `.toml`, `.md`, `.sql`, `.html`, `.htm`, `.css`, `.js`, `.ts`, `.py`, `.sh`, `.bat`, `.ps1` | Text/config mode; select Chat PII for personal information detection |

Open **one table or workbook at a time**. For a workbook, use the **Worksheet**
selector to review and redact each sheet separately, including hidden worksheets.
Only the selected sheet is exported. Leading blank columns and rows are retained
so column numbers match the worksheet. Imports read cell values and cached formula
results; formulas are not recalculated, number/date formatting and styles are not
preserved, and macros are not run. Review the values preview before redacting.
Output is CSV/TSV, not a rewritten workbook. Original workbooks are never modified.
Encrypted workbooks must be decrypted in your spreadsheet app before importing.
Worksheets larger than 2 million cells must be split into smaller tables first.

**Text file encoding** defaults to UTF-8 and detects UTF-8/UTF-16/UTF-32 byte-order
marks. For older Windows exports, choose **Windows-1252** before opening. No
characters are silently replaced when decoding fails. Output is UTF-8.
PDFs, Word documents, images, archives, and other binary formats are not text
imports; export their relevant data to a supported format first.

The command line recognizes tables and workbooks too:

```powershell
# Redact just email cells in a selected worksheet; preserve its header row
uv run python -m src.cli orders.xlsx --sheet Orders --header -o output/orders.csv

# Also redact columns 1 and 2 in a headerless CSV export
uv run python -m src.cli orders.csv --columns 1,2 -o output/orders.csv

# An older Windows text export, with the delimiter explicitly selected
uv run python -m src.cli orders.csv --encoding Windows-1252 --delimiter Semicolon
```

Table mode always redacts its selected cells. Credential action, confidence, and
chat controls apply to their own modes. The CLI uses the first worksheet unless
`--sheet` is supplied; `--no-emails` selects only the explicit `--columns`.

Automatic credential detection is enabled by default in the GUI. It catches
vendor-prefixed fields such as `twocaptcha_apikey`, `stripeApiKey`, `access_token`,
and `client_secret`, regardless of case or separators. Disable the checkbox for
exact matching only. Field names such as `api_key_enabled` or `token_count` are
left alone. Additional exact, case-sensitive field names can be entered separated
by commas. Recognizable token formats, private keys, credential URLs, and labeled
strings are also checked under generic field names. JSON modes
preserve all other characters, including whitespace, number spelling, arrays,
and escapes. Invalid JSON produces an error. JSON redaction needs no NLP model.
Objects and arrays are kept: explicitly selecting a container redacts its scalar
leaves rather than deleting the container. **JSON key names** only renames keys;
use **JSON values under keys** to remove credentials.
Boolean configuration values retain their original `true`/`false` tokens, even
under names such as `preserve_cookies` or `session_token`. Quoted strings and
actual serialized credentials are still inspected normally.

**Redaction settings** lets you select usernames, API keys, tokens, passwords,
cookies, private keys, authorization headers, proxy authentication, and other
secrets. All are enabled by default; **Restore defaults** enables them again.
Usernames are detected in named fields (including nested objects), labeled text,
and connection URLs. Username and password components can be controlled
independently. Harmless boolean settings and username metadata stay intact.
The additional JSON keys box starts empty; category choices control automatic
detection. Explicit field selections still follow category selection when the
field has a known category. Chat PII settings also let you switch other personal
information detection on or off. These GUI choices last for the current session;
a loaded credential policy can set `disabled_categories` for later sessions.
Unchecked categories may remain visible in output. Proxy endpoint privacy remains
controlled by **standard / strict**.

The action and confidence controls apply to credentials. **Report** displays
metadata without secret values; **Block** refuses detected credentials; **Warn**
explicitly leaves credentials in output. Use **Load credential policy** for custom
names, patterns, strategy switches, and exact exceptions. See
[credential architecture and policy reference](docs/credentials.md).
**Proxy privacy: standard** preserves endpoints and redacts authentication.
**Strict** also hides validated endpoints. An address such as `192.0.2.59:6491`
is reported as infrastructure, not invented username/password credentials.

Build the Windows app with `powershell -ExecutionPolicy Bypass -File .\build.ps1`.
The build downloads dependencies and bundles the small English model for offline
chat detection. Launch `dist\ChatAnonymizer\ChatAnonymizer.exe`; distribute the
**entire folder** alongside the executable. Runtime processing is local.

Create a shareable ZIP and SHA256 checksum with `./release.ps1` (or
`./release.ps1 -SkipBuild` after a successful build). Downloads are written to
`dist/ChatAnonymizer-0.1.2-windows-x64.zip` and its `.sha256` file. Extract the
whole ZIP before launching the app; Python is not required on the receiving PC.
The executable is currently unsigned.

The **Windows release** GitHub Actions workflow builds and tests on Windows.
Run it manually for downloadable build artifacts, or push a version tag matching
`pyproject.toml` (currently `v0.1.2`) to publish the ZIP and checksum on GitHub
Releases. Release builds must pass both the packaged self-test and regression tests.

```powershell
# Anonymize a file (writes beside input by default)
uv run python -m src.cli path\to\chat.txt

# Explicit output + save the replacement map locally (gitignored)
uv run python -m src.cli input\chat.txt -o output\chat_anon.txt --map maps\chat_map.json

# Print to stdout
uv run python -m src.cli examples\example_chat.txt --stdout

# JSON is detected automatically from the .json extension
uv run python -m src.cli input\settings.json -o output\settings.anon.json --report

# Credential-only config processing; no language model needed
uv run python -m src.cli input\settings.env --format config --credential-action block

# Include proxy infrastructure in privacy redaction
uv run python -m src.cli input\settings.json --proxy-mode strict

# Tests
uv run pytest
```

Placeholders are **consistent within a run**: the same email always becomes `EMAIL_1`, the same person `PERSON_1`, etc.

## What it detects

**Presidio built-ins:** names, emails, phones, cards, SSN/ITIN/passport/driver license, IPs, IBAN, crypto wallets, locations, URLs, …

**Custom chat recognizers:**

- Slack/Discord `@handles`
- API keys / JWTs / bearer tokens (OpenAI, Stripe, GitHub, Slack, AWS, Google, …)
- **Passwords** (`password: …`, `temp password is …`)
- **Cross-line password lookback** (WhatsApp: if a prior message asks for a password, the next short weird token is treated as one)
- **Bare OTP / 6-digit codes** pasted as their own WhatsApp message (`002793`)
- **Short random passwords** (`ezpd3zzb`, `cssss1`, `:h@2323`, `SnowByrds4545`)
- **AnyDesk / TeamViewer IDs + passwords**
- **Verification / OTP / 2FA codes** (`code: 123456`, `OTP: …`, `enter the code …`)
- **High-entropy random strings** near password/token/reset language
- UUIDs, MAC addresses, street addresses, account/customer IDs
- **Sensitive URLs** (full `https://…`, tracking pixels) — avoids mangling JS fragments
- Sentry / API tokens (`sntrys_…`, GitHub, Stripe, …)
- Broad email matcher (includes `.example` / `.test` TLDs)
- Ticket IDs like `JIRA-1234` (optional: `--include-ticket-ids`)
- Optional `--dedupe` and `--drop-media-omitted` for WhatsApp exports

Tune entity lists in `src/detectors.py`. Default score threshold is `0.4` (override with `--score-threshold`).
Credential confidence defaults to `0.7` and can be changed in a policy. Chat
diagnostics omit original values; reversible maps remain an explicit local export.

## Tests

```powershell
uv run pytest
```

Fixtures are **fake**. Never add real client text to `tests/fixtures/`.

## Layout

```text
chat-anonymizer/
├── README.md
├── requirements.txt
├── .gitignore
├── src/
│   ├── anonymizer.py
│   ├── detectors.py
│   └── cli.py
├── tests/
│   ├── test_anonymizer.py
│   └── fixtures/
└── examples/
    └── example_chat.txt
```

## Roadmap

1. Harden regex + Presidio coverage against your real chat formats
2. Optional second pass with a local LLM for residual PII
3. Package as an installable CLI (`pip install -e .`)

Open files supports multi-selection (Ctrl/Shift in the picker). **Open folder**
imports supported text/config files from that folder in filename order without
traversing subfolders. Dropping a folder uses the same import behavior.

Builds reuse the dependency environment and PyInstaller analysis cache by default.
Use `build.ps1 -Clean` for a full clean rebuild, or `-DistRoot dist/test-build`
for a separate output folder. The standard output is `dist/ChatAnonymizer`;
close that executable before rebuilding it. Build options use data collection instead of explicitly importing every submodule
of the larger packages; their own PyInstaller hooks may still include optional modules. The packaged
self-test still checks native drag-and-drop, folder and multi-file picker imports,
JSON redaction, settings, custom patterns, and offline chat processing.
