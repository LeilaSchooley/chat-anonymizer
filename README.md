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

```powershell
# Anonymize a file (writes beside input by default)
uv run python -m src.cli path\to\chat.txt

# Explicit output + save the replacement map locally (gitignored)
uv run python -m src.cli input\chat.txt -o output\chat_anon.txt --map maps\chat_map.json

# Print to stdout
uv run python -m src.cli examples\example_chat.txt --stdout

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
