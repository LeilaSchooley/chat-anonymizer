# Credential detection and policy

`src/credentials.py` owns the name, value, and context strategies, overlap
resolution, safe findings, and action policy. `src/json_redactor.py` extracts
lossless JSON candidates and maps decoded string offsets back to original tokens.
`SharedCredentialRecognizer` in `src/detectors.py` adapts the same engine to
Presidio. `src/whatsapp.py` supplies message boundaries and keeps existing
verification-code and remote-ID behavior; password decisions live in the engine.
The GUI and CLI select adapters and apply policies without provider-specific rules.
`src/connections.py` validates hosts and ports and extracts authentication source
spans; the engine assigns proxy endpoint/connection-secret categories and policies.
`src/file_inputs.py` reads multi-file batches atomically. The GUI uses the native
TkDND extension for drops, and the JSON adapter supports whitespace-separated
documents with correct batch source offsets.

Names are split across case and separators, then examined for credential concepts
and abbreviations. Compound names accept unfamiliar provider prefixes. Metadata
suffixes such as `count`, `enabled`, and `hint` suppress name-based findings.
Known token formats, validated JWT structure, PEM private-key blocks, bearer/basic
authentication, URL passwords/query parameters, and database password assignments
provide independent value signals. Context handles quoted and unquoted assignments,
natural-language `is` labels, newline-separated values, and nearby credential
labels. Entropy is only a secondary signal when credential context is present.
The existing short standalone WhatsApp password heuristic is retained and can
still classify short ordinary IDs as passwords in that specific format.

## Policy

Use `CredentialPolicy`/`CredentialEngine` from Python, load local JSON through the
GUI, or pass `--credential-policy path` to the CLI. Example settings:

```json
{
  "names": true,
  "values": true,
  "context": true,
  "threshold": 0.7,
  "action": "redact",
  "replacement": "[REDACTED]",
  "formats": ["json", "chat", "config"],
  "custom_names": ["internalCredentialBlob"],
  "exceptions": ["publicExampleToken"],
  "custom_patterns": [
    {"name": "internal-format", "expression": "ORG-[A-Z]{8}", "category": "SECRET", "confidence": 0.95}
  ],
  "pattern_timeout": 0.025
}
```

Proxy settings are `"connections": true`, `"proxy_mode": "standard"` or `"strict"`,
and `"proxy_fields": ["routingPool"]` for custom provider-specific parent fields.
These can be added to the same policy object. The GUI exposes a proxy privacy
selector and the CLI accepts `--proxy-mode standard|strict`.

Standard mode classifies endpoints as `PROXY_ENDPOINT` with `sensitive: false`;
they appear in audits but are preserved and do not trigger blocking. Actual
usernames/passwords/auth fields become `PROXY_CONNECTION_SECRET`. Strict mode
marks validated endpoints sensitive as infrastructure and hides them too. Reports
include `sensitive_count` separately from the total number of findings. Authentication
in URLs and colon-delimited connections is replaced by spans, preserving schemes,
hosts/ports in standard mode, and delimiters. Separate proxy object fields are
inspected without replacing the object. Booleans, numeric ports/timeouts, and nulls
are preserved automatically; explicit scalar selections retain their existing
behavior except for protected booleans.

Supported connection forms include IPv4/hostname `host:port`, bracketed IPv6
`[address]:port`, `username:password@host:port`, `host:port:username:password`,
and HTTP/HTTPS/SOCKS4/SOCKS5 URLs with explicit ports. Percent-encoded userinfo is
redacted as supplied; it does not need to be decoded or logged. Object/list context,
compound proxy field names, generic sibling host/port/auth schemas, and INI proxy
sections supply contextual evidence. The same JSON adapter inspects objects in
chat/config text. Chat PII's generic IP/URL recognizers defer to the shared proxy
policy for identified connection regions; other PII recognition remains active.

Defaults enable all three strategies. Disabling all of them is rejected. Thresholds
range from 0 to 1. Custom patterns use the `regex` package with a timeout (maximum
one second per search) and a length cap; a compilation error or timeout rejects the
operation without exposing input. Patterns match their complete span, not a capture
group. Exact field exceptions are case-sensitive. JSON also supports positional
paths such as `/0/1`, meaning the second child of the first root child. Paths use
positions rather than actual key names so audit metadata cannot expose a secret
stored as an object key. Exceptions suppress inspection of that JSON subtree.
Avoid excluding large containers. Unsupported formats and wildcard exceptions
are rejected.

Typed-value classification runs before name-based secret decisions. Genuine JSON
boolean primitives and unquoted boolean literals in supported chat/config
assignments are preserved, including explicit key selections and selected
containers. This covers nested flags such as `profile_identity.use_premade_cookies`,
`session_persistence.preserve_cookies`, campaign `use_premade_cookies`, and
`tasks[].config.warmup.memory.preserve_cookies` without field-specific exceptions.
Quoted `"true"`/`"false"` values remain strings and are inspected normally.
Serialized cookies, tokens, and credential-bearing structures continue to be
inspected. A database connection string's password is a string credential, even
if it happens to spell `false`; its connection-string context takes precedence
over the bare-literal inference used for ordinary configuration assignments.

Actions:

- `redact`: replaces detected source spans.
- `block`: raises a content-free error before output is saved.
- `warn`: returns source data with metadata; the GUI/CLI explicitly says that
  credentials remain. Other PII may still be anonymized in Chat PII mode.
- `report`: returns metadata; GUI/CLI output contains only findings. Python
  callers get unchanged input in `DetectionResult.text` and should use `audit()`
  for diagnostic output.

The exact-key JSON compatibility wrapper defaults to explicit selection. The
GUI, CLI, and `redact_json_result` default to automatic shared detection. Explicit
selection takes priority over confidence and redacts all scalar leaves of a
selected container except boolean configuration primitives. Automatic detection
preserves unrelated container members.
Renaming JSON keys intentionally preserves their values and is a separate mode.

## Preservation and privacy

JSON is validated but never reconstructed. Duplicate keys, number spelling,
whitespace, CRLF, Unicode escapes, surrogate pairs, and array order are retained.
Only detected scalar tokens or string character spans change. JSON depth is
limited to 128; malformed/deeper input fails with a generic error. Overlapping
credential spans are merged so a lower-priority tail cannot leak. Text/config
mode preserves surrounding characters. Chat PII keeps existing PII detection and
optional deduplication/media cleanup in addition to credential detection.

Findings contain category, confidence, strategy, format, and original source
offsets; JSON locations are positional paths. They have no original value.
`audit()` and CLI `--report` omit secrets. Exceptions do not echo input.
Result representations hide source text and reversible maps. Explicit replacement
maps contain originals and remain sensitive local artifacts, never diagnostics.
Detection runs locally and does not call a classification service.

## Coverage and limits

The tests separately exercise positive detections, benign cases, exact source
preservation, cross-adapter consistency, overlap boundaries, privacy, invalid
inputs, and adversarial custom regexes. A seeded generator varies unfamiliar
provider prefixes without adding handler rules. These are synthetic regression
cases, not estimates of accuracy on arbitrary real data.

Arbitrary strings with no meaningful label, recognizable format, or context
cannot reliably be identified. Base64 alone, hashes, and generic IDs are not
credentials by default. Recognized vendor patterns and abbreviation concepts
need maintenance. Text/config is an assignment adapter, not a complete parser for
every YAML/TOML/SQL language; complex concatenation, interpolations, encoded URLs,
or broken/partial key blocks may require custom rules. Token structure validation
does not verify token validity or cryptographic signatures. Unrecognized metadata
names can produce false positives. Custom exceptions can introduce false negatives.
JSON field-name matching does not redact sensitive data embedded in an unrelated
key name; the separate key-name mode is available for known fields.

Connection parsing requires valid ports (1–65535), valid IPs or DNS host syntax,
and brackets for IPv6. Single-label hosts require URL, authentication, or explicit
proxy context to avoid interpreting settings such as `retry:3` as endpoints.
Standard mode deliberately preserves ordinary network endpoints. Strict mode
also hides matching endpoints that may be ordinary network configuration; select
it when infrastructure privacy is desired. URLs with omitted ports, whole-URL
percent encoding, unusual delimiter/escaping conventions, and complex YAML/TOML
schemas may need custom rules. Embedded JSON inspection tries up to 128 candidate
openings; malformed or more complicated text still uses the text strategies.
Unknown/ambiguous usernames outside established connection context remain
unclassified. These are tested format guarantees, not universal secret coverage.

Native drag-and-drop binding and five-file callbacks are exercised with synthetic
files, including spaces in filenames. GUI JSON imports are validated atomically, conservatively cleaned, and
combined into one pretty-printed JSON array without merging overlapping keys.
The underlying lossless adapter and CLI also accept JSON document streams. There is no automatic execution or upload of dropped files.

## Category selection

All sensitive categories are enabled by default. `disabled_categories` accepts
an array containing any of `USERNAME`, `API_KEY`, `TOKEN`, `PASSWORD`, `COOKIE`,
`PRIVATE_KEY`, `AUTHORIZATION`, `PROXY_CONNECTION_SECRET`, and `SECRET`.
For example, `{"disabled_categories":["USERNAME"]}` preserves detected usernames
while keeping password and token redaction enabled. GUI Redaction settings
updates this shared policy for JSON, config, and chat. Category filtering occurs
before overlapping detections are resolved. Proxy endpoints still follow the
separate standard/strict policy. Other personal information has a separate
Chat PII switch in the GUI. GUI choices reset on restart; load a policy file to
reuse credential category selections.
