"""CLI for the chat anonymizer."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from src.anonymizer import ChatAnonymizer
from src.credentials import CredentialEngine, CredentialPolicy, DetectionError, load_policy
from src.json_redactor import redact_json_documents
from dataclasses import replace


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="chat-anonymizer",
        description="Anonymize PII in chat transcripts (Presidio, deterministic).",
    )
    parser.add_argument("input", type=Path, help="Path to the chat transcript")
    parser.add_argument("--format", choices=["auto", "chat", "json", "config"], default="auto",
                        help="Auto uses JSON for .json files; config detects credentials without NLP")
    parser.add_argument("--credential-policy", type=Path, help="Local credential policy JSON")
    parser.add_argument("--credential-action", choices=["redact", "block", "warn", "report"])
    parser.add_argument("--proxy-mode", choices=["standard", "strict"], help="Also hide endpoints in strict mode")
    parser.add_argument("--keys", default="", help="Additional exact JSON field names, comma-separated")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Where to write anonymized text (default: <input>.anon.txt)",
    )
    parser.add_argument(
        "--stdout",
        action="store_true",
        help="Print anonymized text to stdout instead of writing a file",
    )
    parser.add_argument(
        "--map",
        type=Path,
        dest="map_path",
        help="Write replacement map JSON here (gitignored; may contain real PII)",
    )
    parser.add_argument(
        "--load-map",
        type=Path,
        dest="load_map",
        help="Load an existing replacement map before anonymizing",
    )
    parser.add_argument(
        "--include-ticket-ids",
        action="store_true",
        help="Also redact issue-tracker IDs like ABC-123",
    )
    parser.add_argument(
        "--dedupe",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Drop consecutive duplicate lines (default: on; use --no-dedupe to keep them)",
    )
    parser.add_argument(
        "--drop-media-omitted",
        action="store_true",
        help="Drop WhatsApp '<Media omitted>' lines",
    )
    parser.add_argument(
        "--score-threshold",
        type=float,
        default=0.4,
        help="Minimum detection confidence (default: 0.4)",
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Print a JSON summary of entities found to stderr",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return run(args)
    except Exception as exc:
        message = str(exc) if isinstance(exc, DetectionError) else "Processing failed; input is omitted from diagnostics."
        print(f"error: {message}", file=sys.stderr)
        return 1


def run(args) -> int:

    if not args.input.is_file():
        print(f"error: input file not found: {args.input}", file=sys.stderr)
        return 1

    policy = load_policy(args.credential_policy) if args.credential_policy else CredentialPolicy()
    if args.credential_action:
        policy = replace(policy, action=args.credential_action)
    if args.proxy_mode:
        policy = replace(policy, proxy_mode=args.proxy_mode)
    source = ("json" if args.input.suffix.lower() == ".json" else "chat") if args.format == "auto" else args.format
    if source != "chat":
        with args.input.open(encoding="utf-8-sig", newline="") as stream:
            text = stream.read()
        engine = CredentialEngine(policy)
        if source == "json":
            result = redact_json_documents(text, [key.strip() for key in args.keys.split(',') if key.strip()], engine=engine)
        else:
            result = engine.apply_text(text, engine.detect_text(text, source="config"))
        output_text = json.dumps(result.audit(), indent=2) if policy.action == "report" else result.text
        if args.stdout:
            sys.stdout.write(output_text)
        else:
            output = args.output or args.input.with_suffix('.anon.json' if source == "json" else '.anon.txt')
            output.parent.mkdir(parents=True, exist_ok=True)
            with output.open('w', encoding='utf-8', newline='') as stream:
                stream.write(output_text)
            print(f"Wrote processed output to {output}")
        if args.report:
            print(json.dumps(result.audit(), indent=2), file=sys.stderr)
        if policy.action == "warn":
            print("warning: warn-only policy leaves credentials in output", file=sys.stderr)
        return 0

    anonymizer = ChatAnonymizer(
        include_ticket_ids=args.include_ticket_ids,
        score_threshold=args.score_threshold,
        dedupe_lines=args.dedupe,
        drop_media_omitted=args.drop_media_omitted,
        credential_policy=policy,
    )
    if args.load_map:
        anonymizer.load_map(args.load_map)

    result = anonymizer.anonymize_file(args.input)
    if policy.action == "report":
        result.text = json.dumps({"entities": result.entities_found}, indent=2)

    if args.stdout:
        sys.stdout.write(result.text)
        if not result.text.endswith("\n"):
            sys.stdout.write("\n")
    else:
        output = args.output or args.input.with_suffix(args.input.suffix + ".anon.txt")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(result.text, encoding="utf-8")
        print(f"Wrote anonymized chat to {output}")

    if args.map_path:
        anonymizer.save_map(args.map_path)
        print(f"Wrote replacement map to {args.map_path}", file=sys.stderr)

    if args.report:
        summary = {
            "entities_found": len(result.entities_found),
            "unique_replacements": len(result.mapping),
            "entities": result.entities_found,
        }
        print(json.dumps(summary, indent=2), file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
