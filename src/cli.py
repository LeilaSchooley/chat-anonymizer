"""CLI for the chat anonymizer."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from src.anonymizer import ChatAnonymizer


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="chat-anonymizer",
        description="Anonymize PII in chat transcripts (Presidio, deterministic).",
    )
    parser.add_argument("input", type=Path, help="Path to the chat transcript")
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

    if not args.input.is_file():
        print(f"error: input file not found: {args.input}", file=sys.stderr)
        return 1

    anonymizer = ChatAnonymizer(
        include_ticket_ids=args.include_ticket_ids,
        score_threshold=args.score_threshold,
        dedupe_lines=args.dedupe,
        drop_media_omitted=args.drop_media_omitted,
    )
    if args.load_map:
        anonymizer.load_map(args.load_map)

    result = anonymizer.anonymize_file(args.input)

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
