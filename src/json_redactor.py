"""Lossless JSON adapter for the shared credential engine."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, replace

from src.credentials import (CredentialBlocked, CredentialEngine, DetectionError,
                             DetectionResult, Finding, name_category, resolve_findings)

TOKENS = re.compile(r'"(?:[^"\\]|\\.)*"|[{}\[\]:,]|[^\s{}\[\]:,]+')


@dataclass
class Node:
    start: int
    end: int
    kind: str
    children: list[tuple[str | int, "Node", tuple[int, int] | None]] = field(default_factory=list)


def parse_source(text: str) -> Node:
    """Validate first; retain source tokens, including duplicate object fields."""
    try:
        def invalid_constant(value):
            raise ValueError()
        json.loads(text, parse_constant=invalid_constant)
        tokens = list(TOKENS.finditer(text))
        position = 0

        def parse(depth=0):
            nonlocal position
            if depth > 128:
                raise ValueError()
            token = tokens[position]
            position += 1
            if token.group() not in ('{', '['):
                return Node(token.start(), token.end(), "string" if token.group().startswith('"') else "scalar")
            opening = token.group()
            node = Node(token.start(), token.end(), "object" if opening == '{' else "array")
            closing = '}' if opening == '{' else ']'
            while tokens[position].group() != closing:
                key_span = None
                if opening == '{':
                    key_token = tokens[position]
                    key = json.loads(key_token.group())
                    key_span = key_token.span()
                    position += 2
                else:
                    key = len(node.children)
                node.children.append((key, parse(depth + 1), key_span))
                if tokens[position].group() == ',':
                    position += 1
            node.end = tokens[position].end()
            position += 1
            return node
        return parse()
    except (ValueError, IndexError, RecursionError, TypeError):
        raise DetectionError("Invalid JSON or nesting exceeds the supported limit (128 levels).") from None


def decoded_string_spans(raw: str) -> tuple[str, list[tuple[int, int]]]:
    """Map decoded code points to the original quoted JSON source spans."""
    spans, pieces = [], []
    index = 1
    while index < len(raw) - 1:
        start = index
        if raw[index] == '\\':
            index += 6 if raw[index + 1] == 'u' else 2
            if raw[start:start + 2] == '\\u' and 0xD800 <= int(raw[start + 2:start + 6], 16) <= 0xDBFF:
                if raw[index:index + 2] == '\\u' and 0xDC00 <= int(raw[index + 2:index + 6], 16) <= 0xDFFF:
                    index += 6
            decoded = json.loads('"' + raw[start:index] + '"')
        else:
            index += 1
            decoded = raw[start:index]
        pieces.append(decoded)
        spans.extend((start, index) for _ in decoded)
    return ''.join(pieces), spans


def is_sensitive_key(key: str) -> bool:
    """Compatibility export; semantic name rules belong to the engine."""
    return name_category(key) is not None


def redact_json_result(text: str, keys: list[str] | None = None, *, key_names: bool = False,
                       auto_sensitive: bool = True,
                       engine: CredentialEngine | None = None) -> DetectionResult:
    engine = engine or CredentialEngine()
    engine.require_format("json")
    root = parse_source(text)
    selected = set(keys or [])
    if not selected and not auto_sensitive:
        raise DetectionError("Enter at least one JSON key, or enable automatic credential detection.")
    findings, edits, replacements = [], [], {}
    tokens = list(TOKENS.finditer(text))
    existing = {json.loads(token.group()) for index, token in enumerate(tokens[:-1])
                if token.group().startswith('"') and tokens[index + 1].group() == ':'} if key_names else set()

    def visit(node, path="", label="", forced=False, context=""):
        # Audit paths use positions and cannot reveal secret object keys.
        if node.kind in {"object", "array"}:
            if auto_sensitive and node.kind == "object":
                context = engine.object_context([str(key) for key, _, _ in node.children], context)
            for ordinal, (key, child, key_span) in enumerate(node.children):
                name = str(key) if key_span else ""
                location = path + '/' + str(ordinal)
                if engine.excluded(name, location):
                    continue
                category = engine.classify_name(name, location) if auto_sensitive else None
                chosen = name in selected
                if key_names and key_span and (chosen or category) and (category or 'SECRET') not in engine.policy.disabled_categories:
                    if name not in replacements:
                        replacement = f"REDACTED_KEY_{len(replacements) + 1}"
                        while replacement in existing:
                            replacement += "_"
                        existing.add(replacement)
                        replacements[name] = replacement
                    edits.append((*key_span, json.dumps(replacements[name])))
                    findings.append(Finding(category or "SECRET", *key_span, 0.99, "field-name", "json", location))
                visit(child, location, name, forced or chosen,
                      name if category or engine.proxy_context(name) else context)
            return
        if key_names:
            return
        if node.kind == "scalar":
            if engine.classify_value(json.loads(text[node.start:node.end])) == "configuration-boolean" or not forced:
                return
        decoded = json.loads(text[node.start:node.end])
        if auto_sensitive and not forced:
            proxy_field = engine.proxy_field_finding(label, decoded, node.start, node.end,
                                                     context=context, location=path)
            if proxy_field:
                if proxy_field.confidence >= engine.policy.threshold:
                    findings.append(proxy_field)
                if proxy_field.sensitive:
                    return
        category = engine.classify_name(label or context, path) if auto_sensitive else None
        if forced or (category and engine.policy.threshold <= 0.95):
            findings.append(Finding(category or "SECRET", node.start, node.end, 0.99 if forced else 0.95,
                                    "explicit-field" if forced else "field-name", "json", path))
            return
        if node.kind == "string" and auto_sensitive:
            decoded, spans = decoded_string_spans(text[node.start:node.end])
            for finding in engine.value_findings(decoded, context=context, source="json", location=path):
                findings.append(replace(finding, start=node.start + spans[finding.start][0],
                                        end=node.start + spans[finding.end - 1][1]))

    visit(root)
    findings = resolve_findings(engine.filter_categories(findings))
    if any(finding.sensitive for finding in findings) and engine.policy.action == "block":
        raise CredentialBlocked("Input blocked: credentials were detected.")
    if engine.policy.action == "redact":
        if not key_names:
            for finding in findings:
                if not finding.sensitive:
                    continue
                replacement = json.dumps(engine.policy.replacement, ensure_ascii=False)
                if finding.strategy not in {"field-name", "explicit-field", "proxy-field"}:
                    replacement = replacement[1:-1]
                edits.append((finding.start, finding.end, replacement))
        for start, end, replacement in sorted(edits, reverse=True):
            text = text[:start] + replacement + text[end:]
    return DetectionResult(text, tuple(findings), engine.policy.action)


def redact_json(text: str, keys: list[str], *, key_names: bool = False,
                auto_sensitive: bool = False) -> tuple[str, int]:
    """Compatibility wrapper; GUI uses the full policy-aware result API."""
    result = redact_json_result(text, keys, key_names=key_names, auto_sensitive=auto_sensitive)
    return result.text, len(result.findings)


def redact_json_documents(text: str, keys: list[str] | None = None, **kwargs) -> DetectionResult:
    """Process stacked JSON documents while preserving separators and offsets."""
    decoder = json.JSONDecoder()
    cursor = 0
    documents = []
    try:
        while cursor < len(text):
            while cursor < len(text) and text[cursor].isspace():
                cursor += 1
            if cursor == len(text):
                break
            _, end = decoder.raw_decode(text, cursor)
            documents.append((cursor, end))
            cursor = end
        if not documents:
            raise ValueError()
    except (ValueError, RecursionError):
        raise DetectionError("Invalid stacked JSON input. Each input must be a complete JSON document.") from None
    # Validate and inspect the entire batch before assembling any output.
    results = [(start, end, redact_json_result(text[start:end], keys, **kwargs))
               for start, end in documents]
    findings = tuple(replace(finding, start=start + finding.start, end=start + finding.end,
                             location=f"document/{index}" + finding.location)
                     for index, (start, _, result) in enumerate(results) for finding in result.findings)
    output = text
    for start, end, result in reversed(results):
        output = output[:start] + result.text + output[end:]
    return DetectionResult(output, findings, results[0][2].action)
