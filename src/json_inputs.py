"""Conservative JSON cleanup for editable import previews, never secret detection."""
import json
import re

from src.credentials import DetectionError


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate key')
        result[key] = value
    return result


def _constant(value):
    raise ValueError('Nonfinite number')


def parse_inputs(text):
    """Accept JSON streams; safely remove comments and trailing commas if needed."""
    decoder = json.JSONDecoder(object_pairs_hook=_pairs, parse_constant=_constant)

    def decode(source):
        documents = []
        position = 0
        while position < len(source):
            while position < len(source) and source[position].isspace():
                position += 1
            if position == len(source):
                break
            value, position = decoder.raw_decode(source, position)
            documents.append(value)
        if not documents:
            raise ValueError('Empty input')
        return documents

    try:
        return decode(text), False
    except (ValueError, RecursionError):
        pass
    # Recognize quoted strings first so URL slashes and commas inside values survive.
    token = re.compile(r'"(?:[^"\\]|\\.)*"|//[^\r\n]*|/\*[\s\S]*?\*/|,\s*(?=[}\]])')
    cleaned = token.sub(lambda m: m.group() if m.group().startswith('"') else ' ', text)
    # Comments can sit between a trailing comma and a closing delimiter.
    cleaned = token.sub(lambda m: m.group() if m.group().startswith('"') else ' ', cleaned)
    try:
        return decode(cleaned), True
    except (ValueError, RecursionError):
        raise DetectionError('JSON could not be safely formatted. Check syntax and duplicate keys; input was left unchanged.') from None


def format_inputs(documents):
    value = documents[0] if len(documents) == 1 else documents
    try:
        return json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False)
    except (ValueError, RecursionError):
        raise DetectionError('JSON could not be safely formatted. Input was left unchanged.') from None
