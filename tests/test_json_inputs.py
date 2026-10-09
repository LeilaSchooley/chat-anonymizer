import json
import pytest

from src.credentials import DetectionError
from src.json_inputs import parse_inputs, format_inputs
from src.json_redactor import redact_json_documents


def test_repair_preserves_strings_types_and_secret_detection():
    source = '''// settings
    {"url":"https://example.test/a,}", "preserve_cookies":false,
     "use_premade_cookies":true, "token":"synthetic", /* comment */
     "nested":[1,null,{"enabled":false,},],}'''
    documents, repaired = parse_inputs(source)
    assert repaired
    formatted = format_inputs(documents)
    result = json.loads(redact_json_documents(formatted).text)
    assert result == {'url':'https://example.test/a,}', 'preserve_cookies':False,
                      'use_premade_cookies':True, 'token':'[REDACTED]',
                      'nested':[1,None,{'enabled':False}]}


def test_combine_keeps_conflicting_keys_and_array_boundaries():
    documents, repaired = parse_inputs('{"id":1}\n[false,{"id":2}]\n{"id":3}')
    assert not repaired
    assert json.loads(format_inputs(documents)) == [{'id':1},[False,{'id':2}],{'id':3}]


@pytest.mark.parametrize('source', ['{"x":1,"x":2}', '{"x":1,"x":2,}',
                                  '{"token":', '{"x":NaN}', '{"x":1e999}',
                                  '', '{"x":"unfinished}', '{"x":undefined}'])
def test_ambiguous_or_lossy_inputs_are_rejected(source):
    with pytest.raises(DetectionError):
        documents, _ = parse_inputs(source)
        format_inputs(documents)


def test_single_document_unicode_and_booleans():
    source = '[true,false,null,42,"日本語"]'
    documents, repaired = parse_inputs(source)
    assert not repaired
    assert json.loads(format_inputs(documents)) == json.loads(source)
