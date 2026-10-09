"""Synthetic effectiveness, preservation, privacy, and false-positive cases."""
import json
import random
import string
import time
from dataclasses import replace

import pytest

from src.credentials import (CredentialBlocked, CredentialEngine, CredentialPolicy,
                             CustomPattern, DetectionError, Finding, load_policy,
                             name_category, resolve_findings)
from src.json_redactor import redact_json_result


@pytest.mark.parametrize("name", [
    "twocaptcha_apikey", "brandNewProviderApiKey", "ServiceAPIKey", "APIKEY",
    "provider_api_token", "new-provider-access-token", "clientSecret", "webhookSigningSecret",
    "dbPassword", "passphrase", "PIN", "pwd", "oauthCredentials", "refreshToken",
    "Authorization", "session_token", "cookies", "private_key", "signingKey",
    "AWS_ACCESS_KEY_ID", "auth_tok", "api_k", "client_sec", "dbPass", "sessionId",
])
def test_unfamiliar_names_share_rules_in_json_and_text(name):
    engine = CredentialEngine()
    assert name_category(name)
    source = json.dumps({"items": [{name: "short", "keep": "hello"}]})
    result = redact_json_result(source, engine=engine)
    assert json.loads(result.text)["items"][0][name] == "[REDACTED]"
    text = name + ': "short"'
    findings = engine.detect_text(text)
    assert engine.apply_text(text, findings).text == name + ': "[REDACTED]"'
    assert result.findings[0].category == findings[0].category


@pytest.mark.parametrize("name", ["token_count", "apiKeyEnabled", "passwordHint", "passwordlength",
                                  "session_name", "public_key", "secretary", "monkey", "tokenizer"])
def test_benign_names(name):
    assert name_category(name) is None
    source = json.dumps({name: "plain-value"})
    assert redact_json_result(source).text == source


@pytest.mark.parametrize("value", [
    'ghp_abcdefghijklmnopqrstuvwx', 'sk-proj-abcdefghijklmnopqrstuvwx',
    'Bearer synthetic-short', 'Basic dXNlcjpwYXNz',
    '-----BEGIN PRIVATE KEY-----\nZmFrZQ==\n-----END PRIVATE KEY-----',
])
def test_value_detection_under_generic_fields_and_in_logs(value):
    engine = CredentialEngine()
    text = 'log: ' + value + ' end'
    assert engine.detect_text(text)
    source = json.dumps({"payload": value, "keep": 3})
    result = redact_json_result(source, engine=engine)
    assert value not in json.loads(result.text)["payload"]
    assert json.loads(result.text)["keep"] == 3


@pytest.mark.parametrize("text", [
    'My service token is abc123', 'API key:\n  short', 'export BRAND_API_KEY=short',
    '```\nprovider_api_token = "has spaces"\n```', 'Authorization: Bearer short',
    '{"nested":{"twocaptcha_apikey":"short"}}', 'password: "多行\n秘密"',
])
def test_context_in_prose_config_fragments_and_multiline(text):
    engine = CredentialEngine()
    result = engine.apply_text(text, engine.detect_text(text, source="config"))
    assert result.findings
    assert '[REDACTED]' in result.text


def test_url_and_database_credentials_preserve_surroundings():
    engine = CredentialEngine()
    text = 'postgres://alice:fakepass@db.example/app?ssl=true&access_token=short&count=2'
    result = engine.apply_text(text, engine.detect_text(text))
    assert result.text == 'postgres://[REDACTED]:[REDACTED]@db.example/app?ssl=true&access_token=[REDACTED]&count=2'
    db = 'Server=db;User Id=alice;Password=fakepass;Timeout=30'
    result = engine.apply_text(db, engine.detect_text(db, source="config"))
    assert result.text == 'Server=db;User Id=[REDACTED];Password=[REDACTED];Timeout=30'


def test_validated_jwt_and_invalid_lookalike():
    engine = CredentialEngine()
    token = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlIn0.c3ludGhldGlj'
    assert engine.value_findings(token)
    assert not engine.value_findings('eyJnotjson.notjson.signature')


def test_entropy_requires_context_and_preserves_identifiers():
    engine = CredentialEngine()
    value = 'a8f3K9mX2pQ7vL0s'
    assert not engine.value_findings(value)
    assert engine.value_findings(value, context='reset token')
    for benign in ['deadbeef' * 8, 'abc123', 'alex_support', '2026-10-09', 'querySelector']:
        assert not engine.detect_text('id = ' + benign)


def test_escaped_unicode_tokens_and_exact_source_preservation():
    source = r'{"message":"\ud83d\ude00 API key: sho\u0072t\nkeep","ok":1.00,"text":"\u4f60\u597d"}'
    result = redact_json_result(source)
    assert result.text == source.replace(r'sho\u0072t', '[REDACTED]')
    assert json.loads(result.text)["message"] == '😀 API key: [REDACTED]\nkeep'


def test_sensitive_parent_retains_unrelated_children():
    source = '{"credentials":{"username":"alice","password":"short","enabled":true},"keep":[1,2]}'
    result = redact_json_result(source)
    assert result.text == source.replace('"short"', '"[REDACTED]"').replace('"alice"', '"[REDACTED]"')


def test_credential_arrays_preserve_structure_and_redact_items():
    source = '{"api_keys":["short", "other"], "count":2}'
    result = redact_json_result(source)
    assert result.text == source.replace('"short"', '"[REDACTED]"').replace('"alice"', '"[REDACTED]"').replace('"other"', '"[REDACTED]"')


def test_overlap_union_prevents_partial_redaction():
    findings = [Finding('SECRET', 2, 8, .9, 'one'), Finding('API_KEY', 4, 10, .95, 'two')]
    merged = resolve_findings(findings)
    assert [(finding.start, finding.end) for finding in merged] == [(2, 10)]
    assert CredentialEngine().apply_text('xxabcdefghyy', findings).text == 'xx[REDACTED]yy'


def test_policies_block_warn_report_and_safe_metadata():
    source = '{"token":"synthetic-secret"}'
    with pytest.raises(CredentialBlocked) as error:
        redact_json_result(source, engine=CredentialEngine(CredentialPolicy(action='block')))
    assert 'synthetic-secret' not in str(error.value)
    for action in ['warn', 'report']:
        result = redact_json_result(source, engine=CredentialEngine(CredentialPolicy(action=action)))
        assert result.text == source
        assert 'synthetic-secret' not in repr(result)
        assert 'synthetic-secret' not in json.dumps(result.audit())


def test_threshold_strategies_formats_and_exact_exceptions():
    source = '{"token":"short","password":"short"}'
    engine = CredentialEngine(CredentialPolicy(exceptions=('token',)))
    assert redact_json_result(source, engine=engine).text == source.replace('"password":"short"', '"password":"[REDACTED]"')
    high = CredentialEngine(CredentialPolicy(threshold=.99))
    assert not redact_json_result('{"token":"short"}', engine=high).findings
    with pytest.raises(DetectionError):
        CredentialPolicy(names=False, values=False, context=False)
    with pytest.raises(DetectionError):
        CredentialPolicy(exceptions=('*',))
    with pytest.raises(DetectionError):
        CredentialEngine(CredentialPolicy(formats=('json',))).detect_text('token=short')


def test_independent_strategies_and_text_exception():
    names = CredentialEngine(CredentialPolicy(values=False, context=False))
    assert names.detect_text('twocaptcha_apikey=short')
    context = CredentialEngine(CredentialPolicy(names=False, values=False))
    assert context.detect_text('API key: short')
    values = CredentialEngine(CredentialPolicy(names=False, context=False))
    assert values.detect_text('ghp_abcdefghijklmnopqrstuvwx')
    assert values.detect_text('https://example.test/?token=short')
    exempt = CredentialEngine(CredentialPolicy(exceptions=('demoToken',)))
    assert not exempt.detect_text('demoToken="ghp_abcdefghijklmnopqrstuvwx"')


def test_chat_diagnostics_and_representations_hide_credentials():
    from src.anonymizer import ChatAnonymizer
    result = ChatAnonymizer(dedupe_lines=False).anonymize('twocaptcha_apikey: synthetic-key')
    assert 'synthetic-key' not in json.dumps(result.entities_found)
    assert 'synthetic-key' not in repr(result)
    # Originals are available only through the explicitly retained reversal map.
    assert 'synthetic-key' in result.mapping


def test_custom_rules_reuse_both_adapters():
    policy = CredentialPolicy(custom_names=('companyCredentialBlob',),
                              custom_patterns=(CustomPattern('org', r'ORG-[A-Z]{8}'),))
    engine = CredentialEngine(policy)
    assert engine.detect_text('companyCredentialBlob = short')
    source = '{"payload":"prefix ORG-ABCDEFGH suffix"}'
    assert redact_json_result(source, engine=engine).text == source.replace('ORG-ABCDEFGH', '[REDACTED]')


def test_custom_pattern_backtracking_has_time_limit():
    engine = CredentialEngine(CredentialPolicy(custom_patterns=(CustomPattern('evil', r'(a+)+$'),),
                                               pattern_timeout=.002))
    start = time.monotonic()
    with pytest.raises(DetectionError) as error:
        engine.value_findings('a' * 20000 + '!')
    assert time.monotonic() - start < 1
    assert 'aaaa' not in str(error.value)


@pytest.mark.parametrize("source", ['{"token":"raw-secret",', '{"token":NaN}', '[' * 150 + '0' + ']' * 150])
def test_malformed_or_deep_input_fails_without_content(source):
    with pytest.raises(DetectionError) as error:
        redact_json_result(source)
    assert 'raw-secret' not in str(error.value)


def test_local_policy_loading_and_safe_errors(tmp_path):
    path = tmp_path / 'settings.json'
    path.write_text(json.dumps({'action':'block', 'custom_names':['x']}))
    assert load_policy(path).action == 'block'
    path.write_text('{"secret":"do-not-show",')
    with pytest.raises(DetectionError) as error:
        load_policy(path)
    assert 'do-not-show' not in str(error.value)


def test_generated_provider_names_and_character_preservation():
    randomizer = random.Random(123)
    for _ in range(80):
        provider = ''.join(randomizer.choices(string.ascii_lowercase, k=12))
        source = '{\r\n  "' + provider + 'ApiKey" : "short", "count" : 1.00e+2, "items": [true, null]\r\n}'
        result = redact_json_result(source)
        assert result.text == source.replace('"short"', '"[REDACTED]"').replace('"alice"', '"[REDACTED]"')
        assert json.loads(result.text)['items'] == [True, None]


def test_json_and_presidio_use_same_engine(monkeypatch):
    from src.detectors import SharedCredentialRecognizer
    calls = []
    original = CredentialEngine.classify_name

    def spy(self, name, location=''):
        calls.append(name)
        return original(self, name, location)

    monkeypatch.setattr(CredentialEngine, 'classify_name', spy)
    redact_json_result('{"newVendorApiKey":"short"}')
    assert 'newVendorApiKey' in calls
    calls.clear()
    SharedCredentialRecognizer().analyze('newVendorApiKey=short', ['API_KEY'])
    assert 'newVendorApiKey' in calls


def test_cli_reports_and_failures_omit_secrets(tmp_path, capsys):
    from src.cli import main
    path = tmp_path / 'input.json'
    path.write_text('{"token":"do-not-show"}')
    assert main([str(path), '--stdout', '--credential-action', 'report']) == 0
    output = capsys.readouterr()
    assert 'do-not-show' not in output.out + output.err
    path.write_text('{"token":"do-not-show",')
    assert main([str(path), '--stdout']) == 1
    output = capsys.readouterr()
    assert 'do-not-show' not in output.out + output.err
