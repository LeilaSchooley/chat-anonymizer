"""Typed settings are configuration; credential strings remain sensitive."""
import json

import pytest

from src.credentials import CredentialEngine, CredentialPolicy
from src.json_redactor import redact_json_result


CASES = [
    '{"profile_identity":{"use_premade_cookies":BOOL},"password":"synthetic-secret"}',
    '{"session_persistence":{"preserve_cookies":BOOL},"password":"synthetic-secret"}',
    '{"campaign":{"use_premade_cookies":BOOL},"password":"synthetic-secret"}',
    '{"tasks":[{"config":{"warmup":{"memory":{"preserve_cookies":BOOL}}}}],"password":"synthetic-secret"}',
]


@pytest.mark.parametrize("source", CASES)
@pytest.mark.parametrize("literal", ["true", "false"])
def test_affected_examples_keep_exact_boolean_and_redact_secrets(source, literal):
    source = source.replace('BOOL', literal)
    result = redact_json_result(source)
    assert result.text == source.replace('"synthetic-secret"', '"[REDACTED]"')
    assert len(result.findings) == 1
    engine = CredentialEngine()
    findings = engine.detect_text(source)
    output = engine.apply_text(source, findings).text
    assert output == source.replace('synthetic-secret', '[REDACTED]')
    assert len(findings) == 1


@pytest.mark.parametrize("label", [
    'profile_identity.use_premade_cookies', 'session_persistence.preserve_cookies',
    'use_premade_cookies', 'tasks.config.warmup.memory.preserve_cookies',
    'cookies', 'session_token', 'password', 'authorization',
])
@pytest.mark.parametrize("literal", ['true', 'false', 'True', 'False'])
def test_config_and_chat_preserve_unquoted_booleans(label, literal):
    source = label + ' = ' + literal + '\r\naccess_token = "synthetic-token"\r\n'
    for mode in ('chat', 'config'):
        engine = CredentialEngine()
        result = engine.apply_text(source, engine.detect_text(source, source=mode))
        assert result.text == source.replace('synthetic-token', '[REDACTED]')


@pytest.mark.parametrize("literal", ['true', 'false'])
def test_booleans_preserved_inside_explicitly_selected_containers(literal):
    source = '{ "credentials": [BOOL, {"cookies": BOOL,"token":"short"}] }'.replace('BOOL', literal)
    result = redact_json_result(source, ['credentials'])
    assert result.text == source.replace('"short"', '"[REDACTED]"')
    assert len(result.findings) == 1


@pytest.mark.parametrize("field", ['use_premade_cookies', 'preserve_cookies', 'cookies', 'session_token', 'authorization'])
@pytest.mark.parametrize("value", ['true', 'false', 'sessionid=synthetic-cookie; HttpOnly', 'Bearer synthetic-token'])
def test_string_credentials_are_not_boolean_exceptions(field, value):
    source = json.dumps({field: value, 'enabled': False})
    result = redact_json_result(source)
    assert json.loads(result.text)[field] == '[REDACTED]'
    assert json.loads(result.text)['enabled'] is False
    engine = CredentialEngine()
    text_result = engine.apply_text(source, engine.detect_text(source))
    assert json.loads(text_result.text)[field] == '[REDACTED]'
    assert json.loads(text_result.text)['enabled'] is False


def test_cookie_jars_remain_inspected_without_hiding_flags():
    source = '{"cookie_jar":[{"name":"session","value":"Bearer synthetic-token","secure":true,"httpOnly":false}],"preserve_cookies":false}'
    result = redact_json_result(source)
    assert result.text == source.replace('Bearer synthetic-token', '[REDACTED]')


@pytest.mark.parametrize('action', ['redact', 'block', 'warn', 'report'])
def test_boolean_only_settings_do_not_trigger_policy_actions(action):
    source = '{"cookies":true,"session_token":false,"password":true}'
    engine = CredentialEngine(CredentialPolicy(action=action))
    result = redact_json_result(source, engine=engine)
    assert result.text == source
    assert not result.findings


def test_database_password_string_spelling_false_remains_sensitive():
    source = 'Server=db;User Id=alice;Password=false;Timeout=30'
    engine = CredentialEngine()
    result = engine.apply_text(source, engine.detect_text(source, source='config'))
    assert result.text == source.replace('Password=false', 'Password=[REDACTED]').replace('alice', '[REDACTED]')


def test_boolean_source_types_and_quoted_literals():
    engine = CredentialEngine()
    assert engine.classify_value(True) == 'configuration-boolean'
    assert engine.classify_value(False) == 'configuration-boolean'
    for value in ('true', 'false', 'Bearer false', 0, 1):
        assert engine.classify_value(value) != 'configuration-boolean'
    for raw in ('"true"', "'false'", '`true`', 'Bearer false', 'false-token'):
        assert engine.classify_literal(raw, source='config') != 'configuration-boolean'


def test_presidio_chat_mode_keeps_boolean_settings():
    from src.anonymizer import ChatAnonymizer
    source = '{"profile_identity":{"use_premade_cookies":true},"session_persistence":{"preserve_cookies":false},"access_token":"synthetic-token"}'
    result = ChatAnonymizer(dedupe_lines=False).anonymize(source)
    assert '"use_premade_cookies":true' in result.text
    assert '"preserve_cookies":false' in result.text
    assert 'synthetic-token' not in result.text
