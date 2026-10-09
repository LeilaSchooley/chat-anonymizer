"""Synthetic proxy/connection policy tests with preserved surroundings."""
import json

import pytest

from src.connections import parse_connections
from src.credentials import CredentialEngine, CredentialPolicy, DetectionError
from src.json_redactor import redact_json_result


@pytest.mark.parametrize('endpoint', [
    '192.0.2.59:6491', 'proxy.example:8080', 'http://proxy.example:8080',
    'https://192.0.2.59:6491', 'socks4://proxy.example:1080',
    'socks5://[2001:db8::1]:1080', '[2001:db8::1]:6491',
])
def test_endpoints_are_reported_without_inventing_authentication(endpoint):
    engine = CredentialEngine()
    result = engine.apply_text(endpoint, engine.detect_text(endpoint))
    assert result.text == endpoint
    assert result.findings
    assert {finding.category for finding in result.findings} == {'PROXY_ENDPOINT'}
    assert not any(finding.sensitive for finding in result.findings)
    blocking = CredentialEngine(CredentialPolicy(action='block'))
    assert blocking.apply_text(endpoint, blocking.detect_text(endpoint)).text == endpoint


@pytest.mark.parametrize('source,expected', [
    ('alice:fakepass@proxy.example:8080', '[REDACTED]:[REDACTED]@proxy.example:8080'),
    ('proxy.example:8080:alice:fakepass', 'proxy.example:8080:[REDACTED]:[REDACTED]'),
    ('http://alice:fakepass@proxy.example:8080', 'http://[REDACTED]:[REDACTED]@proxy.example:8080'),
    ('socks5://alice:fakepass@[2001:db8::1]:1080', 'socks5://[REDACTED]:[REDACTED]@[2001:db8::1]:1080'),
    ('http://al%69ce:p%40ss@proxy.example:8080', 'http://[REDACTED]:[REDACTED]@proxy.example:8080'),
    ('alice : fakepass @ proxy.example : 8080', '[REDACTED] : [REDACTED] @ proxy.example : 8080'),
    ('proxy.example:8080 : alice : fakepass', 'proxy.example:8080 : [REDACTED] : [REDACTED]'),
])
def test_auth_formats_preserve_scheme_endpoint_and_delimiters(source, expected):
    engine = CredentialEngine()
    result = engine.apply_text(source, engine.detect_text(source))
    assert result.text == expected
    assert any(finding.category == 'PROXY_CONNECTION_SECRET' and finding.sensitive for finding in result.findings)
    assert 'fakepass' not in json.dumps(result.audit())


@pytest.mark.parametrize('mode', ['standard', 'strict'])
def test_identical_policy_for_json_and_chat(mode):
    engine = CredentialEngine(CredentialPolicy(proxy_mode=mode))
    source = '{"proxy_url":"socks5://alice:fakepass@192.0.2.59:1080", "enabled":true,"port":1080,"timeout":null}'
    json_result = redact_json_result(source, engine=engine)
    chat_result = engine.apply_text(source, engine.detect_text(source))
    assert chat_result.text == json_result.text
    assert json.loads(json_result.text)['port'] == 1080
    assert json.loads(json_result.text)['enabled'] is True
    assert json.loads(json_result.text)['timeout'] is None
    if mode == 'standard':
        assert '192.0.2.59:1080' in json_result.text
    else:
        assert '192.0.2.59:1080' not in json_result.text


@pytest.mark.parametrize('prefix', ['proxy', 'brandNewProviderProxy', 'vendor_proxy_auth'])
def test_structured_proxy_objects_and_generic_auth_properties(prefix):
    source = '{"' + prefix + '":{"host":"proxy.example","port":8080,"user":"alice","pass":"fakepass","enabled":false,"retries":2,"unused":null},"username":"benign"}'
    engine = CredentialEngine()
    result = redact_json_result(source, engine=engine)
    expected = source.replace('"alice"', '"[REDACTED]"').replace('"fakepass"', '"[REDACTED]"').replace('"benign"', '"[REDACTED]"')
    assert result.text == expected
    assert engine.apply_text(source, engine.detect_text(source)).text == expected


def test_generic_schema_inferred_from_sibling_fields():
    source = '{"host":"proxy.example","port":8080,"username":"alice","password":"fakepass","enabled":true}'
    result = redact_json_result(source)
    assert result.text == source.replace('"alice"', '"[REDACTED]"').replace('"fakepass"', '"[REDACTED]"').replace('"benign"', '"[REDACTED]"')


def test_endpoint_field_names_do_not_bypass_value_detection():
    source = '{"proxy_host":"http://alice:fakepass@proxy.example:8080","proxy_port":8080}'
    result = redact_json_result(source)
    assert result.text == source.replace('alice', '[REDACTED]').replace('fakepass', '[REDACTED]').replace('benign', '[REDACTED]')


def test_nested_proxy_lists_escaped_values_and_unrelated_fields():
    source = r'{"tasks":[{"config":{"proxies":[{"host":"proxy.example","port":8080,"username":"al\u0069ce","password":"f\"ake"},"http:\/\/alice:fakepass@proxy.example:8080"]}}],"preserve_cookies":true,"count":1.00}'
    result = redact_json_result(source)
    data = json.loads(result.text)
    assert data['tasks'][0]['config']['proxies'][0]['username'] == '[REDACTED]'
    assert data['tasks'][0]['config']['proxies'][0]['password'] == '[REDACTED]'
    assert data['tasks'][0]['config']['proxies'][1] == 'http://[REDACTED]:[REDACTED]@proxy.example:8080'
    assert r'"count":1.00' in result.text
    assert data['preserve_cookies'] is True


def test_strict_privacy_redacts_string_endpoints_preserving_numbers():
    engine = CredentialEngine(CredentialPolicy(proxy_mode='strict'))
    source = '{"proxy":{"host":"proxy.example","port":8080,"enabled":false,"auth":null}}'
    result = redact_json_result(source, engine=engine)
    assert result.text == source.replace('"proxy.example"', '"[REDACTED]"')
    assert engine.apply_text(source, engine.detect_text(source)).text == result.text


def test_environment_variables_and_ini_proxy_section():
    engine = CredentialEngine()
    source = 'HTTP_PROXY=http://alice:fakepass@proxy.example:8080\r\nPROXY_USER=alice\r\nPROXY_PORT=8080\r\n'
    result = engine.apply_text(source, engine.detect_text(source, source='config'))
    assert result.text == source.replace('alice', '[REDACTED]').replace('fakepass', '[REDACTED]').replace('benign', '[REDACTED]')
    source = '[proxy]\nusername=alice\npassword=fakepass\nhost=proxy.example\nport=8080\nenabled=true\n[other]\nusername=benign\n'
    result = engine.apply_text(source, engine.detect_text(source, source='config'))
    assert result.text == source.replace('alice', '[REDACTED]').replace('fakepass', '[REDACTED]').replace('benign', '[REDACTED]')


def test_custom_provider_context_without_handler_changes():
    engine = CredentialEngine(CredentialPolicy(proxy_fields=('routingPool',)))
    source = '{"routingPool":[{"user":"alice","auth":"opaque-value","active":true}]}'
    result = redact_json_result(source, engine=engine)
    assert result.text == source.replace('"alice"', '"[REDACTED]"').replace('"opaque-value"', '"[REDACTED]"')


@pytest.mark.parametrize('source', ['192.0.2.59', '8080', '12:30:15', 'retry:3',
                                   '256.1.1.1:8080', 'proxy.example:65536', 'proxy.example:0',
                                   '[2001:::db8]:8080', 'name:password', 'version:1.2'])
def test_invalid_or_benign_endpoints_are_not_connections(source):
    assert not parse_connections(source)


def test_proxy_booleans_numbers_and_nulls_are_not_auth_secrets():
    source = '{"proxy_user":false,"proxy_password":true,"proxy_auth":null,"proxy_port":8080,"proxy_host":null}'
    engine = CredentialEngine()
    assert redact_json_result(source).text == source
    assert engine.apply_text(source, engine.detect_text(source)).text == source


def test_malformed_input_fails_without_credentials_in_message():
    with pytest.raises(DetectionError) as error:
        redact_json_result('{"proxy_url":"alice:fakepass@proxy.example:8080",')
    assert 'fakepass' not in str(error.value)


def test_chat_pii_respects_connection_policy_without_mangling_urls():
    from src.anonymizer import ChatAnonymizer
    source = 'socks5://alice:fakepass@192.0.2.59:1080'
    result = ChatAnonymizer(dedupe_lines=False).anonymize(source)
    assert 'socks5://' in result.text
    assert '192.0.2.59:1080' in result.text
    assert 'alice' not in result.text and 'fakepass' not in result.text
