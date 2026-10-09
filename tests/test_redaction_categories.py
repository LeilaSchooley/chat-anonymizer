import json
import pytest

from src.credentials import CredentialEngine, CredentialPolicy, REDACTION_CATEGORIES, load_policy
from src.json_redactor import redact_json_result
from src.anonymizer import ChatAnonymizer


SAMPLES = {'USERNAME': ('username','alice'), 'API_KEY': ('twocaptcha_apikey','synthetic'),
           'TOKEN': ('session_token','synthetic'), 'PASSWORD': ('password','synthetic'),
           'COOKIE': ('cookies','sid=synthetic'), 'PRIVATE_KEY': ('private_key','synthetic'),
           'AUTHORIZATION': ('authorization','Bearer synthetic'), 'SECRET': ('secret','synthetic'),
           'PROXY_CONNECTION_SECRET': ('proxy_password','synthetic')}


@pytest.mark.parametrize('category', SAMPLES)
def test_each_category_default_and_selective_json_and_text(category):
    key, value = SAMPLES[category]
    source = json.dumps({key:value, 'enabled':False, 'count':2})
    assert json.loads(redact_json_result(source).text)[key] == '[REDACTED]'
    engine = CredentialEngine(CredentialPolicy(disabled_categories=(category,)))
    assert redact_json_result(source, engine=engine).text == source
    text = f'{key}="{value}"'
    assert engine.apply_text(text, engine.detect_text(text)).text == text
    default = CredentialEngine()
    assert value not in default.apply_text(text, default.detect_text(text)).text


def test_username_disabled_keeps_nested_username_but_redacts_password():
    source = '{"credentials":{"username":"alice","password":"synthetic","use_premade_cookies":true}}'
    engine = CredentialEngine(CredentialPolicy(disabled_categories=('USERNAME',)))
    assert json.loads(redact_json_result(source, engine=engine).text)['credentials'] == {
        'username':'alice','password':'[REDACTED]','use_premade_cookies':True}


@pytest.mark.parametrize('source', ['postgres://alice:synthetic@db.example/app',
                                  'http://alice:synthetic@proxy.example:8080',
                                  'proxy.example:8080:alice:synthetic'])
def test_connection_username_can_be_preserved_independently(source):
    engine = CredentialEngine(CredentialPolicy(disabled_categories=('USERNAME',)))
    result = engine.apply_text(source, engine.detect_text(source))
    assert 'alice' in result.text
    assert 'synthetic' not in result.text


def test_chat_uses_shared_username_selection():
    assert 'alice' not in ChatAnonymizer().anonymize('username: alice').text
    assert ChatAnonymizer(entities=['USERNAME'], credential_policy=CredentialPolicy(
        disabled_categories=('USERNAME',))).anonymize('username: alice').text == 'username: alice'


def test_policy_can_disable_all_and_load_categories(tmp_path):
    categories = tuple(key for key, _ in REDACTION_CATEGORIES)
    path = tmp_path / 'policy.json'
    path.write_text(json.dumps({'disabled_categories':categories}))
    engine = CredentialEngine(load_policy(path))
    source = '{"username":"alice","password":"synthetic","token":"synthetic"}'
    assert redact_json_result(source, engine=engine).text == source


def test_username_metadata_and_booleans_stay_intact():
    source = '{"username_enabled":true,"username_count":2,"login":false,"keep":"hello"}'
    assert redact_json_result(source).text == source
