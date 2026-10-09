import json
import pytest
from src.json_redactor import redact_json


def test_values_preserve_every_other_character():
    source = '{\r\n  "api_key" : "fake-secret", "amount": 1.00e+2, "items": [{"api_key": 42}], "ok": true\r\n}'
    output, count = redact_json(source, ["api_key"])
    assert output == source.replace('"fake-secret"', '"[REDACTED]"').replace(': 42', ': "[REDACTED]"')
    assert count == 2
    assert json.loads(output)["ok"] is True


@pytest.mark.parametrize("value", ['null', '123'])
def test_whole_selected_value(value):
    output, count = redact_json('{"token":' + value + ',"keep":"token"}', ["token"])
    assert output == '{"token":"[REDACTED]","keep":"token"}'
    assert count == 1


def test_selected_container_preserves_structure():
    source = '{"token":[1,{"token":"nested"}],"keep":"token"}'
    output, count = redact_json(source, ["token"])
    assert output == '{"token":["[REDACTED]",{"token":"[REDACTED]"}],"keep":"token"}'
    assert count == 2


def test_names_preserve_values_and_avoid_collisions():
    source = '{"token":"secret", "REDACTED_KEY_1":1, "items":[{"token":true}]}'
    output, count = redact_json(source, ["token"], key_names=True)
    assert output == source.replace('"token":', '"REDACTED_KEY_1_":')
    assert count == 2


def test_escaped_keys_duplicate_keys_and_exact_matching():
    source = r'{"to\u006ben": "a", "token":"b", "Token":"c", "keep":"token: x"}'
    output, count = redact_json(source, ["token"])
    assert count == 2
    assert '"Token":"c"' in output
    assert '"keep":"token: x"' in output
    assert json.loads(output)["token"] == "[REDACTED]"


@pytest.mark.parametrize("source", ['{"token":', '{"token": NaN}', '{"token": Infinity}'])
def test_invalid_json_rejected(source):
    with pytest.raises(ValueError):
        redact_json(source, ["token"])


def test_no_matches_and_empty_keys():
    assert redact_json(' [ 1, "hello" ] ', ["token"]) == (' [ 1, "hello" ] ', 0)
    with pytest.raises(ValueError):
        redact_json('{}', [])


@pytest.mark.parametrize("key", ["twocaptcha_apikey", "TWOCAPTCHA_APIKEY", "stripeApiKey",
                                  "api-key", "access_token", "clientSecret", "db_password"])
def test_automatic_credential_fields(key):
    source = '{\r\n  "items": [{"' + key + '": "short"}], "count": 1.00, "enabled":true\r\n}'
    output, count = redact_json(source, [], auto_sensitive=True)
    assert output == source.replace('"short"', '"[REDACTED]"')
    assert count == 1


def test_auto_matching_does_not_redact_metadata_or_text_values():
    source = '{"api_key_enabled":true,"token_count":2,"secretary":"name","text":"twocaptcha_apikey","custom":"fake"}'
    output, count = redact_json(source, ["custom"], auto_sensitive=True)
    assert output == source.replace('"fake"', '"[REDACTED]"')
    assert count == 1


def test_automatic_matching_can_be_disabled():
    source = '{"twocaptcha_apikey":"fake","api_key":"fake2"}'
    assert redact_json(source, ["api_key"])[0] == source.replace('"fake2"', '"[REDACTED]"')
