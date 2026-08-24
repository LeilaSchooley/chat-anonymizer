"""Tests for ChatAnonymizer.

Fixtures are synthetic. Never add real client conversations here.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src.anonymizer import ChatAnonymizer
from src.detectors import (
    HighEntropySecretRecognizer,
    _api_key_recognizer,
    _chat_handle_recognizer,
    _email_recognizer,
    _password_recognizer,
    _six_digit_otp_recognizer,
    _verification_code_recognizer,
)


FIXTURES = Path(__file__).parent / "fixtures"
SAMPLE_CHAT = FIXTURES / "sample_chat.txt"
WHATSAPP_CHAT = FIXTURES / "whatsapp_sample.txt"


def _spacy_available() -> bool:
    try:
        import spacy

        for name in ("en_core_web_lg", "en_core_web_sm"):
            try:
                spacy.load(name)
                return True
            except OSError:
                continue
        return False
    except ImportError:
        return False


requires_spacy = pytest.mark.skipif(
    not _spacy_available(),
    reason="spaCy English model not installed (en_core_web_lg or en_core_web_sm)",
)


def _spans(text: str, results) -> set[str]:
    return {text[r.start : r.end] for r in results}


class TestCustomRecognizers:
    def test_chat_handle_detects_mention(self):
        recognizer = _chat_handle_recognizer()
        text = "ping @priya_nair please"
        results = recognizer.analyze(text=text, entities=["CHAT_HANDLE"])
        assert "@priya_nair" in _spans(text, results)

    def test_api_key_detects_github_pat(self):
        recognizer = _api_key_recognizer()
        text = "key ghp_abcdefghijklmnopqrstuvwx leaked"
        results = recognizer.analyze(text=text, entities=["API_KEY"])
        assert any(text[r.start : r.end].startswith("ghp_") for r in results)

    def test_email_catches_example_tld(self):
        recognizer = _email_recognizer()
        text = "mail priya.nair@contoso.example please"
        results = recognizer.analyze(text=text, entities=["EMAIL_ADDRESS"])
        assert "priya.nair@contoso.example" in _spans(text, results)

    def test_password_labeled_value(self):
        recognizer = _password_recognizer()
        text = "Temporary password: Vn9$kQ2mLp!x thanks"
        results = recognizer.analyze(text=text, entities=["PASSWORD"])
        assert "Vn9$kQ2mLp!x" in _spans(text, results)

    def test_password_is_form(self):
        recognizer = _password_recognizer()
        text = "my password is Tr0ub4dor&3x for now"
        results = recognizer.analyze(text=text, entities=["PASSWORD"])
        assert "Tr0ub4dor&3x" in _spans(text, results)

    def test_verification_code_numeric(self):
        recognizer = _verification_code_recognizer()
        text = "verification code is 392847"
        results = recognizer.analyze(text=text, entities=["VERIFICATION_CODE"])
        assert "392847" in _spans(text, results)

    def test_otp_labeled(self):
        recognizer = _verification_code_recognizer()
        text = "OTP: 847291"
        results = recognizer.analyze(text=text, entities=["VERIFICATION_CODE"])
        assert "847291" in _spans(text, results)

    def test_six_digit_otp_anywhere(self):
        recognizer = _six_digit_otp_recognizer()
        text = "ping me the code later — 002793 — thanks"
        results = recognizer.analyze(text=text, entities=["VERIFICATION_CODE"])
        assert "002793" in _spans(text, results)

    def test_six_digit_does_not_eat_longer_ids(self):
        recognizer = _six_digit_otp_recognizer()
        text = "anydesk 1734539244"
        results = recognizer.analyze(text=text, entities=["VERIFICATION_CODE"])
        assert results == []

    def test_high_entropy_near_password_context(self):
        recognizer = HighEntropySecretRecognizer()
        text = "here is the reset token a8f3K9mX2pQ7vL0s for login"
        results = recognizer.analyze(text=text, entities=["SECRET"])
        assert "a8f3K9mX2pQ7vL0s" in _spans(text, results)


class TestMappingConsistency:
    def test_placeholder_reuse_is_stable(self):
        anonymizer = ChatAnonymizer(mapping={"Ada Lovelace": "PERSON_1"})
        assert anonymizer._placeholder_for("PERSON", "Ada Lovelace") == "PERSON_1"
        assert anonymizer._placeholder_for("PERSON", "ada lovelace") == "PERSON_1"

    def test_new_values_increment(self):
        anonymizer = ChatAnonymizer()
        first = anonymizer._placeholder_for("EMAIL_ADDRESS", "a@example.com")
        second = anonymizer._placeholder_for("EMAIL_ADDRESS", "b@example.com")
        assert first == "EMAIL_ADDRESS_1"
        assert second == "EMAIL_ADDRESS_2"

    def test_save_and_load_map(self, tmp_path: Path):
        anonymizer = ChatAnonymizer(mapping={"a@example.com": "EMAIL_ADDRESS_1"})
        map_path = tmp_path / "map.json"
        anonymizer.save_map(map_path)

        loaded = ChatAnonymizer()
        loaded.load_map(map_path)
        assert loaded.mapping == {"a@example.com": "EMAIL_ADDRESS_1"}
        assert loaded._placeholder_for("EMAIL_ADDRESS", "b@example.com") == "EMAIL_ADDRESS_2"

    def test_deanonymize_roundtrip_with_map(self):
        anonymizer = ChatAnonymizer(
            mapping={"Priya Nair": "PERSON_1", "priya.nair@contoso.example": "EMAIL_ADDRESS_1"}
        )
        scrubbed = "Hello PERSON_1 at EMAIL_ADDRESS_1"
        assert anonymizer.deanonymize(scrubbed) == "Hello Priya Nair at priya.nair@contoso.example"


@requires_spacy
class TestAnonymizeIntegration:
    def test_sample_chat_redacts_sensitive_values(self):
        text = SAMPLE_CHAT.read_text(encoding="utf-8")
        result = ChatAnonymizer().anonymize(text)

        for sensitive in [
            "priya.nair@contoso.example",
            "Priya Nair",
            "+1-206-555-0199",
            "ghp_abcdefghijklmnopqrstuvwx",
            "Vn9$kQ2mLp!x",
            "392847",
            "a8f3K9mX2pQ7vL0s",
            "552219",
            "acct_77821",
        ]:
            assert sensitive not in result.text, f"leaked: {sensitive}"

        email_placeholders = {
            item["replacement"]
            for item in result.entities_found
            if item["entity_type"] == "EMAIL_ADDRESS"
        }
        assert len(email_placeholders) == 1
        placeholder = next(iter(email_placeholders))
        assert result.text.count(placeholder) >= 2

    def test_anonymize_file(self):
        result = ChatAnonymizer().anonymize_file(SAMPLE_CHAT)
        assert isinstance(result.text, str)
        assert result.text != SAMPLE_CHAT.read_text(encoding="utf-8")

    def test_whatsapp_codes_passwords_remote_and_lookback(self):
        text = WHATSAPP_CHAT.read_text(encoding="utf-8")
        result = ChatAnonymizer(dedupe_lines=True, drop_media_omitted=True).anonymize(text)

        for sensitive in [
            "002793",
            "cssss1",
            "1734539244",
            "$sdsdsdsd{Fj",
            ":h@2323",
            "h@2323",
            "SnowByrds4545",
            "sntrys_eyJpYXQiOjE3NjE5NTkxMzIuNTgxABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "1 222 222 177",
            "ezpd3zzb",
            "p8br3da5",
            "ab12cd34",
            "https://connect.example.com/join/abc123",
        ]:
            assert sensitive not in result.text, f"leaked: {sensitive}"

        # Harmless chat should survive
        assert "Retry" in result.text
        assert "yes" in result.text
        # Media omitted line dropped
        assert "Media omitted" not in result.text
        # Consecutive duplicate Ready collapsed to one
        assert result.text.count("Ready") == 1

        types = {e["entity_type"] for e in result.entities_found}
        assert "VERIFICATION_CODE" in types
        assert "PASSWORD" in types
        assert "REMOTE_DESKTOP_ID" in types
        assert "API_KEY" in types
        assert "SENSITIVE_URL" in types
