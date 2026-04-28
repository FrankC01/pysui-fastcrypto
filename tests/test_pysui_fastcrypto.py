import pytest
import pysui_fastcrypto as fc


class TestKeyGeneration:
    def test_generate_keypair_ed25519(self):
        phrase, pub_bytes, prv_bytes = fc.generate_new_keypair(0)
        assert phrase
        assert len(phrase.split()) == 12
        assert len(pub_bytes) == 32
        assert len(prv_bytes) == 32

    def test_generate_keypair_secp256k1(self):
        phrase, pub_bytes, prv_bytes = fc.generate_new_keypair(1)
        assert phrase
        assert len(phrase.split()) == 12
        assert len(pub_bytes) == 33
        assert len(prv_bytes) == 32

    def test_generate_keypair_secp256r1(self):
        phrase, pub_bytes, prv_bytes = fc.generate_new_keypair(2)
        assert phrase
        assert len(phrase.split()) == 12
        assert len(pub_bytes) == 33
        assert len(prv_bytes) == 32

    def test_generate_keypair_custom_word_count(self):
        phrase_12, _, _ = fc.generate_new_keypair(0, word_count="12")
        phrase_24, _, _ = fc.generate_new_keypair(0, word_count="24")
        assert len(phrase_12.split()) == 12
        assert len(phrase_24.split()) == 24

    def test_generate_keypair_with_custom_path(self):
        path = "m/44'/784'/0'/0'/0'"
        phrase, pub_bytes, prv_bytes = fc.generate_new_keypair(
            0, derv_path=path
        )
        assert phrase
        assert len(pub_bytes) == 32
        assert len(prv_bytes) == 32


class TestMnemonicGeneration:
    def test_generate_mnemonic_default(self):
        phrase = fc.generate_mnemonic_phrase()
        assert phrase
        assert len(phrase.split()) == 12

    def test_generate_mnemonic_12(self):
        phrase = fc.generate_mnemonic_phrase("12")
        assert len(phrase.split()) == 12

    def test_generate_mnemonic_24(self):
        phrase = fc.generate_mnemonic_phrase("24")
        assert len(phrase.split()) == 24

    def test_generate_mnemonic_all_counts(self):
        for word_count in ["12", "15", "18", "21", "24"]:
            phrase = fc.generate_mnemonic_phrase(word_count)
            assert len(phrase.split()) == int(word_count)


class TestKeyRecovery:
    def test_keys_from_mnemonics_ed25519(self):
        phrase = "test walk nut penalty hip pave soap entry language right filter choice"
        path = "m/44'/784'/0'/0'/0'"
        pub_bytes, prv_bytes = fc.keys_from_mnemonics(0, path, phrase)
        assert len(pub_bytes) == 32
        assert len(prv_bytes) == 32

    def test_keys_from_mnemonics_consistent(self):
        phrase, orig_pub, orig_prv = fc.generate_new_keypair(0)
        path = "m/44'/784'/0'/0'/0'"
        pub_bytes, prv_bytes = fc.keys_from_mnemonics(0, path, phrase)
        assert pub_bytes == orig_pub
        assert prv_bytes == orig_prv

    def test_keys_from_mnemonics_all_schemes(self):
        phrase = "test walk nut penalty hip pave soap entry language right filter choice"
        for scheme in [0, 1, 2]:
            path = (
                "m/44'/784'/0'/0'/0'"
                if scheme == 0
                else "m/54'/784'/0'/0/0"
                if scheme == 1
                else "m/74'/784'/0'/0/0"
            )
            pub_bytes, prv_bytes = fc.keys_from_mnemonics(scheme, path, phrase)
            assert pub_bytes
            assert prv_bytes




class TestSigning:
    def test_sign_digest_ed25519(self):
        phrase, pub_bytes, prv_bytes = fc.generate_new_keypair(0)
        msg_b64 = "aGVsbG8gd29ybGQ="  # "hello world" in base64
        sig = fc.sign_digest(0, prv_bytes, msg_b64)
        assert sig
        assert len(sig) > 0

    def test_sign_digest_all_schemes(self):
        msg_b64 = "dGVzdCBkYXRh"  # "test data" in base64
        for scheme in [0, 1, 2]:
            _, _, prv_bytes = fc.generate_new_keypair(scheme)
            sig = fc.sign_digest(scheme, prv_bytes, msg_b64)
            assert sig
            assert len(sig) > 0

    def test_sign_message(self):
        phrase, _, prv_bytes = fc.generate_new_keypair(0)
        msg_b64 = "aGVsbG8="  # "hello" in base64
        sig = fc.sign_message(0, prv_bytes, msg_b64)
        assert sig
        assert isinstance(sig, str)


class TestVerification:
    def test_verify_wrong_signature(self):
        phrase, pub_bytes, prv_bytes = fc.generate_new_keypair(0)
        msg_b64 = "aGVsbG8="
        import base64

        bad_sig_b64 = base64.b64encode(b"x" * 64).decode()
        result = fc.verify_pubk(0, pub_bytes, msg_b64, bad_sig_b64)
        assert result is False


class TestBech32:
    def test_encode_bech32(self):
        phrase, _, prv_bytes = fc.generate_new_keypair(0)
        bech32_str = fc.encode_bech32(prv_bytes, "sui")
        assert bech32_str.startswith("sui")

    def test_bech32_invalid_hrp(self):
        _, _, prv_bytes = fc.generate_new_keypair(0)
        bech32_str = fc.encode_bech32(prv_bytes, "sui")
        scheme, _, _ = fc.decode_bech32(bech32_str, "invalid")
        assert scheme == 255
