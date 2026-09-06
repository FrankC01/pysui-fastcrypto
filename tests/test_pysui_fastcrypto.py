import ast
import pathlib
import types

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

    def test_decode_bech32_correct_round_trip(self):
        _, pub_bytes, prv_bytes = fc.generate_new_keypair(0)
        encoded = fc.encode_bech32(bytes([0]) + prv_bytes, "sui")
        scheme, decoded_pub, decoded_prv = fc.decode_bech32(encoded, "sui")
        assert scheme == 0
        assert decoded_pub == pub_bytes
        assert decoded_prv == prv_bytes


class TestVerifyPubk:
    def test_verify_pubk_ed25519(self):
        _, pub_bytes, prv_bytes = fc.generate_new_keypair(0)
        msg_b64 = "aGVsbG8gd29ybGQ="  # "hello world"
        sig = fc.sign_message(0, prv_bytes, msg_b64)
        assert fc.verify_pubk(0, pub_bytes, msg_b64, sig) is True

    def test_verify_pubk_returns_false_on_wrong_sig(self):
        import base64
        _, pub_bytes, _ = fc.generate_new_keypair(0)
        msg_b64 = "aGVsbG8="
        bad_sig_b64 = base64.b64encode(b"x" * 64).decode()
        assert fc.verify_pubk(0, pub_bytes, msg_b64, bad_sig_b64) is False


class TestErrors:
    def test_keys_from_keystring_empty(self):
        with pytest.raises(ValueError):
            fc.keys_from_keystring("")

    def test_keys_from_keystring_invalid_base64(self):
        with pytest.raises(ValueError):
            fc.keys_from_keystring("!!!")

    def test_generate_new_keypair_bad_scheme(self):
        with pytest.raises(ValueError):
            fc.generate_new_keypair(6)

    def test_generate_new_keypair_bad_path(self):
        with pytest.raises(ValueError):
            fc.generate_new_keypair(0, derv_path="bad/path")

    def test_generate_new_keypair_bad_word_count(self):
        with pytest.raises(ValueError):
            fc.generate_new_keypair(0, word_count="13")

    def test_generate_mnemonic_bad_word_count(self):
        with pytest.raises(ValueError):
            fc.generate_mnemonic_phrase("13")

    def test_keys_from_mnemonics_bad_phrase(self):
        with pytest.raises(ValueError):
            fc.keys_from_mnemonics(0, "m/44'/784'/0'/0'/0'", "aaaa bbbb cccc dddd eeee ffff gggg hhhh iiii jjjj kkkk llll")

    def test_sign_digest_bad_scheme(self):
        with pytest.raises(ValueError):
            fc.sign_digest(6, bytes(32), "aGVsbG8=")

    def test_sign_digest_bad_base64(self):
        _, _, prv_bytes = fc.generate_new_keypair(0)
        with pytest.raises(ValueError):
            fc.sign_digest(0, prv_bytes, "!!!")

    def test_sign_message_bad_scheme(self):
        with pytest.raises(ValueError):
            fc.sign_message(6, bytes(32), "aGVsbG8=")

    def test_verify_bad_scheme(self):
        import base64
        with pytest.raises(ValueError):
            fc.verify(6, bytes(32), "aGVsbG8=", base64.b64encode(b"x" * 64).decode())

    def test_verify_pubk_bad_scheme(self):
        import base64
        with pytest.raises(ValueError):
            fc.verify_pubk(6, bytes(32), "aGVsbG8=", base64.b64encode(b"x" * 64).decode())

    def test_verify_pubk_unsupported_scheme(self):
        import base64
        with pytest.raises(ValueError):
            fc.verify_pubk(3, bytes(48), "aGVsbG8=", base64.b64encode(b"x" * 64).decode())

    def test_verify_pubk_bad_pub_bytes(self):
        import base64
        bad_sig_b64 = base64.b64encode(b"x" * 64).decode()
        try:
            result = fc.verify_pubk(0, bytes(32), "aGVsbG8=", bad_sig_b64)
            assert result is False
        except ValueError:
            pass


class TestTypeStubParity:
    """The hand-maintained ``.pyi`` must describe exactly the shipped surface.

    ``CLAUDE.md`` requires the stub to be updated in the same commit as any
    public API change, but nothing enforced that: the extension is compiled, the
    stub is written by hand, and drift between them is silent. A caller then
    gets no completion for a real function, or a type error for one that does
    not exist.

    This checks names and existence only. Signature drift is NOT detectable — a
    compiled extension exposes no introspectable signature to compare against —
    so a stub whose parameters have gone stale still passes here.
    """

    @staticmethod
    def _stub_surface() -> set[str]:
        """Top-level function and class names declared in the type stub."""
        stub_path = pathlib.Path(__file__).resolve().parent.parent / "pysui_fastcrypto.pyi"
        tree = ast.parse(stub_path.read_text(encoding="utf-8"))
        return {
            node.name
            for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.ClassDef))
        }

    @staticmethod
    def _module_surface() -> set[str]:
        """Public names the built extension actually exposes.

        Submodules are excluded. Maturin's package layout puts the compiled
        extension inside a package of the same name, so ``dir()`` reports a
        nested ``pysui_fastcrypto`` module — that is packaging structure, not
        API surface, and it has no business in a type stub.
        """
        return {
            name
            for name in dir(fc)
            if not name.startswith("_")
            and not isinstance(getattr(fc, name), types.ModuleType)
        }

    def test_every_export_is_stubbed(self):
        """A new export without a stub entry fails here.

        This also catches an export that was written and stubbed but never
        registered in the ``#[pymodule]`` block, since the comparison runs
        against the imported module rather than against the Rust source.
        """
        missing = self._module_surface() - self._stub_surface()
        assert not missing, f"exported but missing from pysui_fastcrypto.pyi: {sorted(missing)}"

    def test_every_stub_entry_is_exported(self):
        """A stub for a removed or misspelled export fails here."""
        extra = self._stub_surface() - self._module_surface()
        assert not extra, f"stubbed but not exported by the module: {sorted(extra)}"
