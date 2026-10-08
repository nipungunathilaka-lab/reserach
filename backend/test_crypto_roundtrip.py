import pytest
pytestmark = [pytest.mark.integration, pytest.mark.pqc]
from types import SimpleNamespace

from app.services.crypto_service import CryptoService


def test_pfce_round_trip(tmp_path, monkeypatch):
    encrypted_dir = tmp_path / "encrypted"
    keys_dir = tmp_path / "keys"
    encrypted_dir.mkdir()
    keys_dir.mkdir()

    import app.services.crypto_service as module

    monkeypatch.setattr(module, "ENCRYPTED_DIR", encrypted_dir)
    monkeypatch.setattr(module, "KEYS_DIR", keys_dir)

    source = tmp_path / "research.txt"
    original = (b"PFCE research data\n" * 10000)
    source.write_bytes(original)

    from app.services.upce_quantum_service import UniversalPolymorphicCryptoEngine
    from app.services.mlkem_service import MLKEMService

    CryptoService.generate_prekeys_for_user(99, 1)
    prekey_pub = CryptoService.claim_prekey(99, "test-package")
    
    try:
        MLKEMService.get_active_public_key("99")
    except ValueError:
        MLKEMService.generate_keypair("99")

    upce = UniversalPolymorphicCryptoEngine()
    upce_result = upce.initialize_transfer_security(1, 99, {"min_chunk_bytes": 1024}, prekey_pub, "test-package")
    hybrid_kek = upce_result.get("hybrid_kek")

    result = CryptoService.encrypt_file_for_receiver(
        src_path=str(source),
        receiver_id=99,
        stored_name="test-package",
        classification="Sensitive",
        hybrid_kek=hybrid_kek,
        transfer_id="test-package"
    )

    transfer = SimpleNamespace(
        encrypted_path=result.encrypted_path,
        encrypted_key=result.encrypted_key,
        hybrid_wrapped_key=result.hybrid_wrapped_key,
        hybrid_wrap_nonce=result.hybrid_wrap_nonce,
        stored_name="test-package",
        nonce=result.nonce,
        cipher_algorithm=result.cipher_algorithm,
    )

    prekey_priv = CryptoService.get_and_delete_prekey(99, "test-package")
    recovered_kek = upce.recover_transfer_security(1, 99, "test-package", upce_result.get("metadata"), prekey_priv, prekey_pub)

    recovered = CryptoService.decrypt_transfer_bytes(
        transfer,
        receiver_id=99,
        hybrid_kek=recovered_kek
    )

    assert recovered == original
