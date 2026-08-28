from types import SimpleNamespace

from app.services.crypto_service import CryptoContext, CryptoService


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

    context = CryptoContext(
        classification="Sensitive",
        file_size_bytes=len(original),
        file_extension=".txt",
        threat_score=0.5,
        cpu_usage_percent=20,
        memory_usage_percent=30,
    )

    result = CryptoService.encrypt_file_for_receiver(
        src_path=str(source),
        receiver_id=99,
        stored_name="test-package",
        context=context,
    )

    transfer = SimpleNamespace(
        encrypted_path=result.encrypted_path,
        encrypted_key=result.encrypted_key,
        ecdh_public_key=result.ecdh_public_key,
        ecdh_wrapped_key=result.ecdh_wrapped_key,
        ecdh_key_nonce=result.ecdh_key_nonce,
        stored_name="test-package",
        nonce=result.nonce,
    )

    recovered = CryptoService.decrypt_transfer_bytes(
        transfer,
        receiver_id=99,
    )

    assert recovered == original
    assert result.fragment_count >= 1
    assert result.original_hash == CryptoService.sha256_bytes(original)
