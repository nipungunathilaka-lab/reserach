from app.services.crypto_service import CryptoContext, CryptoService


def test_sensitive_policy_enables_forward_secrecy():
    context = CryptoContext(
        classification="Sensitive",
        file_size_bytes=1024,
        file_extension=".pdf",
        threat_score=0.5,
        cpu_usage_percent=30,
        memory_usage_percent=40,
    )
    policy = CryptoService.select_policy(context)

    assert policy.security_level == "high"
    assert policy.use_forward_secrecy is True
    assert len(policy.candidate_algorithms) == 2


def test_critical_policy_uses_small_fragments():
    context = CryptoContext(
        classification="Restricted",
        file_size_bytes=1024,
        file_extension=".docx",
        threat_score=0.9,
        cpu_usage_percent=30,
        memory_usage_percent=40,
    )
    policy = CryptoService.select_policy(context)

    assert policy.security_level == "critical"
    assert policy.fragment_size_bytes == 512 * 1024
