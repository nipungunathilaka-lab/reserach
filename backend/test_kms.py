import pytest
import sys
try:
    import boto3
except ImportError:
    pytest.skip("boto3 is not installed; KMS tests require it for aws_kms_provider", allow_module_level=True)

import os
import pytest
import base64
from app.security.kms.local_dev_provider import LocalDevProvider
try:
    from app.security.kms.aws_kms_provider import AWSKMSProvider
except ImportError:
    AWSKMSProvider = None
from app.security.kms import kms_provider
from app.core.config import settings

def test_local_dev_provider():
    provider = LocalDevProvider()
    
    # Test Data Key Generation
    plain_key, enc_key = provider.generate_data_key("alias/test")
    assert len(plain_key) == 32
    assert len(enc_key) > 32
    
    # Test Decrypt Data Key
    decrypted_key = provider.decrypt(enc_key, "alias/test")
    assert decrypted_key == plain_key
    
    # Test Sign and Verify
    msg = b"test audit hash"
    sig = provider.sign(msg, "alias/audit")
    assert len(sig) > 0
    assert provider.verify(msg, sig, "alias/audit") is True
    assert provider.verify(b"tampered", sig, "alias/audit") is False

def test_kms_module_initialization():
    # Because tests run with local_dev by default, this should be a LocalDevProvider
    assert kms_provider is not None
    assert isinstance(kms_provider, LocalDevProvider)

@pytest.mark.skipif("boto3" not in sys.modules or not os.environ.get("AWS_ACCESS_KEY_ID"), reason="Live AWS credentials and boto3 required")
def test_live_aws_kms_provider():
    """
    Live test against AWS KMS.
    Only runs if AWS_ACCESS_KEY_ID is present in the environment.
    """
    provider = AWSKMSProvider(region_name=settings.aws_region)
    assert provider.health_check() is True

    # Note: A real live test would need the actual envelope alias set up in the account.
    envelope_alias = settings.kms_envelope_key_alias
    plain_key, enc_key = provider.generate_data_key(envelope_alias)
    assert plain_key is not None
    assert enc_key is not None

    decrypted = provider.decrypt(enc_key, envelope_alias)
    assert decrypted == plain_key

    # Audit signing test
    audit_alias = settings.kms_audit_signing_key_alias
    msg = b"live audit hash"
    sig = provider.sign(msg, audit_alias)
    assert provider.verify(msg, sig, audit_alias) is True
