from .base import KeyManagementProvider
from .aws_kms_provider import AWSKMSProvider
from .local_dev_provider import LocalDevProvider
from app.core.config import settings

def get_kms_provider() -> KeyManagementProvider:
    if settings.key_provider == "aws_kms":
        return AWSKMSProvider(region_name=settings.aws_region)
    elif settings.key_provider == "local_dev":
        if settings.environment.lower() == "production":
            raise RuntimeError("CRITICAL SECURITY ERROR: local_dev KEY_PROVIDER cannot be used in production environment.")
        return LocalDevProvider()
    else:
        raise ValueError(f"Unknown KEY_PROVIDER: {settings.key_provider}")

kms_provider = get_kms_provider()
