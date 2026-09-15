import argparse
import logging
from app.database.db import SessionLocal
from app.security.kms.key_registry import KeyRegistry
from app.core.config import settings
import boto3

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def rotate_key(purpose: str, alias_name: str, key_spec: str = "SYMMETRIC_DEFAULT", key_usage: str = "ENCRYPT_DECRYPT"):
    """
    Simulates a manual key rotation event.
    1. Creates a new KMS Key in AWS.
    2. Updates the Alias to point to the new key.
    3. Registers the new key in the database registry.
    4. Marks the previous key as VERIFY_ONLY (or allows automatic handling).
    """
    logger.info(f"Starting key rotation for purpose: {purpose}")
    
    if settings.key_provider != "aws_kms":
        logger.error("Rotation tool requires KEY_PROVIDER=aws_kms")
        return

    kms = boto3.client("kms", region_name=settings.aws_region)
    
    # 1. Create new key
    logger.info("Creating new AWS KMS key...")
    response = kms.create_key(
        Description=f"AI SFT - {purpose} Key",
        KeyUsage=key_usage,
        KeySpec=key_spec,
        Origin="AWS_KMS"
    )
    new_key_id = response["KeyMetadata"]["KeyId"]
    new_key_arn = response["KeyMetadata"]["Arn"]
    logger.info(f"New Key ID: {new_key_id}")

    # 2. Update alias
    logger.info(f"Updating alias {alias_name} to point to {new_key_id}")
    try:
        kms.update_alias(
            AliasName=alias_name,
            TargetKeyId=new_key_id
        )
    except kms.exceptions.NotFoundException:
        logger.info(f"Alias {alias_name} not found. Creating it.")
        kms.create_alias(
            AliasName=alias_name,
            TargetKeyId=new_key_id
        )

    # 3. Update Database Registry
    with SessionLocal() as db:
        new_record = KeyRegistry.register_key(
            db=db,
            purpose=purpose,
            provider_key_id=new_key_id,
            alias=alias_name,
            provider_key_arn=new_key_arn,
            key_spec=key_spec,
            key_usage=key_usage
        )
        logger.info(f"Successfully registered new key version {new_record.version} in database.")
        
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Rotate Enterprise KMS Keys")
    parser.add_argument("--purpose", required=True, choices=["envelope", "audit_signing"], help="Which key to rotate")
    args = parser.parse_args()

    if args.purpose == "envelope":
        rotate_key(
            purpose="envelope",
            alias_name=settings.kms_envelope_key_alias,
            key_spec="SYMMETRIC_DEFAULT",
            key_usage="ENCRYPT_DECRYPT"
        )
    elif args.purpose == "audit_signing":
        rotate_key(
            purpose="audit_signing",
            alias_name=settings.kms_audit_signing_key_alias,
            key_spec="RSA_3072",
            key_usage="SIGN_VERIFY"
        )
