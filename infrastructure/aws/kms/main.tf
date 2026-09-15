provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  description = "AWS region for KMS keys"
  default     = "us-east-1"
}

# -----------------------------------------------------------------------------
# SYMMETRIC ENVELOPE ENCRYPTION KEY
# Used to encrypt per-file AES data keys for non-E2EE transfers
# -----------------------------------------------------------------------------
resource "aws_kms_key" "envelope_key" {
  description             = "AI Secure File Transfer - Envelope Encryption KEK"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  is_enabled              = true
  key_usage               = "ENCRYPT_DECRYPT"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"

  tags = {
    Environment = "production"
    Service     = "ai-sft"
    Purpose     = "EnvelopeEncryption"
  }
}

resource "aws_kms_alias" "envelope_alias" {
  name          = "alias/ai-sft-prod-envelope"
  target_key_id = aws_kms_key.envelope_key.key_id
}

# -----------------------------------------------------------------------------
# ASYMMETRIC AUDIT SIGNING KEY
# Used to sign AuditBlock hashes for non-repudiation
# -----------------------------------------------------------------------------
resource "aws_kms_key" "audit_signing_key" {
  description             = "AI Secure File Transfer - Audit Ledger Signing Key"
  deletion_window_in_days = 30
  is_enabled              = true
  key_usage               = "SIGN_VERIFY"
  customer_master_key_spec = "RSA_3072" # Or RSA_4096 / ECC_NIST_P256

  tags = {
    Environment = "production"
    Service     = "ai-sft"
    Purpose     = "AuditSigning"
  }
}

resource "aws_kms_alias" "audit_signing_alias" {
  name          = "alias/ai-sft-prod-audit-signing"
  target_key_id = aws_kms_key.audit_signing_key.key_id
}

# -----------------------------------------------------------------------------
# IAM POLICY FOR BACKEND ROLE
# -----------------------------------------------------------------------------
resource "aws_iam_policy" "kms_access_policy" {
  name        = "ai-sft-kms-policy"
  description = "Allows backend to use KMS keys for encryption and signing"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "kms:GenerateDataKey",
          "kms:Decrypt",
          "kms:Encrypt"
        ]
        Resource = [
          aws_kms_key.envelope_key.arn
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Sign",
          "kms:Verify"
        ]
        Resource = [
          aws_kms_key.audit_signing_key.arn
        ]
      }
    ]
  })
}
