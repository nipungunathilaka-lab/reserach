provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  description = "AWS region for Private CA"
  default     = "us-east-1"
}

# -----------------------------------------------------------------------------
# AWS PRIVATE CA (Certificate Authority)
# Used to issue client and server certificates for mTLS.
# WARNING: This resource costs $400/month per CA. Only apply in production.
# -----------------------------------------------------------------------------

resource "aws_acmpca_certificate_authority" "root_ca" {
  type = "ROOT"

  certificate_authority_configuration {
    key_algorithm     = "RSA_4096"
    signing_algorithm = "SHA512WITHRSA"

    subject {
      common_name  = "AI SFT Root CA"
      organization = "AI Secure File Transfer System"
      country      = "US"
    }
  }

  permanent_deletion_time_in_days = 7

  tags = {
    Environment = "production"
    Service     = "ai-sft"
  }
}

# In a real environment, you must manually install the CA certificate or use 
# aws_acmpca_certificate to self-sign the root before it becomes active.
