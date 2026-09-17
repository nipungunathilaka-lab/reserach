#!/bin/bash

set -e

export DEBIAN_FRONTEND=noninteractive

apt-get update

apt-get install -y python3-pip python3-venv cmake build-essential git



cd /tmp

rm -rf crypto_test

mkdir crypto_test

cd crypto_test

python3 -m venv venv

source venv/bin/activate



# Copy necessary files from Windows mount

cp -r /mnt/c/RP3/ai-secure-file-transfer-system/backend .

cp -r /mnt/c/RP3/ai-secure-file-transfer-system/tests .

cp /mnt/c/RP3/ai-secure-file-transfer-system/run_custom_tests.py .



# Install dependencies in the fast native /tmp filesystem

pip install -r backend/requirements.txt

pip install cryptography liboqs-python



# Run tests

PYTHONPATH=/tmp/crypto_test/backend python run_custom_tests.py



# Copy results back to Windows mount

mkdir -p /mnt/c/RP3/ai-secure-file-transfer-system/tests/results/final_crypto_assurance

cp tests/results/final_crypto_assurance/*.json /mnt/c/RP3/ai-secure-file-transfer-system/tests/results/final_crypto_assurance/