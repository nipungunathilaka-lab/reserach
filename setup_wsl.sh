#!/bin/bash

apt-get update

apt-get install -y python3-pip python3-venv cmake build-essential git

python3 -m venv venv

source venv/bin/activate

pip install -r backend/requirements.txt

pip install cryptography

pip install liboqs-python

PYTHONPATH=/mnt/c/RP3/ai-secure-file-transfer-system/backend python run_custom_tests.py