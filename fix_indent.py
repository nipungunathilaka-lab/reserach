import sys

lines = open('C:/RP3/ai-secure-file-transfer-system/backend/app/services/pfce_engine.py').readlines()

for i in range(405, 465):
    lines[i] = "        " + lines[i]

open('C:/RP3/ai-secure-file-transfer-system/backend/app/services/pfce_engine.py', 'w').writelines(lines)
