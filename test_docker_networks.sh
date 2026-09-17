#!/bin/bash
# test_docker_networks.sh
# Validates Docker network segmentation via ping and curl.

echo "Testing Node.js -> FastAPI (Expected: ALLOW)"
docker exec $(docker ps -qf "name=node-api") curl -s -m 2 http://backend:8000/internal/crypto/ensure_keys > /dev/null
if [ $? -eq 0 ] || [ $? -eq 22 ]; then echo "PASS (Reachable)"; else echo "FAIL"; fi

echo "Testing Node.js -> Besu Gateway (Expected: DENY)"
docker exec $(docker ps -qf "name=node-api") curl -s -m 2 https://besu-gateway:8443 > /dev/null
if [ $? -eq 28 ]; then echo "PASS (Timeout/Blocked)"; else echo "FAIL"; fi

echo "Testing Node.js -> Besu Validator (Expected: DENY)"
docker exec $(docker ps -qf "name=node-api") curl -s -m 2 http://besu-validator-1:8545 > /dev/null
if [ $? -eq 28 ] || [ $? -eq 6 ]; then echo "PASS (Blocked/Unresolved)"; else echo "FAIL"; fi

echo "Testing FastAPI -> Besu Gateway (Expected: ALLOW)"
docker exec $(docker ps -qf "name=backend") curl -k -s -m 2 https://besu-gateway:8443 > /dev/null
if [ $? -eq 0 ] || [ $? -eq 22 ] || [ $? -eq 401 ]; then echo "PASS (Reachable)"; else echo "FAIL"; fi

echo "Testing FastAPI -> Besu Validator directly (Expected: DENY)"
docker exec $(docker ps -qf "name=backend") curl -s -m 2 http://besu-validator-1:8545 > /dev/null
if [ $? -eq 28 ] || [ $? -eq 6 ]; then echo "PASS (Blocked)"; else echo "FAIL"; fi

echo "Host -> FastAPI (Expected: DENY)"
curl -s -m 2 http://localhost:8000 > /dev/null
if [ $? -eq 7 ] || [ $? -eq 28 ]; then echo "PASS (Blocked)"; else echo "FAIL"; fi

echo "Host -> Besu RPC (Expected: DENY)"
curl -s -m 2 https://localhost:8443 > /dev/null
if [ $? -eq 7 ] || [ $? -eq 28 ]; then echo "PASS (Blocked)"; else echo "FAIL"; fi

echo "Generating Network Matrix..."
docker network inspect app_edge app_internal rpc_client_net besu_private_net | grep -E 'Name"|IPv4Address'
