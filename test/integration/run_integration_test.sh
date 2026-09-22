#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

echo "Building agent..."
make build

echo "Starting agent (requires root for BPF)..."
sudo ./agent/bin/netmon &
AGENT_PID=$!
sleep 2

echo "Generating known TCP traffic..."
python3 test/integration/generate_traffic.py

sleep 6  # let one 5s collection interval pass

echo "Checking /metrics for our own process..."
METRICS=$(curl -s http://localhost:9200/metrics)
if echo "$METRICS" | grep -q 'netmon_bytes_sent_total{process="python3"}'; then
    echo "PASS: found netmon_bytes_sent_total for python3"
    RESULT=0
else
    echo "FAIL: no netmon_bytes_sent_total metric found for python3"
    echo "$METRICS"
    RESULT=1
fi

sudo kill "$AGENT_PID"
exit $RESULT
