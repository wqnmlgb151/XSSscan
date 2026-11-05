#!/bin/sh
# Executed inside the test-only image, with --network none and loopback fixture.
set -eu
container-fixture &
fixture_pid=$!
trap 'kill "$fixture_pid" 2>/dev/null || true' EXIT
sleep 1
set +e
xsscan --url 'http://127.0.0.1:18080/?q=test' --allow-private --types reflected \
  --verify-execution --max-payloads 1 --silent --output /tmp/container-report.json
code=$?
set -e
test "$code" -eq 2
cat /tmp/container-report.json
