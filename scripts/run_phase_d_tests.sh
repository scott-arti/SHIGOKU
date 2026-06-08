#!/bin/bash
# Run Phase D Integration Tests
# Usage: ./scripts/run_phase_d_tests.sh [test_pattern]

set -e

echo "========================================"
echo "SHIGOKU Phase D Integration Tests"
echo "========================================"

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "Error: Docker is not running"
    exit 1
fi

# Start infrastructure
echo "[1/4] Starting infrastructure (Redis)..."
docker-compose -f docker-compose.phase-d.yml up -d redis

# Wait for Redis
sleep 2

# Check Redis health
echo "[2/4] Checking Redis health..."
docker-compose -f docker-compose.phase-d.yml exec -T redis redis-cli ping || {
    echo "Error: Redis health check failed"
    exit 1
}

# Run tests
echo "[3/4] Running integration tests..."
TEST_PATTERN="${1:-tests/integration/test_phase_d_implementation.py}"
docker-compose -f docker-compose.phase-d.yml run --rm test pytest "$TEST_PATTERN" -v --tb=short

# Cleanup
echo "[4/4] Cleaning up..."
docker-compose -f docker-compose.phase-d.yml down

echo ""
echo "========================================"
echo "Phase D Tests Complete"
echo "========================================"
