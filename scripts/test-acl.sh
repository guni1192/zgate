#!/bin/bash
set -e

echo "=== Phase 3.2: ACL E2E Test ==="
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test result tracking
TESTS_PASSED=0
TESTS_FAILED=0

# Helper function to print test results
print_result() {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}✓ PASS${NC}: $2"
        ((TESTS_PASSED++))
    else
        echo -e "${RED}✗ FAIL${NC}: $2"
        ((TESTS_FAILED++))
    fi
}

echo "Starting zgate environment..."
docker compose up -d --build
sleep 5

echo ""
echo "=== Test 1: client-1 (Restricted Access) ==="
echo ""

# Test 1.1: client-1 can access 8.8.8.8 (allowed)
echo "Test 1.1: client-1 -> 8.8.8.8 (DNS - should ALLOW)"
if docker compose exec -T agent-1 ping -c 2 -W 3 8.8.8.8 > /dev/null 2>&1; then
    print_result 0 "client-1 can reach 8.8.8.8 (allowed by ACL)"
else
    print_result 1 "client-1 cannot reach 8.8.8.8 (should be allowed)"
fi

# Test 1.2: client-1 can access 1.1.1.1 (allowed)
echo "Test 1.2: client-1 -> 1.1.1.1 (DNS - should ALLOW)"
if docker compose exec -T agent-1 ping -c 2 -W 3 1.1.1.1 > /dev/null 2>&1; then
    print_result 0 "client-1 can reach 1.1.1.1 (allowed by ACL)"
else
    print_result 1 "client-1 cannot reach 1.1.1.1 (should be allowed)"
fi

# Test 1.3: client-1 cannot access 8.8.4.4 (denied)
echo "Test 1.3: client-1 -> 8.8.4.4 (should DENY)"
if docker compose exec -T agent-1 ping -c 2 -W 3 8.8.4.4 > /dev/null 2>&1; then
    print_result 1 "client-1 can reach 8.8.4.4 (should be denied)"
else
    print_result 0 "client-1 cannot reach 8.8.4.4 (correctly denied by ACL)"
fi

echo ""
echo "=== Test 2: client-2 (Full Access) ==="
echo ""

# Test 2.1: client-2 can access 8.8.8.8 (allowed)
echo "Test 2.1: client-2 -> 8.8.8.8 (should ALLOW)"
if docker compose exec -T agent-2 ping -c 2 -W 3 8.8.8.8 > /dev/null 2>&1; then
    print_result 0 "client-2 can reach 8.8.8.8 (allowed by ACL)"
else
    print_result 1 "client-2 cannot reach 8.8.8.8 (should be allowed)"
fi

# Test 2.2: client-2 can access 1.1.1.1 (allowed)
echo "Test 2.2: client-2 -> 1.1.1.1 (should ALLOW)"
if docker compose exec -T agent-2 ping -c 2 -W 3 1.1.1.1 > /dev/null 2>&1; then
    print_result 0 "client-2 can reach 1.1.1.1 (allowed by ACL)"
else
    print_result 1 "client-2 cannot reach 1.1.1.1 (should be allowed)"
fi

# Test 2.3: client-2 can access 8.8.4.4 (allowed - full access)
echo "Test 2.3: client-2 -> 8.8.4.4 (should ALLOW)"
if docker compose exec -T agent-2 ping -c 2 -W 3 8.8.4.4 > /dev/null 2>&1; then
    print_result 0 "client-2 can reach 8.8.4.4 (full access via 0.0.0.0/0)"
else
    print_result 1 "client-2 cannot reach 8.8.4.4 (should be allowed)"
fi

echo ""
echo "=== Test 3: Audit Logs Verification ==="
echo ""

# Check for ACL allow/deny events in relay logs
echo "Checking relay audit logs for ACL events..."
ACL_ALLOW_COUNT=$(docker compose logs relay 2>/dev/null | grep -c '"event_type":"acl.allow"' || true)
ACL_DENY_COUNT=$(docker compose logs relay 2>/dev/null | grep -c '"event_type":"acl.deny"' || true)

echo "ACL Allow events: $ACL_ALLOW_COUNT"
echo "ACL Deny events: $ACL_DENY_COUNT"

if [ $ACL_ALLOW_COUNT -gt 0 ]; then
    print_result 0 "Found ACL allow events in audit logs"
else
    print_result 1 "No ACL allow events found (expected some)"
fi

if [ $ACL_DENY_COUNT -gt 0 ]; then
    print_result 0 "Found ACL deny events in audit logs"
else
    print_result 1 "No ACL deny events found (expected some from client-1)"
fi

echo ""
echo "=== Test Summary ==="
echo -e "Tests Passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Tests Failed: ${RED}$TESTS_FAILED${NC}"
echo ""

# Show sample audit logs
echo "=== Sample Audit Logs ==="
docker compose logs relay 2>/dev/null | grep '"event_type":"acl' | head -10 || echo "No ACL audit logs found"

echo ""
echo "Stopping environment..."
docker compose down

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}All ACL tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some ACL tests failed!${NC}"
    exit 1
fi
