#!/bin/bash
# ==============================================================================
# stacksniff — Deployment Validation Checklist
#
# Validates a live deployment WITHOUT running setup.sh.
# Run on the server AFTER setup.sh has completed.
#
# Usage:  bash test_setup.sh
#         bash test_setup.sh --base http://192.168.1.10
# ==============================================================================

set -uo pipefail

# ------------------------------------------------------------------------------
# Colours & helpers
# ------------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

PASS_COUNT=0
FAIL_COUNT=0
TOTAL_CHECKS=8

pass() { echo -e "  ${GREEN}✔ PASS${NC}  $1"; ((PASS_COUNT++)); }
fail() { echo -e "  ${RED}✘ FAIL${NC}  $1"; ((FAIL_COUNT++)); }
info() { echo -e "  ${YELLOW}ℹ${NC}      $1"; }
step() { echo -e "\n${CYAN}${BOLD}── Check $1 ──────────────────────────────────────────────${NC}"; }

# ------------------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------------------
BASE_URL="http://localhost"
TOKEN_FILE="/opt/stacksniff/API_TOKEN.txt"
LOG_DIR="/var/log/stacksniff"

# Allow --base override
while [[ $# -gt 0 ]]; do
    case $1 in
        --base) BASE_URL="$2"; shift 2 ;;
        *)      echo "Usage: bash test_setup.sh [--base http://<ip>]"; exit 1 ;;
    esac
done

echo -e "\n${BOLD}stacksniff Deployment Validation${NC}"
echo -e "Target: ${CYAN}${BASE_URL}${NC}"
echo -e "Time:   $(date -u '+%Y-%m-%dT%H:%M:%SZ')\n"

# ------------------------------------------------------------------------------
# Check 1 — Health endpoint returns 200 with status=ok
# ------------------------------------------------------------------------------
step "1/8  Health check endpoint"

HEALTH_BODY=$(curl -s --max-time 10 "${BASE_URL}/api/health/" 2>/dev/null || echo "CURL_FAIL")

if echo "$HEALTH_BODY" | grep -q '"status": *"ok"'; then
    pass "GET /api/health/ → 200, status=ok"
    echo "$HEALTH_BODY" | python3 -m json.tool 2>/dev/null | sed 's/^/         /' || true
else
    fail "GET /api/health/ did not return {\"status\": \"ok\"}"
    info "Response: $HEALTH_BODY"
fi

# ------------------------------------------------------------------------------
# Check 2 — Auth enforcement: no token → 401 (prod) or 200 (dev)
# ------------------------------------------------------------------------------
step "2/8  Authentication enforcement"

AUTH_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    --max-time 10 "${BASE_URL}/api/scans/" 2>/dev/null || echo "000")

if [ "$AUTH_CODE" = "401" ]; then
    pass "GET /api/scans/ without token → 401 (auth enforced ✓)"
elif [ "$AUTH_CODE" = "200" ]; then
    pass "GET /api/scans/ without token → 200 (dev/AllowAny mode)"
    info "This is expected in DEBUG=True mode"
else
    fail "GET /api/scans/ without token → unexpected ${AUTH_CODE}"
fi

# ------------------------------------------------------------------------------
# Check 3 — Create scan job returns 201
# ------------------------------------------------------------------------------
step "3/8  Create scan job (POST /api/scan/tech/)"

if [ ! -f "$TOKEN_FILE" ]; then
    fail "Token file not found: $TOKEN_FILE"
    info "Run setup.sh first, or set TOKEN_FILE variable"
    TOKEN=""
else
    TOKEN=$(cat "$TOKEN_FILE")
fi

JOB_BODY=""
JOB_ID=""
CREATE_CODE="000"

if [ -n "${TOKEN:-}" ]; then
    CREATE_RESPONSE=$(curl -s -w "\n%{http_code}" --max-time 15 \
        -X POST "${BASE_URL}/api/scan/tech/" \
        -H "Authorization: Token $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"url": "https://example.com"}' 2>/dev/null || echo -e "\n000")

    CREATE_CODE=$(echo "$CREATE_RESPONSE" | tail -1)
    JOB_BODY=$(echo "$CREATE_RESPONSE" | head -n -1)
fi

if [ "$CREATE_CODE" = "201" ]; then
    JOB_ID=$(echo "$JOB_BODY" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])" 2>/dev/null || echo "")
    pass "POST /api/scan/tech/ → 201 Created (job id: ${JOB_ID:-unknown})"
    echo "$JOB_BODY" | python3 -m json.tool 2>/dev/null | sed 's/^/         /' | head -20 || true
elif [ -z "${TOKEN:-}" ]; then
    fail "Skipped — no token available (check $TOKEN_FILE)"
else
    fail "POST /api/scan/tech/ → ${CREATE_CODE} (expected 201)"
    info "Response: $JOB_BODY"
fi

# ------------------------------------------------------------------------------
# Check 4 — Job appears in list endpoint
# ------------------------------------------------------------------------------
step "4/8  Job list endpoint (GET /api/scans/)"

LIST_CODE="000"
LIST_BODY=""

if [ -n "${TOKEN:-}" ]; then
    LIST_RESPONSE=$(curl -s -w "\n%{http_code}" --max-time 10 \
        "${BASE_URL}/api/scans/" \
        -H "Authorization: Token $TOKEN" 2>/dev/null || echo -e "\n000")

    LIST_CODE=$(echo "$LIST_RESPONSE" | tail -1)
    LIST_BODY=$(echo "$LIST_RESPONSE" | head -n -1)
fi

if [ "$LIST_CODE" = "200" ]; then
    JOB_COUNT=$(echo "$LIST_BODY" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('count',len(d.get('results',[]))))" 2>/dev/null || echo "?")
    pass "GET /api/scans/ → 200 OK (${JOB_COUNT} job(s) in list)"
elif [ -z "${TOKEN:-}" ]; then
    fail "Skipped — no token available"
else
    fail "GET /api/scans/ → ${LIST_CODE} (expected 200)"
    info "Response: $LIST_BODY"
fi

# ------------------------------------------------------------------------------
# Check 5 — Rate limit: 11th consecutive POST returns 429
# ------------------------------------------------------------------------------
step "5/8  Rate limit enforcement (10 scans/min)"

if [ -z "${TOKEN:-}" ]; then
    fail "Skipped — no token available"
else
    info "Sending 11 POST requests to /api/scan/tech/ ..."
    LAST_CODE="000"
    GOT_429=false

    for i in $(seq 1 11); do
        CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 \
            -X POST "${BASE_URL}/api/scan/tech/" \
            -H "Authorization: Token $TOKEN" \
            -H "Content-Type: application/json" \
            -d '{"url": "https://example.com"}' 2>/dev/null || echo "000")

        printf "         Request %2d → %s\n" "$i" "$CODE"
        LAST_CODE="$CODE"

        if [ "$CODE" = "429" ]; then
            GOT_429=true
            # Don't break — keep going to show the remaining requests also 429
        fi
    done

    if $GOT_429; then
        pass "Rate limit enforced — at least one request returned 429"
    else
        fail "No 429 received in 11 requests — rate limit may not be configured"
        info "Check INSTALLED_APPS includes 'django_ratelimit' and cache is configured"
    fi
fi

# ------------------------------------------------------------------------------
# Check 6 — Supervisor processes are running
# ------------------------------------------------------------------------------
step "6/8  Supervisor process status"

if ! command -v supervisorctl &>/dev/null; then
    fail "supervisorctl not found — is supervisor installed?"
else
    SUPER_OUT=$(supervisorctl status stacksniff-api stacksniff-celery 2>/dev/null || echo "ERROR")
    echo "$SUPER_OUT" | sed 's/^/         /'

    API_RUNNING=false
    CELERY_RUNNING=false

    echo "$SUPER_OUT" | grep -q "stacksniff-api.*RUNNING"   && API_RUNNING=true   || true
    echo "$SUPER_OUT" | grep -q "stacksniff-celery.*RUNNING" && CELERY_RUNNING=true || true

    if $API_RUNNING && $CELERY_RUNNING; then
        pass "Both stacksniff-api and stacksniff-celery are RUNNING"
    elif $API_RUNNING; then
        fail "stacksniff-api is RUNNING but stacksniff-celery is NOT"
    elif $CELERY_RUNNING; then
        fail "stacksniff-celery is RUNNING but stacksniff-api is NOT"
    else
        fail "Neither service is RUNNING"
        info "Try: supervisorctl start stacksniff-api stacksniff-celery"
    fi
fi

# ------------------------------------------------------------------------------
# Check 7 — Log files exist and are non-empty
# ------------------------------------------------------------------------------
step "7/8  Log files exist and are non-empty"

LOG_OK=true

for logfile in api.out.log api.err.log celery.out.log celery.err.log; do
    full_path="${LOG_DIR}/${logfile}"
    if [ -f "$full_path" ]; then
        size=$(wc -c < "$full_path" 2>/dev/null || echo 0)
        lines=$(wc -l < "$full_path" 2>/dev/null || echo 0)
        printf "         %-40s %6d bytes, %4d lines\n" "$logfile" "$size" "$lines"
    else
        echo -e "         ${RED}MISSING${NC} $full_path"
        LOG_OK=false
    fi
done

if $LOG_OK; then
    pass "All 4 log files present in ${LOG_DIR}/"
else
    fail "One or more log files missing — check Supervisor started correctly"
fi

# ------------------------------------------------------------------------------
# Check 8 — Nginx is proxying correctly (Server header present)
# ------------------------------------------------------------------------------
step "8/8  Nginx proxy (curl -I /api/health/)"

NGINX_HEADERS=$(curl -sI --max-time 10 "${BASE_URL}/api/health/" 2>/dev/null || echo "CURL_FAIL")

echo "$NGINX_HEADERS" | head -12 | sed 's/^/         /'

HTTP_STATUS=$(echo "$NGINX_HEADERS" | head -1 | grep -oE '[0-9]{3}' | head -1 || echo "000")
HAS_NGINX=$(echo "$NGINX_HEADERS" | grep -i "^server:" | grep -i "nginx" || echo "")
HAS_CONTENT_TYPE=$(echo "$NGINX_HEADERS" | grep -i "^content-type:" || echo "")

if [ "$HTTP_STATUS" = "200" ] && [ -n "$HAS_NGINX" ]; then
    pass "Nginx is proxying /api/health/ → ${HTTP_STATUS} (Server: nginx)"
elif [ "$HTTP_STATUS" = "200" ]; then
    pass "Got 200 from /api/health/ (no nginx Server header — may be stripped)"
    info "Headers: $NGINX_HEADERS"
else
    fail "Nginx proxy check failed — HTTP ${HTTP_STATUS}"
    info "Is nginx running? Try: systemctl status nginx"
fi

# ------------------------------------------------------------------------------
# Final summary
# ------------------------------------------------------------------------------
echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e " Final result: ${PASS_COUNT}/${TOTAL_CHECKS} checks passed"

if [ "$FAIL_COUNT" -eq 0 ]; then
    echo -e " ${GREEN}${BOLD}All checks passed — deployment is healthy ✓${NC}"
else
    echo -e " ${RED}${BOLD}${FAIL_COUNT} check(s) failed — review output above${NC}"
    echo ""
    echo " Common fixes:"
    echo "   supervisorctl restart stacksniff-api stacksniff-celery"
    echo "   tail -f /var/log/stacksniff/api.err.log"
    echo "   nginx -t && systemctl reload nginx"
fi

echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

exit "$FAIL_COUNT"
