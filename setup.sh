#!/bin/bash
# ==============================================================================
# stacksniff — Production Setup & Deployment Script
#
# Supports:  Debian / Ubuntu Linux (20.04+)
# Requires:  sudo / root
# Usage:     sudo bash setup.sh [--dir <install_path>] [--uninstall] [--help]
#
# Idempotent: safe to run multiple times on the same server.
# ==============================================================================

set -euo pipefail

# ------------------------------------------------------------------------------
# ANSI colour helpers
# ------------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log_info()    { echo -e "${BLUE}[INFO]${NC}    $1"; }
log_success() { echo -e "${GREEN}[OK]${NC}      $1"; }
log_warning() { echo -e "${YELLOW}[WARN]${NC}    $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC}   $1" >&2; }
log_step()    { echo -e "\n${CYAN}${BOLD}━━━  $1  ━━━${NC}"; }

# ------------------------------------------------------------------------------
# Global configuration defaults (overridable via --dir flag)
# ------------------------------------------------------------------------------
INSTALL_DIR="/opt/stacksniff"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Tunable resource values – set by tune_resources()
CELERY_WORKERS=2
MAX_BROWSERS=3
CACHE_TTL=1800
DETECTED_IP=""
API_TOKEN=""

# ------------------------------------------------------------------------------
# parse_args  — handle --dir, --uninstall, --help
# ------------------------------------------------------------------------------
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --dir)
                INSTALL_DIR="$2"
                shift 2
                ;;
            --uninstall)
                check_root
                uninstall
                exit 0
                ;;
            --help|-h)
                echo "Usage: sudo bash setup.sh [--dir <install_path>] [--uninstall] [--help]"
                echo ""
                echo "  --dir <path>   Install to <path> instead of /opt/stacksniff"
                echo "  --uninstall    Remove all installed components"
                echo "  --help         Show this message"
                exit 0
                ;;
            *)
                log_error "Unknown argument: $1"
                echo "Run with --help for usage."
                exit 1
                ;;
        esac
    done
}

# ------------------------------------------------------------------------------
# check_root  — abort early if not running as root
# ------------------------------------------------------------------------------
check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root or with sudo."
        log_error "Try: sudo bash setup.sh"
        exit 1
    fi
}

# ------------------------------------------------------------------------------
# tune_resources  — set CELERY_WORKERS and MAX_BROWSERS based on available RAM
# ------------------------------------------------------------------------------
tune_resources() {
    log_step "Resource tuning"

    local ram_mb=0
    if command -v free &>/dev/null; then
        ram_mb=$(free -m | awk '/^Mem:/{print $2}')
    fi

    if [ "$ram_mb" -lt 2048 ]; then
        CELERY_WORKERS=1
        MAX_BROWSERS=2
        log_warning "Low memory: ${ram_mb}MB RAM detected → workers=1, browsers=2"
    elif [ "$ram_mb" -lt 4096 ]; then
        CELERY_WORKERS=2
        MAX_BROWSERS=3
        log_info "Medium memory: ${ram_mb}MB RAM detected → workers=2, browsers=3"
    else
        CELERY_WORKERS=4
        MAX_BROWSERS=5
        log_info "High memory: ${ram_mb}MB RAM detected → workers=4, browsers=5"
    fi

    log_success "Tuned: CELERY_WORKERS=${CELERY_WORKERS}, MAX_BROWSERS=${MAX_BROWSERS}"
}

# ------------------------------------------------------------------------------
# install_system_deps  — idempotent apt + uv install
# ------------------------------------------------------------------------------
install_system_deps() {
    log_step "System dependencies"

    log_info "Running apt-get update..."
    apt-get update -qq

    log_info "Installing system packages..."
    apt-get install -y -qq \
        python3 \
        python3-venv \
        python3-pip \
        curl \
        git \
        redis-server \
        nginx \
        supervisor \
        rsync \
        apt-transport-https \
        ca-certificates

    # Install uv (Astral) — idempotent via command check
    if command -v uv &>/dev/null; then
        log_info "uv is already installed: $(uv --version)"
    else
        log_info "Installing Astral uv..."
        curl -LsSf https://astral.sh/uv/install.sh | sh
        # Source uv into PATH for the rest of this session
        export PATH="$HOME/.local/bin:$PATH"
        log_success "uv installed: $(uv --version)"
    fi

    # Make sure uv is on PATH even if it was already installed elsewhere
    export PATH="$HOME/.local/bin:/usr/local/bin:$PATH"
}

# ------------------------------------------------------------------------------
# setup_project  — copy sources, sync dependencies, install Playwright
# ------------------------------------------------------------------------------
setup_project() {
    log_step "Project setup"

    # Create install directories
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$INSTALL_DIR/stacksniff-api"

    # Sync sources only when running from a different directory (idempotent)
    if [ "$SCRIPT_DIR" != "$INSTALL_DIR" ]; then
        log_info "Syncing stacksniff library → $INSTALL_DIR/"
        rsync -av --delete \
            --exclude='.venv' \
            --exclude='__pycache__' \
            --exclude='*.pyc' \
            --exclude='.git' \
            --exclude='.pytest_cache' \
            --exclude='.mypy_cache' \
            --exclude='stacksniff-api' \
            "$SCRIPT_DIR/" "$INSTALL_DIR/"

        log_info "Syncing stacksniff-api → $INSTALL_DIR/stacksniff-api/"
        rsync -av --delete \
            --exclude='.venv' \
            --exclude='__pycache__' \
            --exclude='*.pyc' \
            --exclude='.git' \
            --exclude='.pytest_cache' \
            --exclude='db.sqlite3' \
            --exclude='staticfiles' \
            "$SCRIPT_DIR/stacksniff-api/" "$INSTALL_DIR/stacksniff-api/"
    fi

    # Sync scanner library venv
    log_info "Syncing stacksniff library dependencies..."
    cd "$INSTALL_DIR"
    uv sync

    # Sync API venv
    log_info "Syncing stacksniff-api dependencies..."
    cd "$INSTALL_DIR/stacksniff-api"
    uv sync

    # Install scanner library as editable into API venv
    log_info "Installing stacksniff as editable package in API venv..."
    uv pip install -e ../

    # Install production ASGI server
    log_info "Installing uvicorn + gevent in API venv..."
    uv pip install \
        "uvicorn[standard]>=0.30.0" \
        "uvicorn-worker>=0.3.0" \
        "gevent>=24.0.0"

    # Install Playwright chromium
    log_info "Installing Playwright Chromium browser..."
    cd "$INSTALL_DIR"
    uv run playwright install chromium

    log_info "Installing Playwright system dependencies..."
    uv run playwright install-deps chromium

    log_success "Project setup complete"
}

# ------------------------------------------------------------------------------
# configure_environment  — detect IP, write .env, migrate, collectstatic, tokens
# ------------------------------------------------------------------------------
configure_environment() {
    log_step "Environment configuration"

    # --- IP detection: four-level fallback chain ---
    log_info "Detecting server IP address..."

    # 1. ip addr
    DETECTED_IP=$(ip addr show 2>/dev/null \
        | grep 'inet ' \
        | grep -v '127.0.0.1' \
        | awk '{print $2}' \
        | cut -d/ -f1 \
        | head -1 || true)

    # 2. hostname -I
    if [ -z "$DETECTED_IP" ]; then
        DETECTED_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || true)
    fi

    # 3. External lookup (non-fatal)
    if [ -z "$DETECTED_IP" ]; then
        DETECTED_IP=$(curl -s --max-time 5 https://ipinfo.io/ip 2>/dev/null || true)
    fi

    # 4. Prompt user
    if [ -z "$DETECTED_IP" ]; then
        log_warning "Could not auto-detect server IP."
        read -rp "Enter server IP or domain name: " DETECTED_IP
        if [ -z "$DETECTED_IP" ]; then
            log_error "Server IP/domain is required."
            exit 1
        fi
    fi

    log_success "Server address: $DETECTED_IP"

    # --- Generate SECRET_KEY ---
    local secret_key
    secret_key=$(python3 -c "import secrets; print(secrets.token_urlsafe(50))")

    # --- Write .env (idempotent – always regenerated with fresh key) ---
    log_info "Writing $INSTALL_DIR/stacksniff-api/.env..."
    cat > "$INSTALL_DIR/stacksniff-api/.env" << EOF
DJANGO_SETTINGS_MODULE=config.settings.prod
SECRET_KEY=${secret_key}
ALLOWED_HOSTS=${DETECTED_IP},localhost,127.0.0.1
CORS_ALLOWED_ORIGINS=http://${DETECTED_IP}
REDIS_URL=redis://localhost:6379/0
CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/0
STACKSNIFF_MAX_BROWSERS=${MAX_BROWSERS}
STACKSNIFF_CACHE_TTL=${CACHE_TTL}
CELERY_POOL=gevent
CELERY_CONCURRENCY=10
EOF

    # --- Database migrations ---
    log_info "Running Django migrations..."
    cd "$INSTALL_DIR/stacksniff-api"
    uv run python manage.py migrate --noinput

    # --- Static files ---
    log_info "Collecting static files..."
    uv run python manage.py collectstatic --noinput --clear

    # --- Create admin user idempotently ---
    local admin_password
    admin_password=$(openssl rand -hex 10)

    local admin_status
    admin_status=$(uv run python -c "
import os, django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.prod')
django.setup()
from django.contrib.auth import get_user_model
User = get_user_model()
if not User.objects.filter(username='admin').exists():
    User.objects.create_superuser('admin', 'admin@localhost', '${admin_password}')
    print('CREATED')
else:
    print('EXISTS')
")

    if echo "$admin_status" | grep -q "CREATED"; then
        log_success "Admin user created (password: ${admin_password})"
        echo "  → Save this password — it won't be shown again"
    else
        log_info "Admin user already exists"
    fi

    # --- Generate/retrieve API token ---
    API_TOKEN=$(uv run python -c "
import os, django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.prod')
django.setup()
from django.contrib.auth import get_user_model
from rest_framework.authtoken.models import Token
User = get_user_model()
user = User.objects.get(username='admin')
token, _ = Token.objects.get_or_create(user=user)
print(token.key)
")

    # Save token securely
    echo "$API_TOKEN" > "$INSTALL_DIR/API_TOKEN.txt"
    chmod 600 "$INSTALL_DIR/API_TOKEN.txt"
    log_success "API token saved → $INSTALL_DIR/API_TOKEN.txt"
}

# ------------------------------------------------------------------------------
# configure_supervisor  — write stacksniff.conf and reload
# ------------------------------------------------------------------------------
configure_supervisor() {
    log_step "Supervisor configuration"

    mkdir -p /var/log/stacksniff

    local venv_bin="$INSTALL_DIR/stacksniff-api/.venv/bin"

    cat > /etc/supervisor/conf.d/stacksniff.conf << EOF
[program:stacksniff-api]
command=${venv_bin}/gunicorn config.asgi:application \
    --worker-class uvicorn.workers.UvicornWorker \
    --workers ${CELERY_WORKERS} \
    --bind 127.0.0.1:8000 \
    --timeout 120 \
    --graceful-timeout 30
directory=${INSTALL_DIR}/stacksniff-api
environment=PATH="${venv_bin}:%(ENV_PATH)s",DJANGO_SETTINGS_MODULE="config.settings.prod"
user=root
autostart=true
autorestart=true
startretries=5
stderr_logfile=/var/log/stacksniff/api.err.log
stdout_logfile=/var/log/stacksniff/api.out.log

[program:stacksniff-celery]
command=${venv_bin}/celery -A config worker \
    --pool=gevent \
    --concurrency=10 \
    --loglevel=info \
    --without-gossip \
    --without-mingle
directory=${INSTALL_DIR}/stacksniff-api
environment=PATH="${venv_bin}:%(ENV_PATH)s",DJANGO_SETTINGS_MODULE="config.settings.prod"
user=root
autostart=true
autorestart=true
startretries=5
stopwaitsecs=120
stderr_logfile=/var/log/stacksniff/celery.err.log
stdout_logfile=/var/log/stacksniff/celery.out.log
EOF

    supervisorctl reread
    supervisorctl update
    log_success "Supervisor config written and reloaded"
}

# ------------------------------------------------------------------------------
# configure_nginx  — write site config, enable, reload
# ------------------------------------------------------------------------------
configure_nginx() {
    log_step "Nginx configuration"

    cat > /etc/nginx/sites-available/stacksniff << EOF
# Rate limiting zone — shared memory, 10MB for IP tracking, 30 req/min
limit_req_zone \$binary_remote_addr zone=api:10m rate=30r/m;

server {
    listen 80;
    server_name ${DETECTED_IP};

    client_max_body_size 1M;

    # --- API — rate-limited ---
    location /api/ {
        limit_req zone=api burst=10 nodelay;

        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_read_timeout    300;
        proxy_connect_timeout  10;
        proxy_send_timeout    300;
    }

    # --- Static files — long-lived cache ---
    location /static/ {
        alias ${INSTALL_DIR}/stacksniff-api/staticfiles/;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }

    # --- Catch-all → Django (dashboard, admin, etc.) ---
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_read_timeout 300;
    }
}
EOF

    # Enable site, remove default
    ln -sf /etc/nginx/sites-available/stacksniff \
           /etc/nginx/sites-enabled/stacksniff
    rm -f /etc/nginx/sites-enabled/default

    # Validate and reload
    nginx -t
    systemctl reload nginx
    log_success "Nginx configured and reloaded"
}

# ------------------------------------------------------------------------------
# start_services  — enable and start all daemons
# ------------------------------------------------------------------------------
start_services() {
    log_step "Starting services"

    systemctl enable redis-server nginx supervisor

    # Redis — start or restart if already running
    systemctl restart redis-server
    log_success "Redis started"

    # Supervisor (manages api + celery)
    supervisorctl start stacksniff-api stacksniff-celery || \
        supervisorctl restart stacksniff-api stacksniff-celery || true

    log_info "Waiting 10 seconds for services to stabilise..."
    sleep 10
}

# ------------------------------------------------------------------------------
# verify_health  — curl /api/health/ and check supervisor/redis
# ------------------------------------------------------------------------------
verify_health() {
    log_step "Health verification"

    # --- API health endpoint ---
    log_info "Checking API health endpoint..."
    local health_response
    health_response=$(curl -s --max-time 10 "http://127.0.0.1:8000/api/health/" || echo '{"status":"error"}')

    local api_status
    api_status=$(echo "$health_response" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print(d.get('status', 'unknown'))
except Exception:
    print('parse_error')
" 2>/dev/null || echo "parse_error")

    if [ "$api_status" = "ok" ]; then
        log_success "API health: ok"
    else
        log_warning "API health: ${api_status}"
        log_warning "Health response: $health_response"
        log_warning "Dumping recent logs..."
        echo "=== API error log (last 20 lines) ==="
        tail -n 20 /var/log/stacksniff/api.err.log 2>/dev/null || true
        echo "=== Celery error log (last 20 lines) ==="
        tail -n 20 /var/log/stacksniff/celery.err.log 2>/dev/null || true
        # Warn but don't fail — Celery worker may still be starting
        log_warning "API may still be initialising. Check logs above."
    fi

    # --- Supervisor process status ---
    log_info "Supervisor process status:"
    supervisorctl status stacksniff-api stacksniff-celery || true

    # --- Redis connectivity ---
    log_info "Checking Redis..."
    if command -v redis-cli &>/dev/null; then
        if redis-cli ping 2>/dev/null | grep -q "PONG"; then
            log_success "Redis: PONG"
        else
            log_warning "Redis ping failed — check redis-server status"
        fi
    elif command -v nc &>/dev/null; then
        if nc -z localhost 6379 2>/dev/null; then
            log_success "Redis: port 6379 open"
        else
            log_warning "Redis port 6379 not reachable"
        fi
    fi
}

# ------------------------------------------------------------------------------
# print_summary  — final coloured box with all deployment details
# ------------------------------------------------------------------------------
print_summary() {
    local token="${API_TOKEN:-$(cat "$INSTALL_DIR/API_TOKEN.txt" 2>/dev/null || echo '<see API_TOKEN.txt>')}"
    local ip="${DETECTED_IP:-<server-ip>}"

    echo ""
    echo -e "${GREEN}${BOLD}"
    echo "  ╔══════════════════════════════════════════════════════════════╗"
    echo "  ║           stacksniff — deployment complete ✓                ║"
    echo "  ╠══════════════════════════════════════════════════════════════╣"
    printf "  ║  Dashboard:     http://%-38s║\n" "${ip}/"
    printf "  ║  API Base:      http://%-38s║\n" "${ip}/api/"
    printf "  ║  Health check:  http://%-38s║\n" "${ip}/api/health/"
    echo "  ╠══════════════════════════════════════════════════════════════╣"
    printf "  ║  Auth token:    %-45s║\n" "${token:0:45}"
    printf "  ║  Token file:    %-45s║\n" "${INSTALL_DIR}/API_TOKEN.txt"
    echo "  ╠══════════════════════════════════════════════════════════════╣"
    echo "  ║  Frontend team — include in every request:                  ║"
    printf "  ║  Authorization: Token %-39s║\n" "${token:0:39}"
    echo "  ╠══════════════════════════════════════════════════════════════╣"
    echo "  ║  Quick test (no auth):                                      ║"
    printf "  ║  curl http://%-48s║\n" "${ip}/api/health/"
    echo "  ╠══════════════════════════════════════════════════════════════╣"
    echo "  ║  Scan shortcuts (POST, requires auth):                      ║"
    echo "  ║  /api/scan/tech/        tech stack only        (~30s)       ║"
    echo "  ║  /api/scan/full/        everything             (~90s)       ║"
    echo "  ║  /api/scan/endpoints/   API endpoints only     (~40s)       ║"
    echo "  ║  /api/scan/subdomains/  subdomains only        (~30s)       ║"
    echo "  ╠══════════════════════════════════════════════════════════════╣"
    printf "  ║  Logs:   %-52s║\n" "/var/log/stacksniff/"
    echo "  ║  Status: supervisorctl status                               ║"
    echo "  ╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    echo -e "${CYAN}Copy-paste quick test:${NC}"
    echo ""
    echo "  curl -s http://${ip}/api/health/ | python3 -m json.tool"
    echo ""
    echo "  TOKEN=\$(cat ${INSTALL_DIR}/API_TOKEN.txt)"
    echo "  curl -s -X POST http://${ip}/api/scan/tech/ \\"
    echo "       -H \"Authorization: Token \$TOKEN\" \\"
    echo "       -H \"Content-Type: application/json\" \\"
    echo "       -d '{\"url\": \"https://example.com\"}' | python3 -m json.tool"
    echo ""
}

# ------------------------------------------------------------------------------
# uninstall  — remove all components, idempotent
# ------------------------------------------------------------------------------
uninstall() {
    log_step "Uninstalling stacksniff"

    log_info "Stopping Supervisor programs..."
    supervisorctl stop stacksniff-api stacksniff-celery 2>/dev/null || true
    rm -f /etc/supervisor/conf.d/stacksniff.conf
    supervisorctl reread 2>/dev/null || true
    supervisorctl update 2>/dev/null || true

    log_info "Removing Nginx configuration..."
    rm -f /etc/nginx/sites-enabled/stacksniff
    rm -f /etc/nginx/sites-available/stacksniff
    systemctl reload nginx 2>/dev/null || true

    log_info "Removing install directory: $INSTALL_DIR"
    rm -rf "$INSTALL_DIR"

    log_info "Removing log directory: /var/log/stacksniff"
    rm -rf /var/log/stacksniff

    log_success "Uninstall complete"
}

# ==============================================================================
# MAIN
# ==============================================================================
main() {
    parse_args "$@"
    check_root
    tune_resources
    install_system_deps
    setup_project
    configure_environment
    configure_supervisor
    configure_nginx
    start_services
    verify_health
    print_summary
}

main "$@"
