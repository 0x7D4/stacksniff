#!/bin/bash
# ==============================================================================
# stacksniff — Production Setup & Deployment Script
# Supports: Debian / Ubuntu Linux
# Enforces: set -euo pipefail, idempotency, RAM-based resource auto-tuning,
#           robust offline IP detection, and clean uninstallation.
# ==============================================================================

set -euo pipefail

# ANSI color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# ==============================================================================
# CONFIGURATION (Editable defaults)
# ==============================================================================
INSTALL_DIR="/opt/stacksniff"
ALLOWED_HOSTS=""       # Leave empty to auto-detect server IP/domain
MAX_BROWSERS=3
CACHE_TTL=1800
CELERY_WORKERS=2

# Get current script folder
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ==============================================================================
# FUNCTIONS
# ==============================================================================

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --dir)
                INSTALL_DIR="$2"
                shift 2
                ;;
            --uninstall)
                run_uninstall
                exit 0
                ;;
            *)
                log_error "Unknown argument: $1"
                echo "Usage: sudo bash setup.sh [--dir <install_path>] [--uninstall]"
                exit 1
                ;;
        esac
    done
}

# Verify running with root/sudo privileges
check_privileges() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root or with sudo."
        exit 1
    fi
}

# Auto-tune resource parameters for smaller VPS (less than 2GB RAM)
tune_resources() {
    if [ -f /proc/meminfo ]; then
        TOTAL_RAM_MB=$(free -m | awk '/^Mem:/{print $2}')
        if [ -n "$TOTAL_RAM_MB" ] && [ "$TOTAL_RAM_MB" -lt 2048 ]; then
            log_warning "Low memory detected (${TOTAL_RAM_MB}MB RAM). Automatically clamping Celery workers and BrowserPool to prevent OOM."
            CELERY_WORKERS=1
            MAX_BROWSERS=2
        fi
    fi
}

# Install core system dependencies
install_dependencies() {
    log_info "Installing system dependencies..."
    apt-get update

    # Ensure apt-transport-https is available
    apt-get install -y apt-transport-https ca-certificates gnupg

    # Install Python 3.12, Redis, Nginx, and Supervisor
    apt-get install -y \
        python3.12 \
        python3.12-pip \
        python3.12-venv \
        curl \
        git \
        redis-server \
        nginx \
        supervisor \
        rsync

    # Install Astral uv globally if not already present
    if ! command -v uv &> /dev/null; then
        log_info "Installing Astral uv..."
        curl -LsSf https://astral.sh/uv/install.sh | sh
        # Ensure uv path is exported for the active shell
        export PATH="$HOME/.local/bin:$PATH"
    else
        log_info "Astral uv is already installed."
    fi
}

# Scaffolding project directories and local virtual environments
setup_project_directories() {
    log_info "Setting up project directory structure at: $INSTALL_DIR..."
    mkdir -p "$INSTALL_DIR/stacksniff"
    mkdir -p "$INSTALL_DIR/stacksniff-api"

    # Copy repository files to the installation path if not already running there
    if [ "$SCRIPT_DIR" != "$INSTALL_DIR" ]; then
        log_info "Copying project source files..."
        if [ -d "$SCRIPT_DIR/stacksniff-api" ]; then
            cp -r "$SCRIPT_DIR/stacksniff-api/." "$INSTALL_DIR/stacksniff-api/"
        fi
        
        # Copy core stacksniff engine package
        if command -v rsync &> /dev/null; then
            rsync -a \
                --exclude='stacksniff-api' \
                --exclude='.venv' \
                --exclude='.git' \
                --exclude='.pytest_cache' \
                --exclude='.mypy_cache' \
                --exclude='db.sqlite3' \
                "$SCRIPT_DIR/" "$INSTALL_DIR/stacksniff/"
        else
            cp -r "$SCRIPT_DIR/pyproject.toml" "$SCRIPT_DIR/src" "$SCRIPT_DIR/README.md" "$INSTALL_DIR/stacksniff/" || true
        fi
    fi

    # Sync and build python dependencies inside stacksniff-api
    log_info "Installing python dependencies and building virtual environments..."
    cd "$INSTALL_DIR/stacksniff-api"
    
    # Run uv sync to scaffold api environment
    uv sync

    # Install stacksniff engine as editable package inside the API virtualenv
    uv pip install -e ../stacksniff/

    # Install gunicorn for production Django execution
    uv pip install gunicorn

    # Install Playwright browser and system dependencies
    log_info "Installing Playwright chromium browser binaries..."
    uv run playwright install chromium
    
    log_info "Installing Playwright system dependencies..."
    uv run playwright install-deps chromium
}

# Resolve and write environment configuration
configure_environment() {
    log_info "Resolving system network IP address..."
    
    DETECTED_IP=""
    
    # 1. Try local IP command
    if command -v ip &> /dev/null; then
        DETECTED_IP=$(ip addr show | grep 'inet ' | grep -v '127.0.0.1' | awk '{print $2}' | cut -d/ -f1 | head -1)
    fi
    
    # 2. Try hostname command
    if [ -z "$DETECTED_IP" ] && command -v hostname &> /dev/null; then
        DETECTED_IP=$(hostname -I | awk '{print $1}')
    fi
    
    # 3. Try external check IP service
    if [ -z "$DETECTED_IP" ]; then
        DETECTED_IP=$(curl -s --max-time 5 https://ipinfo.io/ip || echo "")
    fi

    # Bind host IP if empty
    if [ -z "${ALLOWED_HOSTS:-}" ]; then
        if [ -n "$DETECTED_IP" ]; then
            ALLOWED_HOSTS="$DETECTED_IP"
            log_info "Auto-detected server host IP: $ALLOWED_HOSTS"
        else
            log_warning "Could not auto-detect server IP."
            read -p "Please enter ALLOWED_HOSTS (IP address or domain name): " ALLOWED_HOSTS
            if [ -z "$ALLOWED_HOSTS" ]; then
                log_error "ALLOWED_HOSTS configuration is required."
                exit 1
            fi
        fi
    fi

    log_info "Generating environment file .env..."
    SECRET_KEY=$(openssl rand -base64 38 | tr -d '\n' | head -c 50)
    
    cat <<EOF > "$INSTALL_DIR/stacksniff-api/.env"
DJANGO_SETTINGS_MODULE=config.settings.prod
SECRET_KEY=$SECRET_KEY
ALLOWED_HOSTS=$ALLOWED_HOSTS
REDIS_URL=redis://localhost:6379/0
CELERY_BROKER_URL=redis://localhost:6379/0
STACKSNIFF_MAX_BROWSERS=$MAX_BROWSERS
STACKSNIFF_CACHE_TTL=$CACHE_TTL
EOF

    log_info "Running Django database migrations..."
    cd "$INSTALL_DIR/stacksniff-api"
    uv run python manage.py migrate --noinput

    log_info "Creating default superuser admin idempotently..."
    ADMIN_PASSWORD=$(openssl rand -hex 8)
    
    uv run python manage.py shell -c "
from django.contrib.auth import get_user_model
User = get_user_model()
if not User.objects.filter(username='admin').exists():
    User.objects.create_superuser('admin', 'admin@localhost', '$ADMIN_PASSWORD')
    print('CREATED')
else:
    print('EXISTS')
" > /tmp/admin_status.log

    # Extract or generate token
    log_info "Generating/retrieving API token for admin user..."
    ADMIN_TOKEN=$(uv run python manage.py shell -c "
from django.contrib.auth import get_user_model
from rest_framework.authtoken.models import Token
User = get_user_model()
u = User.objects.get(username='admin')
token, _ = Token.objects.get_or_create(user=u)
print(token.key)
")

    # Securely save API token
    echo "$ADMIN_TOKEN" > "$INSTALL_DIR/API_TOKEN.txt"
    chmod 600 "$INSTALL_DIR/API_TOKEN.txt"

    # Display credentials if newly created
    if grep -q "CREATED" /tmp/admin_status.log; then
        log_success "Superuser 'admin' created with password: $ADMIN_PASSWORD"
    else
        log_info "Superuser 'admin' already exists. Re-using existing credentials."
    fi
    rm -f /tmp/admin_status.log
}

# Set up Supervisor services
configure_supervisor() {
    log_info "Configuring Supervisor process control..."
    
    # Create logs path
    mkdir -p /var/log/stacksniff

    cat <<EOF > /etc/supervisor/conf.d/stacksniff.conf
[program:stacksniff-django]
command=$INSTALL_DIR/stacksniff-api/.venv/bin/gunicorn config.wsgi:application --bind 127.0.0.1:8000 --workers 4
directory=$INSTALL_DIR/stacksniff-api
autostart=true
autorestart=true
stderr_logfile=/var/log/stacksniff/django.err.log
stdout_logfile=/var/log/stacksniff/django.out.log

[program:stacksniff-celery]
command=$INSTALL_DIR/stacksniff-api/.venv/bin/celery -A config worker --loglevel=info --concurrency=$CELERY_WORKERS
directory=$INSTALL_DIR/stacksniff-api
autostart=true
autorestart=true
stderr_logfile=/var/log/stacksniff/celery.err.log
stdout_logfile=/var/log/stacksniff/celery.out.log
environment=DISPLAY=":99"

[program:stacksniff-redis]
command=redis-server
autostart=true
autorestart=true
stderr_logfile=/var/log/stacksniff/redis.err.log
stdout_logfile=/var/log/stacksniff/redis.out.log
EOF
}

# Set up Nginx reverse proxy
configure_nginx() {
    log_info "Configuring Nginx reverse-proxy virtualhost..."
    
    cat <<EOF > /etc/nginx/sites-available/stacksniff
server {
    listen 80;
    server_name $ALLOWED_HOSTS;
    
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_read_timeout 300;
        proxy_connect_timeout 300;
    }
    
    location /static/ {
        alias $INSTALL_DIR/stacksniff-api/staticfiles/;
    }
}
EOF

    # Symlink to sites-enabled
    ln -sf /etc/nginx/sites-available/stacksniff /etc/nginx/sites-enabled/stacksniff
    
    # Remove default site
    rm -f /etc/nginx/sites-enabled/default

    # Run Django collectstatic
    log_info "Collecting Django admin static files..."
    cd "$INSTALL_DIR/stacksniff-api"
    uv run python manage.py collectstatic --noinput
}

# Start all daemon services
start_services() {
    log_info "Starting daemon services and process managers..."

    systemctl daemon-reload
    
    # Start and enable core system services
    systemctl restart redis-server || true
    systemctl enable redis-server || true
    
    # Reread and update Supervisor configs
    supervisorctl reread
    supervisorctl update
    supervisorctl restart all || supervisorctl start all || true
    systemctl enable supervisor || true

    # Validate Nginx config and reload
    nginx -t
    systemctl restart nginx || systemctl reload nginx || true
    systemctl enable nginx || true
}

# Perform end-to-end health checks
verify_health() {
    log_info "Waiting 10 seconds for services to boot and stabilize..."
    sleep 10

    log_info "Checking local API health..."
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8000/api/scans/ || echo "000")

    if [ "$HTTP_CODE" -eq 200 ] || [ "$HTTP_CODE" -eq 401 ] || [ "$HTTP_CODE" -eq 403 ]; then
        log_success "API Health Check Passed! HTTP status code: $HTTP_CODE"
        print_summary
    else
        log_error "API Health Check Failed! HTTP status code returned: $HTTP_CODE"
        log_warning "Dumping logs from /var/log/stacksniff/..."
        echo "=== Django Error Logs ==="
        tail -n 20 /var/log/stacksniff/django.err.log || true
        echo "=== Celery Error Logs ==="
        tail -n 20 /var/log/stacksniff/celery.err.log || true
        exit 1
    fi
}

# Output success summary box
print_summary() {
    TOKEN=$(cat "$INSTALL_DIR/API_TOKEN.txt")
    HOST="$ALLOWED_HOSTS"
    
    echo -e "${GREEN}"
    echo "  ╔═════════════════════════════════════════════════════════════════════╗"
    echo "  ║                   stacksniff is ready                               ║"
    echo "  ╠═════════════════════════════════════════════════════════════════════╣"
    echo "    API Base URL:  http://${HOST}/api/"
    echo "    Dashboard:     http://${HOST}/"
    echo "    API Token:     ${TOKEN}"
    echo "    Token saved:   ${INSTALL_DIR}/API_TOKEN.txt"
    echo "  ╠═════════════════════════════════════════════════════════════════════╣"
    echo "    Frontend team header usage:"
    echo "    Authorization: Token ${TOKEN}"
    echo "  ╠═════════════════════════════════════════════════════════════════════╣"
    echo "    Logs:    /var/log/stacksniff/"
    echo "    Status:  sudo supervisorctl status"
    echo "  ╚═════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    echo "Verify the API is running correctly using this command:"
    echo -e "${BLUE}curl -H \"Authorization: Token ${TOKEN}\" http://${HOST}/api/scans/${NC}"
    echo ""
}

# Uninstall all project components
run_uninstall() {
    log_info "Beginning uninstallation of stacksniff production environment..."

    check_privileges

    # Stop supervisor services
    log_info "Stopping and cleaning up Supervisor programs..."
    supervisorctl stop all || true
    rm -f /etc/supervisor/conf.d/stacksniff.conf
    supervisorctl reread || true
    supervisorctl update || true

    # Remove Nginx configurations
    log_info "Removing Nginx reverse proxy configuration..."
    rm -f /etc/nginx/sites-enabled/stacksniff
    rm -f /etc/nginx/sites-available/stacksniff
    systemctl reload nginx || systemctl restart nginx || true

    # Clean install directory and log directories
    log_info "Deleting files in $INSTALL_DIR..."
    rm -rf "$INSTALL_DIR"

    log_info "Deleting log directory..."
    rm -rf "/var/log/stacksniff"

    log_success "Uninstallation completed successfully!"
}

# ==============================================================================
# MAIN EXECUTION FLOW
# ==============================================================================
main() {
    parse_args "$@"
    check_privileges
    tune_resources
    
    log_info "Starting stacksniff production deployment..."
    
    install_dependencies
    setup_project_directories
    configure_environment
    configure_supervisor
    configure_nginx
    start_services
    verify_health
}

main "$@"
