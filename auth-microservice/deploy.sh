#!/bin/bash

# Secure Deployment Script for Auth Microservice
# This script implements security best practices for production deployment

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOYMENT_ENV="${DEPLOYMENT_ENV:-production}"
DOCKER_REGISTRY="${DOCKER_REGISTRY:-}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
HEALTH_CHECK_TIMEOUT=60

# Logging function
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}" >&2
}

warning() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

success() {
    echo -e "${GREEN}[SUCCESS] $1${NC}"
}

# Check if running as root (should not be)
check_user() {
    if [[ $EUID -eq 0 ]]; then
        error "This script should not be run as root for security reasons"
        exit 1
    fi
}

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    local missing_deps=()
    
    # Check required commands
    for cmd in docker docker-compose openssl curl jq; do
        if ! command -v "$cmd" &> /dev/null; then
            missing_deps+=("$cmd")
        fi
    done
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        error "Missing required dependencies: ${missing_deps[*]}"
        echo "Install missing dependencies and try again."
        exit 1
    fi
    
    # Check Docker daemon
    if ! docker info &> /dev/null; then
        error "Docker daemon is not running or accessible"
        exit 1
    fi
    
    success "Prerequisites check passed"
}

# Generate secure secrets
generate_secrets() {
    log "Generating secure secrets..."
    
    local env_file="$PROJECT_DIR/.env"
    local env_example="$PROJECT_DIR/.env.example"
    
    # Create .env from example if it doesn't exist
    if [[ ! -f "$env_file" ]]; then
        if [[ -f "$env_example" ]]; then
            cp "$env_example" "$env_file"
            log "Created .env from .env.example"
        else
            error ".env.example file not found"
            exit 1
        fi
    fi
    
    # Generate secrets if they're placeholder values
    local secret_key=$(openssl rand -hex 32)
    local jwt_secret=$(openssl rand -hex 32)
    local webapp_client_secret=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
    local api_client_secret=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
    
    # Update .env file with secure values (excluding JWT keys for now)
    sed -i.backup \
        -e "s/your-super-secret-key-change-in-production-use-64-chars-minimum/$secret_key/g" \
        -e "s/your-jwt-secret-key-change-in-production-use-64-chars-minimum/$jwt_secret/g" \
        -e "s/your-webapp-client-secret-32-chars-minimum/$webapp_client_secret/g" \
        -e "s/your-api-client-secret-32-chars-minimum/$api_client_secret/g" \
        -e "s/your-email@gmail.com/admin@yourcompany.com/g" \
        -e "s/your-app-password/$(openssl rand -base64 16)/g" \
        "$env_file"
    
    # Update JWT keys if they exist and are currently empty
    if [[ -f "$PROJECT_DIR/keys/jwt_private.pem" ]] && grep -q "^JWT_PRIVATE_KEY=$" "$env_file"; then
        log "Updating JWT private key in .env file..."
        # Use a temporary file to avoid sed issues with special characters
        local temp_private=$(mktemp)
        cat "$PROJECT_DIR/keys/jwt_private.pem" | base64 -w 0 > "$temp_private"
        local jwt_private_b64=$(cat "$temp_private")
        sed -i "s|^JWT_PRIVATE_KEY=$|JWT_PRIVATE_KEY=$jwt_private_b64|" "$env_file"
        rm "$temp_private"
    fi
    
    if [[ -f "$PROJECT_DIR/keys/jwt_public.pem" ]] && grep -q "^JWT_PUBLIC_KEY=$" "$env_file"; then
        log "Updating JWT public key in .env file..."
        # Use a temporary file to avoid sed issues with special characters
        local temp_public=$(mktemp)
        cat "$PROJECT_DIR/keys/jwt_public.pem" | base64 -w 0 > "$temp_public"
        local jwt_public_b64=$(cat "$temp_public")
        sed -i "s|^JWT_PUBLIC_KEY=$|JWT_PUBLIC_KEY=$jwt_public_b64|" "$env_file"
        rm "$temp_public"
    fi
    
    # Set secure permissions
    chmod 600 "$env_file"
    
    success "Secrets generated and .env updated"
}

# Generate JWT keys
generate_jwt_keys() {
    log "Generating JWT RSA keys..."
    
    local keys_dir="$PROJECT_DIR/keys"
    mkdir -p "$keys_dir"
    
    # Generate private key
    if [[ ! -f "$keys_dir/jwt_private.pem" ]]; then
        openssl genrsa -out "$keys_dir/jwt_private.pem" 2048
        chmod 600 "$keys_dir/jwt_private.pem"
        log "Generated JWT private key"
    fi
    
    # Generate public key
    if [[ ! -f "$keys_dir/jwt_public.pem" ]]; then
        openssl rsa -in "$keys_dir/jwt_private.pem" -pubout -out "$keys_dir/jwt_public.pem"
        chmod 644 "$keys_dir/jwt_public.pem"
        log "Generated JWT public key"
    fi
    
    success "JWT keys ready"
}

# Security hardening
security_hardening() {
    log "Applying security hardening..."
    
    # Create dedicated network for the application
    if ! docker network ls | grep -q "auth_network"; then
        docker network create \
            --driver bridge \
            --subnet=172.20.0.0/16 \
            --ip-range=172.20.240.0/20 \
            auth_network
        log "Created dedicated Docker network"
    fi
    
    # Create non-root user for containers if not exists
    if ! id "appuser" &>/dev/null; then
        warning "Consider creating a dedicated 'appuser' system user for running containers"
    fi
    
    # Set proper file permissions
    find "$PROJECT_DIR" -name "*.py" -exec chmod 644 {} \;
    find "$PROJECT_DIR" -name "*.sh" -exec chmod 755 {} \;
    chmod 600 "$PROJECT_DIR/.env" 2>/dev/null || true
    chmod 600 "$PROJECT_DIR/keys"/*.pem 2>/dev/null || true
    
    # Create logs directory with proper permissions
    mkdir -p "$PROJECT_DIR/logs"
    chmod 755 "$PROJECT_DIR/logs"
    
    success "Security hardening applied"
}

# Build Docker image with security scanning
build_image() {
    log "Building Docker image with security scanning..."
    
    cd "$PROJECT_DIR"
    
    # Build image
    local image_name="auth-microservice"
    local full_image_name="$image_name:$IMAGE_TAG"
    
    if [[ -n "$DOCKER_REGISTRY" ]]; then
        full_image_name="$DOCKER_REGISTRY/$full_image_name"
    fi
    
    log "Building image: $full_image_name"
    docker build \
        --no-cache \
        --pull \
        --tag "$full_image_name" \
        --build-arg BUILD_DATE="$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
        --build-arg VCS_REF="$(git rev-parse HEAD 2>/dev/null || echo 'unknown')" \
        .
    
    # Security scan (if available)
    if command -v docker-scan &> /dev/null; then
        log "Running security scan..."
        docker scan "$full_image_name" || warning "Security scan found issues"
    elif command -v trivy &> /dev/null; then
        log "Running Trivy security scan..."
        trivy image --severity HIGH,CRITICAL "$full_image_name" || warning "Security scan found issues"
    else
        warning "No image scanner available. Consider installing docker scan or trivy"
    fi
    
    success "Docker image built successfully"
}

# Validate configuration
validate_config() {
    log "Validating configuration..."
    
    local env_file="$PROJECT_DIR/.env"
    
    # Check critical environment variables
    local required_vars=(
        "SECRET_KEY"
        "DATABASE_URL"
        "REDIS_URL"
        "JWT_SECRET_KEY"
        "JWT_PRIVATE_KEY_PATH"
        "JWT_PUBLIC_KEY_PATH"
    )
    
    local missing_vars=()
    for var in "${required_vars[@]}"; do
        if ! grep -q "^${var}=" "$env_file"; then
            missing_vars+=("$var")
        fi
    done
    
    if [[ ${#missing_vars[@]} -gt 0 ]]; then
        error "Missing required environment variables: ${missing_vars[*]}"
        exit 1
    fi
    
    # Check for placeholder values
    if grep -q "your-.*-minimum\|your-.*@.*\.com\|your-app-password" "$env_file"; then
        error "Found placeholder values in .env file. Run with --generate-secrets first."
        exit 1
    fi
    
    # Validate JWT keys exist
    if [[ ! -f "$PROJECT_DIR/keys/jwt_private.pem" ]] || [[ ! -f "$PROJECT_DIR/keys/jwt_public.pem" ]]; then
        error "JWT keys not found. Run with --generate-keys first."
        exit 1
    fi
    
    success "Configuration validation passed"
}

# Deploy services
deploy_services() {
    log "Deploying services..."
    
    cd "$PROJECT_DIR"
    
    # Stop existing services
    docker-compose down --remove-orphans
    
    # Pull latest images for dependencies
    docker-compose pull postgres redis
    
    # Start services
    docker-compose up -d --build
    
    success "Services deployed"
}

# Health check
health_check() {
    log "Performing health check..."
    
    local url="http://localhost:5000/health"
    local max_attempts=30
    local attempt=1
    
    while [[ $attempt -le $max_attempts ]]; do
        if curl -sf "$url" > /dev/null 2>&1; then
            success "Health check passed"
            return 0
        fi
        
        log "Health check attempt $attempt/$max_attempts failed, retrying in 2 seconds..."
        sleep 2
        ((attempt++))
    done
    
    error "Health check failed after $max_attempts attempts"
    
    # Show logs for debugging
    warning "Recent logs:"
    docker-compose logs --tail=20 app
    
    return 1
}

# Run security audit
security_audit() {
    log "Running security audit..."
    
    if [[ -f "$PROJECT_DIR/scripts/security_audit.py" ]]; then
        cd "$PROJECT_DIR"
        python3 scripts/security_audit.py
    else
        warning "Security audit script not found"
    fi
}

# Database initialization
init_database() {
    log "Initializing database..."
    
    # Wait for database to be ready
    local db_ready=false
    local max_attempts=30
    local attempt=1
    
    while [[ $attempt -le $max_attempts ]] && [[ "$db_ready" == false ]]; do
        if docker-compose exec -T postgres pg_isready -U postgres > /dev/null 2>&1; then
            db_ready=true
        else
            log "Waiting for database... ($attempt/$max_attempts)"
            sleep 2
            ((attempt++))
        fi
    done
    
    if [[ "$db_ready" == false ]]; then
        error "Database not ready after $max_attempts attempts"
        return 1
    fi
    
    # Run database migrations
    log "Running database migrations..."
    docker-compose exec app flask db upgrade || {
        warning "Migration failed, initializing database..."
        docker-compose exec app flask db init
        docker-compose exec app flask db migrate -m "Initial migration"
        docker-compose exec app flask db upgrade
    }
    
    success "Database initialized"
}

# Backup configuration
backup_config() {
    log "Creating configuration backup..."
    
    local backup_dir="$PROJECT_DIR/backups/$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir"
    
    # Backup important files (without secrets)
    cp "$PROJECT_DIR/docker-compose.yml" "$backup_dir/"
    cp "$PROJECT_DIR/Dockerfile" "$backup_dir/"
    cp "$PROJECT_DIR/.env.example" "$backup_dir/"
    
    # Create deployment info
    cat > "$backup_dir/deployment_info.txt" << EOF
Deployment Date: $(date)
Environment: $DEPLOYMENT_ENV
Image Tag: $IMAGE_TAG
Git Commit: $(git rev-parse HEAD 2>/dev/null || echo 'unknown')
Docker Version: $(docker --version)
Docker Compose Version: $(docker-compose --version)
EOF
    
    success "Configuration backed up to $backup_dir"
}

# Cleanup old backups
cleanup_backups() {
    log "Cleaning up old backups..."
    
    local backup_dir="$PROJECT_DIR/backups"
    if [[ -d "$backup_dir" ]]; then
        # Keep only last 5 backups
        find "$backup_dir" -maxdepth 1 -type d -name "20*" | sort -r | tail -n +6 | xargs rm -rf
        success "Old backups cleaned up"
    fi
}

# Display deployment summary
deployment_summary() {
    echo
    success "🚀 Deployment completed successfully!"
    echo
    echo "Service Information:"
    echo "  • Application URL: http://localhost:5000"
    echo "  • Health Check: http://localhost:5000/health"
    echo "  • Metrics: http://localhost:5000/metrics"
    echo "  • Environment: $DEPLOYMENT_ENV"
    echo "  • Image Tag: $IMAGE_TAG"
    echo
    echo "OAuth2 Endpoints:"
    echo "  • Token: http://localhost:5000/oauth/token"
    echo "  • Introspect: http://localhost:5000/oauth/introspect"
    echo "  • Revoke: http://localhost:5000/oauth/revoke"
    echo "  • Authorize: http://localhost:5000/oauth/authorize"
    echo
    echo "Next Steps:"
    echo "  1. Test the API endpoints"
    echo "  2. Set up monitoring and alerting"
    echo "  3. Configure SSL/TLS certificates"
    echo "  4. Set up log aggregation"
    echo "  5. Configure backup procedures"
    echo
}

# Main deployment function
deploy() {
    log "Starting secure deployment of Auth Microservice"
    echo "Environment: $DEPLOYMENT_ENV"
    echo "Project Directory: $PROJECT_DIR"
    echo
    
    check_user
    check_prerequisites
    validate_config
    security_hardening
    backup_config
    cleanup_backups
    build_image
    deploy_services
    init_database
    
    if health_check; then
        security_audit
        deployment_summary
    else
        error "Deployment failed - health check did not pass"
        exit 1
    fi
}

# Script usage
usage() {
    cat << EOF
Secure Deployment Script for Auth Microservice

Usage: $0 [OPTIONS] [COMMAND]

Commands:
    deploy              Full deployment (default)
    generate-secrets    Generate secure secrets
    generate-keys       Generate JWT RSA keys
    build              Build Docker image only
    health-check       Run health check only
    security-audit     Run security audit only
    backup             Create configuration backup
    
Options:
    --env ENV          Set deployment environment (default: production)
    --tag TAG          Set Docker image tag (default: latest)
    --registry URL     Set Docker registry URL
    --help             Show this help message

Environment Variables:
    DEPLOYMENT_ENV     Deployment environment
    IMAGE_TAG          Docker image tag
    DOCKER_REGISTRY    Docker registry URL

Examples:
    $0 deploy
    $0 --env staging deploy
    $0 --tag v1.2.3 build
    $0 generate-secrets
    $0 security-audit

EOF
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --env)
                DEPLOYMENT_ENV="$2"
                shift 2
                ;;
            --tag)
                IMAGE_TAG="$2"
                shift 2
                ;;
            --registry)
                DOCKER_REGISTRY="$2"
                shift 2
                ;;
            --help)
                usage
                exit 0
                ;;
            generate-secrets)
                generate_secrets
                exit 0
                ;;
            generate-keys)
                generate_jwt_keys
                exit 0
                ;;
            build)
                check_prerequisites
                build_image
                exit 0
                ;;
            health-check)
                health_check
                exit 0
                ;;
            security-audit)
                security_audit
                exit 0
                ;;
            backup)
                backup_config
                exit 0
                ;;
            deploy)
                # Default command, handled below
                shift
                break
                ;;
            *)
                error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
}

# Main execution
main() {
    parse_args "$@"
    deploy
}

# Run main function with all arguments
main "$@"
