# 🔐 Secure Authentication Microservice

A production-ready, secure authentication microservice built with Flask, supporting both traditional JWT authentication and OAuth2-like authorization flows. Designed for modern web applications with comprehensive security features, monitoring, and easy deployment.

## 🚀 Features

### Core Authentication
- **User Registration & Login** with secure password hashing (bcrypt)
- **JWT Tokens** with RS256 algorithm and key rotation support
- **Refresh Token Management** with automatic cleanup
- **Account Activation** via email verification
- **Password Reset** with secure token-based flow
- **Account Lockout** protection against brute force attacks

### OAuth2-Like Authorization
- **Authorization Code Grant** with PKCE support
- **Client Credentials Grant** for service-to-service communication
- **Refresh Token Grant** for token renewal
- **Resource Owner Password Grant** for trusted clients
- **Token Introspection** (RFC 7662) for token validation
- **Token Revocation** (RFC 7009) for security
- **Scope Management** for fine-grained access control

### Security Features
- **Rate Limiting** with Redis backend
- **CORS Protection** with configurable origins
- **Security Headers** (HSTS, XSS Protection, etc.)
- **Password Strength Validation** with configurable requirements
- **SQL Injection Protection** via ORM
- **Input Validation & Sanitization**
- **Session Management** with secure defaults

### Production Ready
- **Docker Support** with multi-stage builds
- **Health Checks** for monitoring
- **Metrics Endpoint** for observability
- **Comprehensive Logging** with structured logs
- **Error Handling** with consistent responses
- **Database Migrations** with Flask-Migrate
- **Redis Integration** for caching and sessions

## 📋 Requirements

- Python 3.11+
- PostgreSQL 13+
- Redis 6+
- Docker & Docker Compose (for containerized deployment)

**Note**: If you need to use `sudo` with Docker commands, you can add your user to the docker group:
```bash
sudo usermod -aG docker $USER
# Log out and log back in for changes to take effect
```

## 🛠️ Quick Start

### 1. Clone and Setup

```bash
git clone <repository-url>
cd auth_service

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
cd auth-microservice
pip install -r requirements.txt
```

### 2. Environment Configuration

```bash
# Copy environment template
cp .env.example .env

# Edit .env with your settings
nano .env
```

### 3. Generate Security Keys

```bash
# Generate JWT RSA keys
./deploy.sh generate-keys

# Generate secure secrets
./deploy.sh generate-secrets
```

### 4. Database Setup

```bash
# Start PostgreSQL and Redis (note: service names are 'db' and 'redis')
cd auth-microservice
sudo docker compose up -d db redis

# Initialize database
flask db init
flask db migrate -m "Initial migration"
flask db upgrade
```

### 5. Run the Service

```bash
# Development
python src/app.py

# Production
gunicorn -w 4 -b 0.0.0.0:5000 "src.app:create_app()"
```

## 🐳 Docker Deployment

### Quick Start with Docker Compose

```bash
# Navigate to the auth-microservice directory
cd auth-microservice

# Build and start all services
sudo docker compose up -d

# Check health
curl http://localhost:5000/health
```

### Secure Production Deployment

```bash
# Navigate to the auth-microservice directory
cd auth-microservice

# Run secure deployment script
./deploy.sh deploy

# Or with custom settings
./deploy.sh --env production --tag v1.0.0 deploy
```

## 🔧 Configuration

### Environment Variables

Key configuration options in `.env`:

```bash
# Security
SECRET_KEY=your-super-secure-secret-key
JWT_SECRET_KEY=your-jwt-secret-key
JWT_ALGORITHM=RS256

# Database
DATABASE_URL=postgresql://user:password@localhost:5432/auth_db

# Redis
REDIS_URL=redis://localhost:6379/0

# OAuth2
OAUTH2_AUTHORIZATION_CODE_EXPIRES=600
OAUTH2_ACCESS_TOKEN_EXPIRES=3600
TOKEN_INTROSPECTION_ENABLED=true
TOKEN_REVOCATION_ENABLED=true

# Security Settings
PASSWORD_MIN_LENGTH=8
ACCOUNT_LOCKOUT_ATTEMPTS=5
RATE_LIMITING_DEFAULT=100 per hour
```

See `.env.example` for complete configuration options.

## 📚 API Documentation

### Authentication Endpoints

#### Register User
```bash
POST /auth/register
Content-Type: application/json

{
  "username": "johndoe",
  "email": "john@example.com",
  "password": "SecurePassword123!",
  "full_name": "John Doe"
}
```

#### Login
```bash
POST /auth/login
Content-Type: application/json

{
  "username": "johndoe",
  "password": "SecurePassword123!"
}
```

#### Access Protected Endpoint
```bash
GET /users/me
Authorization: Bearer <access_token>
```

### OAuth2 Endpoints

#### Client Credentials Flow
```bash
POST /oauth/token
Authorization: Basic <base64(client_id:client_secret)>
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&scope=read write
```

#### Authorization Code Flow
```bash
# 1. Get authorization code
GET /oauth/authorize?client_id=CLIENT_ID&redirect_uri=CALLBACK&scope=read&response_type=code&state=STATE

# 2. Exchange code for tokens
POST /oauth/token
Authorization: Basic <base64(client_id:client_secret)>

grant_type=authorization_code&code=AUTH_CODE&redirect_uri=CALLBACK
```

#### Token Introspection
```bash
POST /oauth/introspect
Authorization: Basic <base64(client_id:client_secret)>

token=ACCESS_TOKEN&token_type_hint=access_token
```

See [auth-microservice/API_DOCUMENTATION.md](auth-microservice/API_DOCUMENTATION.md) for complete API reference.

## 🧪 Testing

### Run Integration Tests

```bash
# Navigate to the auth-microservice directory
cd auth-microservice

# Full test suite
python tests/integration_tests.py

# Quick smoke tests
python tests/integration_tests.py --smoke

# Test specific URL
python tests/integration_tests.py --base-url http://localhost:5000
```

### Security Audit

```bash
# Navigate to the auth-microservice directory
cd auth-microservice

# Run security audit
python scripts/security_audit.py

# Check specific security aspects
python scripts/security_audit.py --category environment
```

### Manual Testing with cURL

```bash
# Health check
curl http://localhost:5000/health

# Register user
curl -X POST http://localhost:5000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"test","email":"test@example.com","password":"Test123!","full_name":"Test User"}'

# Login
curl -X POST http://localhost:5000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"Test123!"}'
```

## 📊 Monitoring & Operations

### Health Monitoring

```bash
# Health check endpoint
GET /health

# Metrics endpoint
GET /metrics

# Service info
GET /
```

### Monitoring Script

```bash
# Navigate to the auth-microservice directory
cd auth-microservice

# Run continuous monitoring
python scripts/monitoring.py

# Run single check
python scripts/monitoring.py --once

# Create monitoring config
python scripts/monitoring.py --create-config
```

### Log Management

```bash
# Navigate to the auth-microservice directory
cd auth-microservice

# View application logs
sudo docker compose logs -f auth-service

# View all logs
sudo docker compose logs -f

# Log files location
ls logs/
```

## 🔒 Security Best Practices

### Implemented Security Measures

1. **Authentication Security**
   - Strong password requirements
   - Secure password hashing (bcrypt)
   - Account lockout protection
   - JWT with RS256 algorithm

2. **Authorization Security**
   - Scope-based access control
   - Token introspection and revocation
   - Client authentication for OAuth2

3. **Transport Security**
   - Security headers (HSTS, XSS Protection, etc.)
   - CORS configuration
   - Input validation and sanitization

4. **Infrastructure Security**
   - Non-root container execution
   - Secure file permissions
   - Environment variable protection
   - Rate limiting

### Security Checklist

- [ ] Change default secrets in `.env`
- [ ] Generate strong JWT keys
- [ ] Configure HTTPS in production
- [ ] Set up proper CORS origins
- [ ] Configure rate limiting
- [ ] Enable security monitoring
- [ ] Regular security updates
- [ ] Database backup strategy

## 🚀 Production Deployment

### Prerequisites

1. **Server Requirements**
   - Linux server (Ubuntu 20.04+ recommended)
   - Docker and Docker Compose
   - SSL certificate for HTTPS
   - Domain name configured

2. **External Services**
   - Managed PostgreSQL database
   - Managed Redis instance
   - Email service (SMTP)
   - Monitoring service (optional)

### Deployment Steps

1. **Prepare Environment**
   ```bash
   # Clone repository
   git clone <repository-url>
   cd auth_service/auth-microservice
   
   # Set production environment
   export DEPLOYMENT_ENV=production
   ```

2. **Configure Secrets**
   ```bash
   # Generate secure secrets
   ./deploy.sh generate-secrets
   
   # Update .env with production values
   nano .env
   ```

3. **Deploy Services**
   ```bash
   # Run secure deployment
   ./deploy.sh deploy
   
   # Verify deployment
   curl https://your-domain.com/health
   ```

4. **Post-Deployment**
   ```bash
   # Run security audit
   python scripts/security_audit.py
   
   # Set up monitoring
   python scripts/monitoring.py --create-config
   ```

### SSL/HTTPS Setup

Use a reverse proxy (nginx) with SSL certificate:

```nginx
server {
    listen 443 ssl;
    server_name your-domain.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    location / {
        proxy_pass http://localhost:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## 🔧 Development

### Project Structure

```
auth_service/                   # Top-level directory
├── .gitignore                 # Git ignore rules
├── README.md                  # This file
├── venv/                      # Virtual environment (ignored by git)
└── auth-microservice/         # Main application directory
    ├── src/                   # Application source code
    │   ├── app.py            # Main application factory
    │   ├── config/           # Configuration modules
    │   ├── models/           # Database models
    │   ├── routes/           # API route blueprints
    │   ├── utils/            # Utility functions
    │   └── middleware/       # Custom middleware
    ├── tests/                # Test suite
    ├── scripts/              # Utility scripts
    ├── keys/                 # JWT keys (generated, ignored by git)
    ├── logs/                 # Application logs (ignored by git)
    ├── .env                  # Environment variables (ignored by git)
    ├── docker-compose.yml    # Docker services
    ├── Dockerfile           # Container definition
    ├── requirements.txt     # Python dependencies
    └── deploy.sh           # Deployment script
```

### Adding New Features

1. **New API Endpoint**
   ```python
   # In src/routes/your_blueprint.py
   @your_bp.route('/new-endpoint', methods=['POST'])
   @AuthMiddleware.require_auth
   def new_endpoint():
       # Implementation
       pass
   ```

2. **New Database Model**
   ```python
   # In src/models/your_model.py
   class YourModel(db.Model):
       __tablename__ = 'your_table'
       # Model definition
   ```

3. **Run Migration**
   ```bash
   flask db migrate -m "Add new feature"
   flask db upgrade
   ```

### Code Quality

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run linting
flake8 src/

# Run type checking
mypy src/

# Run tests with coverage
pytest --cov=src tests/
```

## 📦 Dependencies

### Core Dependencies
- **Flask 3.0+** - Web framework
- **SQLAlchemy** - Database ORM
- **PostgreSQL** - Primary database
- **Redis** - Caching and sessions
- **JWT** - Token authentication
- **bcrypt** - Password hashing

### Security Dependencies
- **cryptography** - Encryption utilities
- **passlib** - Password utilities
- **argon2** - Alternative password hashing

### Production Dependencies
- **gunicorn** - WSGI server
- **psutil** - System monitoring
- **structlog** - Structured logging
- **sentry-sdk** - Error tracking

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

### Development Guidelines

- Follow PEP 8 style guide
- Add tests for new features
- Update documentation
- Ensure security best practices
- Run security audit before submitting

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

### Common Issues

1. **Database Connection Failed**
   ```bash
   # Check PostgreSQL status
   sudo docker compose ps db
   
   # View database logs
   sudo docker compose logs db
   ```

2. **Redis Connection Failed**
   ```bash
   # Check Redis status
   sudo docker compose ps redis
   
   # Test Redis connection
   sudo docker compose exec redis redis-cli ping
   ```

3. **JWT Key Errors**
   ```bash
   # Regenerate JWT keys
   ./deploy.sh generate-keys
   
   # Check key permissions
   ls -la keys/
   ```

### Getting Help

- Check the [auth-microservice/API_DOCUMENTATION.md](auth-microservice/API_DOCUMENTATION.md)
- Review the [Security Guide](auth-microservice/SECURITY.md)
- Run the security audit: `cd auth-microservice && python scripts/security_audit.py`
- Check application logs: `cd auth-microservice && docker-compose logs app`

### Performance Tuning

1. **Database Optimization**
   - Add indexes for frequently queried fields
   - Use connection pooling
   - Configure PostgreSQL settings

2. **Redis Optimization**
   - Configure memory limits
   - Set appropriate expiration times
   - Use Redis clustering for high load

3. **Application Optimization**
   - Adjust worker processes
   - Configure rate limiting
   - Enable response caching

## 🔄 Migration Guide

### From Basic JWT to OAuth2

This service provides a migration path from simple JWT authentication to full OAuth2:

1. **Phase 1**: Use JWT endpoints (`/auth/*`)
2. **Phase 2**: Introduce OAuth2 clients (`/oauth/clients`)
3. **Phase 3**: Migrate to OAuth2 flows (`/oauth/token`)
4. **Phase 4**: Add scope-based authorization

### Database Migrations

```bash
# Create migration
flask db migrate -m "Description of changes"

# Apply migration
flask db upgrade

# Rollback if needed
flask db downgrade
```

---

**Built with ❤️ for secure, scalable authentication**

For questions or support, please open an issue or contact the development team.