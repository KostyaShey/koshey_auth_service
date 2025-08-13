# Authentication Microservice

A secure, production-ready authentication microservice built with Flask, PostgreSQL, and Redis. Designed for modern web applications requiring robust user authentication and authorization.

## Features

### 🔐 Security Features
- **JWT Authentication** with RS256 algorithm support
- **Refresh Token** system with automatic rotation
- **Password Security** with bcrypt hashing and strength validation
- **Rate Limiting** on authentication endpoints
- **Account Lockout** after failed login attempts
- **Email Verification** for account activation
- **Password Reset** with secure token-based flow
- **Data Privacy** with hashed email and phone storage

### 🚀 Production Ready
- **Docker** containerization with multi-stage builds
- **PostgreSQL** for reliable data persistence
- **Redis** for token blacklisting and rate limiting
- **Health Checks** for monitoring and orchestration
- **Structured Logging** for debugging and analytics
- **CORS** configuration for web app integration
- **Security Headers** for additional protection

### 📝 API Endpoints

#### Authentication
- `POST /auth/register` - User registration with email verification
- `POST /auth/login` - User authentication with rate limiting
- `POST /auth/refresh-token` - Refresh access tokens
- `POST /auth/logout` - Logout and token blacklisting
- `POST /auth/verify-email` - Email verification
- `POST /auth/forgot-password` - Password reset request
- `POST /auth/reset-password` - Password reset with token
- `GET /auth/verify-token` - Token validation for other services

#### User Management
- `GET /users/profile` - Get current user profile
- `PUT /users/profile` - Update user profile
- `POST /users/change-password` - Change password
- `DELETE /users/delete-account` - Delete user account
- `GET /users/sessions` - List active sessions
- `DELETE /users/sessions/{id}` - Revoke specific session

#### Monitoring
- `GET /health` - Health check endpoint
- `GET /metrics` - Application metrics

## Quick Start

### Prerequisites
- Docker and Docker Compose
- Git

### 1. Clone and Setup

```bash
# Clone the repository
git clone <repository-url>
cd auth-microservice

# Copy environment file
cp .env.example .env

# Edit environment variables (important for production!)
nano .env
```

### 2. Configure Environment

Update `.env` file with your settings:

```bash
# Required: Change these secrets!
SECRET_KEY=your-super-secret-key-64-chars-minimum
JWT_SECRET_KEY=your-jwt-secret-key-64-chars-minimum

# Email configuration (for verification/reset)
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password

# Database credentials (optional - defaults provided)
DATABASE_URL=postgresql://auth_user:auth_password@db:5432/auth_db
```

### 3. Start Services

```bash
# Start all services (production mode)
docker-compose up -d

# Or start with development tools
docker-compose --profile dev up -d

# Check service status
docker-compose ps
```

### 4. Verify Installation

```bash
# Check health
curl http://localhost:5000/health

# Test registration
curl -X POST http://localhost:5000/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "username": "testuser",
    "password": "SecurePass123!",
    "name": "Test",
    "surname": "User"
  }'
```

## Development Setup

### Local Development

```bash
# Install Python dependencies
pip install -r requirements.txt

# Set up local database (PostgreSQL)
createdb auth_db

# Set environment variables
export DATABASE_URL=postgresql://localhost/auth_db
export SECRET_KEY=dev-secret-key
export DEBUG=true

# Run migrations
flask db upgrade

# Start development server
python src/app.py
```

### Development Tools

```bash
# Start with development profile (includes pgAdmin and Redis Commander)
docker-compose --profile dev up -d

# Access development tools:
# - pgAdmin: http://localhost:8080 (admin@authservice.com / admin)
# - Redis Commander: http://localhost:8081
```

## API Documentation

### Authentication Flow

1. **Registration**: `POST /auth/register`
   ```json
   {
     "email": "user@example.com",
     "username": "username",
     "password": "SecurePass123!",
     "name": "John",
     "surname": "Doe",
     "phone_number": "+1234567890"
   }
   ```

2. **Email Verification**: `POST /auth/verify-email`
   ```json
   {
     "token": "email-verification-token"
   }
   ```

3. **Login**: `POST /auth/login`
   ```json
   {
     "username": "username",
     "password": "SecurePass123!"
   }
   ```

4. **Use Access Token**:
   ```bash
   Authorization: Bearer <access-token>
   ```

5. **Refresh Token**: `POST /auth/refresh-token`
   ```json
   {
     "refresh_token": "refresh-token"
   }
   ```

### Example Integration

```javascript
// Frontend JavaScript example
class AuthService {
  constructor(baseUrl) {
    this.baseUrl = baseUrl;
    this.accessToken = localStorage.getItem('access_token');
    this.refreshToken = localStorage.getItem('refresh_token');
  }

  async login(username, password) {
    const response = await fetch(`${this.baseUrl}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });
    
    if (response.ok) {
      const data = await response.json();
      this.accessToken = data.access_token;
      this.refreshToken = data.refresh_token;
      localStorage.setItem('access_token', this.accessToken);
      localStorage.setItem('refresh_token', this.refreshToken);
      return data;
    }
    throw new Error('Login failed');
  }

  async makeAuthenticatedRequest(url, options = {}) {
    const headers = {
      'Authorization': `Bearer ${this.accessToken}`,
      'Content-Type': 'application/json',
      ...options.headers
    };

    let response = await fetch(url, { ...options, headers });
    
    // Handle token refresh
    if (response.status === 401) {
      await this.refreshAccessToken();
      headers['Authorization'] = `Bearer ${this.accessToken}`;
      response = await fetch(url, { ...options, headers });
    }
    
    return response;
  }

  async refreshAccessToken() {
    const response = await fetch(`${this.baseUrl}/auth/refresh-token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: this.refreshToken })
    });
    
    if (response.ok) {
      const data = await response.json();
      this.accessToken = data.access_token;
      localStorage.setItem('access_token', this.accessToken);
    } else {
      this.logout();
    }
  }

  logout() {
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    this.accessToken = null;
    this.refreshToken = null;
  }
}
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | Required |
| `REDIS_URL` | Redis connection string | Required |
| `SECRET_KEY` | Flask secret key | Required |
| `JWT_SECRET_KEY` | JWT signing key | Required |
| `DEBUG` | Enable debug mode | `false` |
| `MAIL_SERVER` | SMTP server | `smtp.gmail.com` |
| `MAIL_USERNAME` | SMTP username | Required for email |
| `MAIL_PASSWORD` | SMTP password | Required for email |

### Security Configuration

For production deployment:

1. **Generate Strong Secrets**:
   ```bash
   # Generate secrets
   python -c "import secrets; print(secrets.token_urlsafe(64))"
   ```

2. **Use RS256 for JWT** (recommended):
   ```bash
   # Generate RSA key pair
   openssl genrsa -out private.pem 2048
   openssl rsa -in private.pem -pubout > public.pem
   
   # Add to environment
   JWT_PRIVATE_KEY="$(cat private.pem)"
   JWT_PUBLIC_KEY="$(cat public.pem)"
   ```

3. **Configure HTTPS** (use reverse proxy like nginx)

4. **Set up proper CORS** origins

## Monitoring and Maintenance

### Health Checks

```bash
# Application health
curl http://localhost:5000/health

# Service metrics
curl http://localhost:5000/metrics
```

### Logs

```bash
# View application logs
docker-compose logs auth-service

# Follow logs
docker-compose logs -f auth-service
```

### Database Maintenance

```bash
# Clean up expired tokens
docker-compose exec auth-service python -c "
from models.user import RefreshToken
RefreshToken.cleanup_expired()
"

# Database backup
docker-compose exec db pg_dump -U auth_user auth_db > backup.sql
```

## Testing

```bash
# Run tests
python -m pytest tests/

# Run with coverage
python -m pytest tests/ --cov=src/

# Test specific endpoint
python -m pytest tests/test_auth.py::test_registration
```

## Deployment

### Production Deployment

1. **Environment Setup**:
   - Use managed PostgreSQL and Redis services
   - Set strong secrets and keys
   - Configure email service (SendGrid, AWS SES, etc.)
   - Set up monitoring (Sentry, DataDog, etc.)

2. **Container Orchestration**:
   ```bash
   # Kubernetes deployment
   kubectl apply -f k8s/

   # Docker Swarm
   docker stack deploy -c docker-compose.yml auth-stack
   ```

3. **Reverse Proxy** (nginx example):
   ```nginx
   server {
       listen 443 ssl;
       server_name auth.yourdomain.com;
       
       location / {
           proxy_pass http://localhost:5000;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
           proxy_set_header X-Forwarded-Proto $scheme;
       }
   }
   ```

### Scaling

- **Horizontal Scaling**: Multiple container instances behind load balancer
- **Database**: Use connection pooling and read replicas
- **Redis**: Use Redis Cluster for high availability
- **Monitoring**: Set up alerts for health checks and metrics

## Security Considerations

1. **Secrets Management**: Use dedicated secret management systems
2. **Database Security**: Enable SSL, use strong passwords, regular updates
3. **Network Security**: Use VPC, firewall rules, private networks
4. **Monitoring**: Set up alerts for suspicious activities
5. **Backup**: Regular automated backups with encryption
6. **Updates**: Keep dependencies and base images updated

## Troubleshooting

### Common Issues

1. **Database Connection Failed**:
   ```bash
   # Check database status
   docker-compose exec db pg_isready -U auth_user
   
   # Check connection string
   echo $DATABASE_URL
   ```

2. **Redis Connection Failed**:
   ```bash
   # Check Redis status
   docker-compose exec redis redis-cli ping
   ```

3. **JWT Token Issues**:
   ```bash
   # Check JWT configuration
   python -c "from utils.token_utils import verify_token; print('JWT config OK')"
   ```

4. **Email Not Sending**:
   - Verify SMTP credentials
   - Check app passwords for Gmail
   - Review email service logs

### Debug Mode

```bash
# Enable debug mode
export DEBUG=true
python src/app.py

# Or with Docker
docker-compose up auth-service -e DEBUG=true
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes with tests
4. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues and questions:
1. Check the troubleshooting section
2. Review existing GitHub issues
3. Create a new issue with detailed information

## Usage

- **User Registration**: POST request to `/auth/register`
- **User Login**: POST request to `/auth/login`
- **Token Generation**: Tokens are provided upon successful login and can be used for subsequent requests.

## Additional Information

- Ensure Docker is installed and running on your Debian 12 system.
- For any issues, please refer to the documentation in the respective files or raise an issue in the repository.

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request for any enhancements or bug fixes.

## License

This project is licensed under the MIT License. See the LICENSE file for details.