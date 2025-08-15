# Auth Microservice API Documentation

## Overview

This is a comprehensive authentication microservice built with Flask, supporting both traditional JWT authentication and OAuth2-like authorization flows. It provides secure user management, token-based authentication, and extensive security features for production use.

## Base URL

```
http://localhost:5000
```

## Authentication

The API supports multiple authentication methods:

1. **JWT Bearer Tokens** - For API access
2. **OAuth2 Client Credentials** - For service-to-service communication
3. **OAuth2 Authorization Code** - For user authorization flows

### Bearer Token Authentication

Include the JWT token in the Authorization header:

```
Authorization: Bearer <token>
```

### OAuth2 Client Authentication

For OAuth2 endpoints, use Basic Authentication with client credentials:

```
Authorization: Basic <base64(client_id:client_secret)>
```

## API Endpoints

### Authentication Endpoints (`/auth`)

#### Register User

**POST** `/auth/register`

Register a new user account.

**Request Body:**
```json
{
  "username": "johndoe",
  "email": "john@example.com",
  "password": "SecurePassword123!",
  "name": "John",
  "surname": "Doe"
}
```

**Response (201):**
```json
{
  "message": "User registered successfully",
  "user": {
    "id": 1,
    "username": "johndoe",
    "email": "john@example.com",
    "name": "John",
    "surname": "Doe",
    "account_activation_status": false,
    "created_at": "2024-01-15T10:30:00Z"
  }
}
```

**Response (400):**
```json
{
  "error": "Validation error",
  "details": {
    "email": ["Invalid email format"],
    "password": ["Password too weak"]
  }
}
```

#### Login

**POST** `/auth/login`

Authenticate user and receive JWT tokens.

**Request Body:**
```json
{
  "username": "johndoe",
  "password": "SecurePassword123!"
}
```

**Response (200):**
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...",
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "user": {
    "id": 1,
    "username": "johndoe",
    "email": "john@example.com",
    "name": "John",
    "surname": "Doe"
  }
}
```

**Response (401):**
```json
{
  "error": "Invalid credentials"
}
```

#### Refresh Token

**POST** `/auth/refresh`

Get a new access token using a refresh token.

**Request Body:**
```json
{
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9..."
}
```

**Response (200):**
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

#### Logout

**POST** `/auth/logout`

**Headers:** `Authorization: Bearer <token>`

Revoke the current access token.

**Response (200):**
```json
{
  "message": "Logged out successfully"
}
```

#### Logout All Sessions

**POST** `/auth/logout-all`

**Headers:** `Authorization: Bearer <token>`

Revoke all refresh tokens for the user.

**Response (200):**
```json
{
  "message": "Logged out from all sessions"
}
```

#### Activate Account

**POST** `/auth/activate`

Activate user account with activation token.

**Request Body:**
```json
{
  "token": "activation_token_here"
}
```

**Response (200):**
```json
{
  "message": "Account activated successfully"
}
```

#### Request Password Reset

**POST** `/auth/forgot-password`

Request password reset email.

**Request Body:**
```json
{
  "email": "john@example.com"
}
```

**Response (200):**
```json
{
  "message": "Password reset email sent"
}
```

#### Reset Password

**POST** `/auth/reset-password`

Reset password with reset token.

**Request Body:**
```json
{
  "token": "reset_token_here",
  "new_password": "NewSecurePassword123!"
}
```

**Response (200):**
```json
{
  "message": "Password reset successfully"
}
```

### User Management Endpoints (`/users`)

#### Get Current User

**GET** `/users/me`

**Headers:** `Authorization: Bearer <token>`

Get current authenticated user information.

**Response (200):**
```json
{
  "id": 1,
  "username": "johndoe",
  "email": "john@example.com",
  "name": "John",
  "surname": "Doe",
  "account_activation_status": true,
  "created_at": "2024-01-15T10:30:00Z",
  "last_login_at": "2024-01-16T14:20:00Z"
}
```

#### Update User Profile

**PUT** `/users/me`

**Headers:** `Authorization: Bearer <token>`

Update current user profile.

**Request Body:**
```json
{
  "name": "John",
  "surname": "Smith",
  "email": "johnsmith@example.com"
}
```

**Response (200):**
```json
{
  "message": "Profile updated successfully",
  "user": {
    "id": 1,
    "username": "johndoe",
    "email": "johnsmith@example.com",
    "name": "John",
    "surname": "Smith",
    "updated_at": "2024-01-16T15:30:00Z"
  }
}
```

#### Change Password

**POST** `/users/change-password`

**Headers:** `Authorization: Bearer <token>`

Change user password.

**Request Body:**
```json
{
  "current_password": "CurrentPassword123!",
  "new_password": "NewSecurePassword123!"
}
```

**Response (200):**
```json
{
  "message": "Password changed successfully"
}
```

#### Delete Account

**DELETE** `/users/me`

**Headers:** `Authorization: Bearer <token>`

Delete current user account.

**Response (200):**
```json
{
  "message": "Account deleted successfully"
}
```

### OAuth2 Endpoints (`/oauth`)

#### Token Endpoint

**POST** `/oauth/token`

**Headers:** `Authorization: Basic <base64(client_id:client_secret)>`

OAuth2 token endpoint supporting multiple grant types.

##### Authorization Code Grant

**Request Body:**
```
grant_type=authorization_code
code=auth_code_here
redirect_uri=https://client.example.com/callback
code_verifier=pkce_code_verifier (optional, for PKCE)
```

##### Refresh Token Grant

**Request Body:**
```
grant_type=refresh_token
refresh_token=refresh_token_here
scope=read write (optional)
```

##### Client Credentials Grant

**Request Body:**
```
grant_type=client_credentials
scope=read write
```

##### Resource Owner Password Credentials Grant

**Request Body:**
```
grant_type=password
username=johndoe
password=SecurePassword123!
scope=read write
```

**Response (200):**
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...",
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "read write"
}
```

#### Authorization Endpoint

**GET** `/oauth/authorize`

OAuth2 authorization endpoint for authorization code flow.

**Query Parameters:**
- `client_id`: OAuth2 client ID
- `redirect_uri`: Callback URL
- `scope`: Requested scopes (space-separated)
- `state`: CSRF protection parameter
- `response_type`: Must be "code"
- `code_challenge`: PKCE code challenge (optional)
- `code_challenge_method`: PKCE method, "S256" (optional)

**Response (200):**
```json
{
  "message": "Authorization required",
  "client_id": "client_abc123",
  "client_name": "My Application",
  "scope": "read write",
  "redirect_uri": "https://client.example.com/callback",
  "state": "random_state_value",
  "action": "POST to this endpoint with user_id and consent=true"
}
```

**POST** `/oauth/authorize`

Handle authorization decision.

**Request Body:**
```
user_id=1
consent=true
client_id=client_abc123
redirect_uri=https://client.example.com/callback
scope=read write
state=random_state_value
```

**Response (302):**
Redirect to `redirect_uri` with authorization code or error.

#### Token Introspection

**POST** `/oauth/introspect`

**Headers:** `Authorization: Basic <base64(client_id:client_secret)>`

Introspect token information (RFC 7662).

**Request Body:**
```
token=access_token_or_refresh_token
token_type_hint=access_token (optional)
```

**Response (200):**
```json
{
  "active": true,
  "client_id": "client_abc123",
  "scope": "read write",
  "sub": "1",
  "exp": 1642348800,
  "iat": 1642345200,
  "token_type": "access_token"
}
```

#### Token Revocation

**POST** `/oauth/revoke`

**Headers:** `Authorization: Basic <base64(client_id:client_secret)>`

Revoke access or refresh token (RFC 7009).

**Request Body:**
```
token=token_to_revoke
token_type_hint=access_token (optional)
```

**Response (200):**
Empty response body.

#### Client Registration

**POST** `/oauth/clients`

Register new OAuth2 client (for development/testing).

**Request Body:**
```json
{
  "client_name": "My Application",
  "redirect_uris": ["https://client.example.com/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "scopes": ["read", "write"]
}
```

**Response (201):**
```json
{
  "client_id": "client_abc123",
  "client_secret": "client_secret_xyz789",
  "client_name": "My Application",
  "grant_types": ["authorization_code", "refresh_token"],
  "scopes": ["read", "write"],
  "redirect_uris": ["https://client.example.com/callback"]
}
```

### System Endpoints

#### Health Check

**GET** `/health`

Check service health status.

**Response (200):**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-16T15:30:00Z",
  "service": "auth-service",
  "version": "1.0.0",
  "checks": {
    "database": "healthy",
    "redis": "healthy"
  }
}
```

#### Metrics

**GET** `/metrics`

Get service metrics.

**Response (200):**
```json
{
  "timestamp": "2024-01-16T15:30:00Z",
  "metrics": {
    "total_users": 150,
    "active_users": 142,
    "inactive_users": 8
  }
}
```

#### Root

**GET** `/`

Get API information.

**Response (200):**
```json
{
  "service": "Auth Microservice",
  "version": "1.0.0",
  "status": "running",
  "endpoints": {
    "auth": "/auth",
    "users": "/users",
    "oauth": "/oauth",
    "health": "/health",
    "metrics": "/metrics"
  },
  "oauth_endpoints": {
    "token": "/oauth/token",
    "introspect": "/oauth/introspect",
    "revoke": "/oauth/revoke",
    "authorize": "/oauth/authorize",
    "clients": "/oauth/clients"
  },
  "documentation": "/docs"
}
```

## OAuth2 Scopes

The service supports the following OAuth2 scopes:

- `read`: Read access to user data
- `write`: Write access to user data
- `admin`: Administrative access (if user has admin role)

## Error Responses

All endpoints return consistent error responses:

```json
{
  "error": "error_code",
  "error_description": "Human readable description",
  "details": {
    "field": ["Specific error messages"]
  }
}
```

### Common Error Codes

- `invalid_request`: The request is missing required parameters
- `invalid_client`: Client authentication failed
- `invalid_grant`: The authorization grant is invalid
- `unauthorized_client`: Client not authorized for this grant type
- `unsupported_grant_type`: Grant type not supported
- `invalid_scope`: Requested scope is invalid
- `invalid_token`: Token is invalid or expired
- `insufficient_scope`: Token doesn't have required scope

## Rate Limiting

The API implements rate limiting to prevent abuse:

- **Authentication endpoints**: 10 requests per minute
- **OAuth2 token endpoint**: 10 requests per minute
- **OAuth2 introspection**: 30 requests per minute
- **OAuth2 revocation**: 20 requests per minute
- **General endpoints**: 100 requests per hour

Rate limit information is returned in response headers:

```
X-RateLimit-Limit: 10
X-RateLimit-Remaining: 7
X-RateLimit-Reset: 1642345200
```

When rate limit is exceeded, a `429 Too Many Requests` response is returned.

## Security Features

### Password Requirements

Passwords must meet the following criteria:
- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one digit
- At least one special character
- Not commonly used passwords

### Account Security

- Account activation via email
- Password reset via secure tokens
- Account lockout after failed login attempts
- Session management with refresh tokens
- Secure password hashing with bcrypt

### API Security

- HTTPS enforcement in production
- Security headers (HSTS, X-Frame-Options, etc.)
- CORS configuration
- Request validation and sanitization
- SQL injection protection
- XSS protection

## Development and Testing

### Environment Variables

Required environment variables for development:

```bash
# Application
SECRET_KEY=your-secret-key
DEBUG=true
TESTING=false
PORT=5000

# Database
DATABASE_URL=postgresql://user:password@localhost:5433/auth_db

# Redis
REDIS_URL=redis://localhost:6379/0

# JWT
JWT_SECRET_KEY=your-jwt-secret
JWT_ACCESS_TOKEN_EXPIRES=3600
JWT_REFRESH_TOKEN_EXPIRES=604800
JWT_ALGORITHM=RS256
JWT_PRIVATE_KEY_PATH=keys/jwt_private.pem
JWT_PUBLIC_KEY_PATH=keys/jwt_public.pem

# OAuth2
OAUTH2_AUTHORIZATION_CODE_EXPIRES=600
OAUTH2_ACCESS_TOKEN_EXPIRES=3600
OAUTH2_REFRESH_TOKEN_EXPIRES=604800
TOKEN_INTROSPECTION_ENABLED=true
TOKEN_REVOCATION_ENABLED=true

# Email (for account activation)
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=true
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password
MAIL_DEFAULT_SENDER=noreply@yourapp.com

# Security
CORS_ORIGINS=http://localhost:3000,http://localhost:3001
RATELIMIT_DEFAULT=100 per hour
```

### Testing with cURL

#### Register a new user:
```bash
curl -X POST http://localhost:5000/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "password": "SecurePassword123!",
    "name": "Test",
    "surname": "User"
  }'
```

#### Login:
```bash
curl -X POST http://localhost:5000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "SecurePassword123!"
  }'
```

#### Access protected endpoint:
```bash
curl -X GET http://localhost:5000/users/me \
  -H "Authorization: Bearer <access_token>"
```

#### OAuth2 Client Credentials:
```bash
curl -X POST http://localhost:5000/oauth/token \
  -H "Authorization: Basic $(echo -n 'client_id:client_secret' | base64)" \
  -d "grant_type=client_credentials&scope=read write"
```

## Deployment

### Docker Deployment

1. Build the image:
```bash
docker build -t auth-service .
```

2. Run with Docker Compose:
```bash
docker-compose up -d
```

### Production Considerations

1. **SSL/TLS**: Always use HTTPS in production
2. **Environment Variables**: Use secure secret management
3. **Database**: Use managed PostgreSQL service
4. **Redis**: Use managed Redis service
5. **Monitoring**: Set up health checks and alerting
6. **Logging**: Configure centralized logging
7. **Backup**: Implement regular database backups
8. **Security**: Regular security updates and audits

## Support

For issues and questions:
- Check the logs: `docker-compose logs app`
- Health check: `curl http://localhost:5000/health`
- Metrics: `curl http://localhost:5000/metrics`

## License

[Add your license information here]
