import os
from datetime import timedelta

# Database configuration
DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql://auth_user:auth_password@db:5432/auth_db')
REDIS_URL = os.getenv('REDIS_URL', 'redis://redis:6379/0')

# Security configuration
SECRET_KEY = os.getenv('SECRET_KEY', 'your-super-secret-key-change-in-production')
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'your-jwt-secret-key-change-in-production')
JWT_ALGORITHM = 'RS256'  # Using RS256 for better security
JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=15)
JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=7)

# JWT Keys (for RS256 - in production, load from files)
JWT_PRIVATE_KEY = os.getenv('JWT_PRIVATE_KEY', '')
JWT_PUBLIC_KEY = os.getenv('JWT_PUBLIC_KEY', '')

# Fallback to HS256 if no keys provided (development only)
if not JWT_PRIVATE_KEY or not JWT_PUBLIC_KEY:
    JWT_ALGORITHM = 'HS256'

# OAuth2-like Configuration
OAUTH2_ENABLED = os.getenv('OAUTH2_ENABLED', 'true').lower() == 'true'
OAUTH2_ACCESS_TOKEN_EXPIRES = timedelta(seconds=int(os.getenv('OAUTH2_ACCESS_TOKEN_EXPIRES', 900)))
OAUTH2_REFRESH_TOKEN_EXPIRES = timedelta(seconds=int(os.getenv('OAUTH2_REFRESH_TOKEN_EXPIRES', 604800)))
OAUTH2_AUTHORIZATION_CODE_EXPIRES = timedelta(seconds=int(os.getenv('OAUTH2_AUTHORIZATION_CODE_EXPIRES', 600)))

# OAuth2 Client Credentials
WEBAPP_CLIENT_SECRET = os.getenv('WEBAPP_CLIENT_SECRET', 'webapp-client-secret-change-me')
API_CLIENT_SECRET = os.getenv('API_CLIENT_SECRET', 'api-client-secret-change-me')

# OAuth2 Scopes
OAUTH2_SCOPES = {
    'read': 'Read access to user data',
    'write': 'Write access to user data', 
    'profile': 'Access to user profile information',
    'email': 'Access to user email address',
    'admin': 'Administrative access'
}

# Supported OAuth2 Grant Types
OAUTH2_GRANT_TYPES = [
    'authorization_code',
    'refresh_token',
    'client_credentials',
    'password'  # Only for trusted clients
]

# OAuth2 Clients Configuration
OAUTH2_CLIENTS = {
    'webapp_client': {
        'client_secret': WEBAPP_CLIENT_SECRET,
        'grant_types': ['authorization_code', 'refresh_token', 'password'],
        'scopes': ['read', 'write', 'profile', 'email'],
        'redirect_uris': ['http://localhost:3000/callback', 'http://localhost:3001/callback']
    },
    'api_client': {
        'client_secret': API_CLIENT_SECRET,
        'grant_types': ['client_credentials'],
        'scopes': ['read', 'write'],
        'redirect_uris': []
    }
}

# Token Introspection and Revocation
TOKEN_INTROSPECTION_ENABLED = os.getenv('TOKEN_INTROSPECTION_ENABLED', 'true').lower() == 'true'
TOKEN_REVOCATION_ENABLED = os.getenv('TOKEN_REVOCATION_ENABLED', 'true').lower() == 'true'

# Email configuration
MAIL_SERVER = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
MAIL_PORT = int(os.getenv('MAIL_PORT', 587))
MAIL_USE_TLS = os.getenv('MAIL_USE_TLS', 'true').lower() == 'true'
MAIL_USERNAME = os.getenv('MAIL_USERNAME', '')
MAIL_PASSWORD = os.getenv('MAIL_PASSWORD', '')
MAIL_DEFAULT_SENDER = os.getenv('MAIL_DEFAULT_SENDER', 'noreply@authservice.com')

# Rate limiting
RATELIMIT_STORAGE_URL = REDIS_URL
RATELIMIT_DEFAULT = "100 per hour"

# CORS configuration
CORS_ORIGINS = [
    "http://localhost:3000",
    "http://localhost:3001", 
    "http://localhost:8080",
    "https://your-frontend-domain.com"
]

# Password requirements
PASSWORD_MIN_LENGTH = 8
PASSWORD_REQUIRE_UPPERCASE = True
PASSWORD_REQUIRE_LOWERCASE = True
PASSWORD_REQUIRE_DIGIT = True
PASSWORD_REQUIRE_SPECIAL = True

# Environment
DEBUG = os.getenv('DEBUG', 'false').lower() == 'true'
TESTING = os.getenv('TESTING', 'false').lower() == 'true'

# SQLAlchemy configuration
SQLALCHEMY_DATABASE_URI = DATABASE_URL
SQLALCHEMY_TRACK_MODIFICATIONS = False
SQLALCHEMY_ENGINE_OPTIONS = {
    'pool_size': 10,
    'pool_recycle': 3600,
    'pool_pre_ping': True
}