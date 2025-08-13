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