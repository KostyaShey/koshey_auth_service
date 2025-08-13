from flask import request, jsonify, g
from functools import wraps
import time
import redis
from utils.token_utils import verify_token, is_user_tokens_revoked
from models.user import User

# Rate limiting using Redis
redis_client = redis.Redis.from_url('redis://redis:6379/0')

class AuthMiddleware:
    """Authentication and authorization middleware"""
    
    @staticmethod
    def verify_token_middleware():
        """Middleware to verify JWT tokens"""
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                token = None
                
                # Extract token from Authorization header
                if 'Authorization' in request.headers:
                    auth_header = request.headers['Authorization']
                    if auth_header.startswith('Bearer '):
                        token = auth_header.split(' ')[1]
                
                if not token:
                    return jsonify({'error': 'Access token is required'}), 401
                
                # Verify the token
                payload = verify_token(token)
                if not payload:
                    return jsonify({'error': 'Invalid or expired token'}), 401
                
                # Check if user tokens are revoked
                user_id = payload.get('sub')
                if is_user_tokens_revoked(user_id):
                    return jsonify({'error': 'Token has been revoked'}), 401
                
                # Get user from database
                user = User.query.get(user_id)
                if not user:
                    return jsonify({'error': 'User not found'}), 401
                
                # Store user in request context
                g.current_user = user
                
                return f(*args, **kwargs)
            
            return decorated_function
        return decorator
    
    @staticmethod
    def rate_limit(max_requests=60, window=60, key_func=None):
        """Rate limiting decorator"""
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                # Determine the key for rate limiting
                if key_func:
                    key = key_func()
                else:
                    key = request.remote_addr
                
                rate_limit_key = f"rate_limit:{f.__name__}:{key}"
                
                try:
                    # Get current count
                    current_count = redis_client.get(rate_limit_key)
                    
                    if current_count is None:
                        # First request in window
                        redis_client.setex(rate_limit_key, window, 1)
                        current_count = 1
                    else:
                        current_count = int(current_count)
                        
                        if current_count >= max_requests:
                            return jsonify({
                                'error': 'Rate limit exceeded',
                                'retry_after': redis_client.ttl(rate_limit_key)
                            }), 429
                        
                        # Increment counter
                        redis_client.incr(rate_limit_key)
                
                except redis.RedisError:
                    # If Redis is down, allow the request
                    pass
                
                return f(*args, **kwargs)
            
            return decorated_function
        return decorator
    
    @staticmethod
    def login_rate_limit(max_attempts=5, window=300):
        """Specific rate limiting for login attempts"""
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                identifier = request.json.get('username') or request.json.get('email')
                if not identifier:
                    return jsonify({'error': 'Username or email required'}), 400
                
                key = f"login_attempts:{identifier}"
                
                try:
                    current_attempts = redis_client.get(key)
                    
                    if current_attempts and int(current_attempts) >= max_attempts:
                        ttl = redis_client.ttl(key)
                        return jsonify({
                            'error': 'Too many login attempts',
                            'retry_after': ttl if ttl > 0 else window
                        }), 429
                
                except redis.RedisError:
                    pass
                
                # Execute the login function
                response = f(*args, **kwargs)
                
                # If login failed, increment attempts
                if response[1] == 401:  # Unauthorized
                    try:
                        if redis_client.exists(key):
                            redis_client.incr(key)
                        else:
                            redis_client.setex(key, window, 1)
                    except redis.RedisError:
                        pass
                else:
                    # Successful login, clear attempts
                    try:
                        redis_client.delete(key)
                    except redis.RedisError:
                        pass
                
                return response
            
            return decorated_function
        return decorator
    
    @staticmethod
    def cors_middleware():
        """CORS middleware for cross-origin requests"""
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                response = f(*args, **kwargs)
                
                # Add CORS headers
                if hasattr(response, 'headers'):
                    response.headers['Access-Control-Allow-Origin'] = '*'
                    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
                    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
                
                return response
            
            return decorated_function
        return decorator
    
    @staticmethod
    def security_headers():
        """Add security headers to responses"""
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                response = f(*args, **kwargs)
                
                if hasattr(response, 'headers'):
                    response.headers['X-Content-Type-Options'] = 'nosniff'
                    response.headers['X-Frame-Options'] = 'DENY'
                    response.headers['X-XSS-Protection'] = '1; mode=block'
                    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
                
                return response
            
            return decorated_function
        return decorator

# Legacy function for backward compatibility
def token_required(f):
    """Legacy token verification decorator"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 403

        if token.startswith('Bearer '):
            token = token.split(' ')[1]

        payload = verify_token(token)
        if not payload:
            return jsonify({'message': 'Token is invalid!'}), 403

        return f(*args, **kwargs)

    return decorated