from functools import wraps
from flask import request, jsonify, current_app
from utils.token_utils import verify_token, is_user_tokens_revoked
from database import db
from models.user import User

def token_required(f):
    """Decorator to require valid JWT token"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Check for token in Authorization header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        # Verify token
        payload = verify_token(token)
        if not payload:
            return jsonify({'error': 'Token is invalid or expired'}), 401
        
        # Check if user tokens are revoked
        user_id = payload.get('sub')
        if is_user_tokens_revoked(user_id):
            return jsonify({'error': 'Token has been revoked'}), 401
        
        # Get user from database
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 401
        
        # Check if account is activated
        if not user.account_activation_status:
            return jsonify({'error': 'Account not activated'}), 401
        
        # Check if account is locked
        if user.is_account_locked():
            return jsonify({'error': 'Account is locked due to too many failed login attempts'}), 423
        
        # Add user to request context
        request.current_user = user
        
        return f(*args, **kwargs)
    
    return decorated

def admin_required(f):
    """Decorator to require admin privileges (can be extended later)"""
    @wraps(f)
    @token_required
    def decorated(*args, **kwargs):
        # For now, all authenticated users can access
        # This can be extended to check for admin role
        return f(*args, **kwargs)
    
    return decorated

def refresh_token_required(f):
    """Decorator to require valid refresh token"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Check for token in request body or Authorization header
        if request.is_json:
            token = request.json.get('refresh_token')
        
        if not token and 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
        
        if not token:
            return jsonify({'error': 'Refresh token is missing'}), 401
        
        # Verify refresh token
        payload = verify_token(token)
        if not payload or payload.get('type') != 'refresh':
            return jsonify({'error': 'Invalid refresh token'}), 401
        
        # Check if user tokens are revoked
        user_id = payload.get('sub')
        if is_user_tokens_revoked(user_id):
            return jsonify({'error': 'Token has been revoked'}), 401
        
        # Get user from database
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 401
        
        # Add user and token to request context
        request.current_user = user
        request.refresh_token = token
        
        return f(*args, **kwargs)
    
    return decorated

def validate_json(required_fields=None):
    """Decorator to validate JSON input"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not request.is_json:
                return jsonify({'error': 'Content-Type must be application/json'}), 400
            
            if required_fields:
                missing_fields = []
                for field in required_fields:
                    if field not in request.json or not request.json[field]:
                        missing_fields.append(field)
                
                if missing_fields:
                    return jsonify({
                        'error': 'Missing required fields',
                        'missing_fields': missing_fields
                    }), 400
            
            return f(*args, **kwargs)
        
        return decorated
    return decorator

def handle_exceptions(f):
    """Decorator to handle common exceptions"""
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            current_app.logger.error(f"Unhandled exception in {f.__name__}: {e}")
            db.session.rollback()
            return jsonify({'error': 'Internal server error'}), 500
    
    return decorated
