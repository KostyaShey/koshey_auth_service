from flask import Blueprint, request, jsonify, current_app
from datetime import datetime, timedelta
import uuid
import secrets

from database import db
from models.user import User, RefreshToken
from utils.password_utils import validate_password_strength
from utils.validators import validate_user_registration_data
from utils.token_utils import (
    create_token_pair, verify_token, blacklist_token, 
    refresh_access_token, is_user_tokens_revoked, revoke_user_tokens
)
from utils.decorators import (
    token_required, refresh_token_required, validate_json, handle_exceptions
)
from middleware.auth_middleware import AuthMiddleware

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['POST'])
@AuthMiddleware.rate_limit(max_requests=5, window=300)  # 5 registrations per 5 minutes
@validate_json(['email', 'username', 'password', 'name', 'surname'])
@handle_exceptions
def register():
    """Register a new user"""
    data = request.json
    
    # Validate input data
    is_valid, validation_errors = validate_user_registration_data(data)
    if not is_valid:
        return jsonify({'error': 'Validation failed', 'details': validation_errors}), 400
    
    # Validate password strength
    password = data.get('password')
    is_password_valid, password_errors = validate_password_strength(password)
    if not is_password_valid:
        return jsonify({'error': 'Password does not meet requirements', 'details': password_errors}), 400
    
    # Check if user already exists
    if User.find_by_email(data['email']):
        return jsonify({'error': 'User with this email already exists'}), 409
    
    if User.find_by_username(data['username']):
        return jsonify({'error': 'User with this username already exists'}), 409
    
    # Check phone number if provided
    phone_number = data.get('phone_number')
    if phone_number and User.find_by_phone(phone_number):
        return jsonify({'error': 'User with this phone number already exists'}), 409
    
    try:
        # Create new user
        new_user = User(
            email=data['email'],
            username=data['username'],
            password=password,
            name=data['name'],
            surname=data['surname'],
            phone_number=phone_number
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        # TODO: Send email verification
        # send_email_verification(new_user.email, new_user.email_verification_token)
        
        return jsonify({
            'message': 'User registered successfully',
            'user_id': new_user.id,
            'email_verification_required': True
        }), 201
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Registration error: {e}")
        return jsonify({'error': 'Registration failed'}), 500

@auth_bp.route('/login', methods=['POST'])
@AuthMiddleware.login_rate_limit(max_attempts=5, window=300)
@validate_json(['username', 'password'])
@handle_exceptions
def login():
    """Authenticate user and return tokens"""
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    # Find user by username or email
    user = User.find_by_username(username) or User.find_by_email(username)
    
    if not user:
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # Check if account is locked
    if user.is_account_locked():
        return jsonify({'error': 'Account is locked due to too many failed login attempts'}), 423
    
    # Verify password
    if not user.verify_password(password):
        user.increment_failed_login()
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # Check if account is activated
    if not user.account_activation_status:
        return jsonify({'error': 'Account not activated. Please check your email.'}), 403
    
    try:
        # Reset failed login attempts
        user.reset_failed_login()
        
        # Update last login
        user.update_last_login()
        
        # Create token pair
        access_token, refresh_token = create_token_pair(user.id)
        
        # Store refresh token in database
        refresh_token_record = RefreshToken(
            user_id=user.id,
            token=refresh_token,
            expires_at=datetime.utcnow() + current_app.config['JWT_REFRESH_TOKEN_EXPIRES']
        )
        db.session.add(refresh_token_record)
        db.session.commit()
        
        return jsonify({
            'message': 'Login successful',
            'access_token': access_token,
            'refresh_token': refresh_token,
            'expires_in': int(current_app.config['JWT_ACCESS_TOKEN_EXPIRES'].total_seconds()),
            'user': user.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Login error: {e}")
        return jsonify({'error': 'Login failed'}), 500

@auth_bp.route('/refresh-token', methods=['POST'])
@refresh_token_required
@handle_exceptions
def refresh_token():
    """Refresh access token using refresh token"""
    user = request.current_user
    old_refresh_token = request.refresh_token
    
    try:
        # Find refresh token in database
        refresh_token_record = RefreshToken.find_by_token(old_refresh_token)
        
        if not refresh_token_record or refresh_token_record.is_expired():
            return jsonify({'error': 'Invalid or expired refresh token'}), 401
        
        # Create new access token
        new_access_token = refresh_access_token(old_refresh_token)
        
        if not new_access_token:
            return jsonify({'error': 'Failed to refresh token'}), 401
        
        return jsonify({
            'access_token': new_access_token,
            'expires_in': int(current_app.config['JWT_ACCESS_TOKEN_EXPIRES'].total_seconds())
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Token refresh error: {e}")
        return jsonify({'error': 'Token refresh failed'}), 500

@auth_bp.route('/logout', methods=['POST'])
@token_required
@handle_exceptions
def logout():
    """Logout user and blacklist tokens"""
    user = request.current_user
    
    try:
        # Get the access token from request
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            access_token = auth_header.split(' ')[1]
            blacklist_token(access_token)
        
        # Revoke refresh token if provided
        refresh_token = request.json.get('refresh_token') if request.is_json else None
        if refresh_token:
            refresh_token_record = RefreshToken.find_by_token(refresh_token)
            if refresh_token_record:
                refresh_token_record.revoke()
        
        return jsonify({'message': 'Logged out successfully'}), 200
        
    except Exception as e:
        current_app.logger.error(f"Logout error: {e}")
        return jsonify({'error': 'Logout failed'}), 500

@auth_bp.route('/verify-email', methods=['POST'])
@validate_json(['token'])
@handle_exceptions
def verify_email():
    """Verify user email with verification token"""
    token = request.json.get('token')
    
    user = User.query.filter_by(email_verification_token=token).first()
    
    if not user:
        return jsonify({'error': 'Invalid verification token'}), 400
    
    if user.account_activation_status:
        return jsonify({'error': 'Account already activated'}), 400
    
    try:
        user.activate_account()
        return jsonify({'message': 'Email verified successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Email verification error: {e}")
        return jsonify({'error': 'Email verification failed'}), 500

@auth_bp.route('/forgot-password', methods=['POST'])
@AuthMiddleware.rate_limit(max_requests=3, window=300)  # 3 requests per 5 minutes
@validate_json(['email'])
@handle_exceptions
def forgot_password():
    """Request password reset"""
    email = request.json.get('email').lower().strip()
    
    user = User.find_by_email(email)
    
    # Always return success to prevent email enumeration
    if user and user.account_activation_status:
        try:
            reset_token = user.generate_password_reset_token()
            # TODO: Send password reset email
            # send_password_reset_email(email, reset_token)
            current_app.logger.info(f"Password reset requested for user {user.id}")
        except Exception as e:
            current_app.logger.error(f"Password reset error: {e}")
    
    return jsonify({'message': 'If the email exists, a password reset link has been sent'}), 200

@auth_bp.route('/reset-password', methods=['POST'])
@AuthMiddleware.rate_limit(max_requests=5, window=300)
@validate_json(['token', 'password'])
@handle_exceptions
def reset_password():
    """Reset password using reset token"""
    token = request.json.get('token')
    new_password = request.json.get('password')
    
    # Validate new password
    is_valid, errors = validate_password_strength(new_password)
    if not is_valid:
        return jsonify({'error': 'Password does not meet requirements', 'details': errors}), 400
    
    user = User.query.filter_by(
        password_reset_token=token,
    ).filter(
        User.password_reset_expires > datetime.utcnow()
    ).first()
    
    if not user:
        return jsonify({'error': 'Invalid or expired reset token'}), 400
    
    try:
        user.set_password(new_password)
        user.password_reset_token = None
        user.password_reset_expires = None
        
        # Revoke all existing tokens for security
        revoke_user_tokens(user.id)
        
        db.session.commit()
        
        return jsonify({'message': 'Password reset successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Password reset error: {e}")
        return jsonify({'error': 'Password reset failed'}), 500

@auth_bp.route('/verify-token', methods=['GET'])
@handle_exceptions
def verify_token_endpoint():
    """Verify token validity (for other services)"""
    token = None
    
    # Extract token from Authorization header
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization']
        if auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
    
    if not token:
        return jsonify({'valid': False, 'error': 'Token is missing'}), 400
    
    # Verify token
    payload = verify_token(token)
    if not payload:
        return jsonify({'valid': False, 'error': 'Invalid or expired token'}), 401
    
    # Check if user tokens are revoked
    user_id = payload.get('sub')
    if is_user_tokens_revoked(user_id):
        return jsonify({'valid': False, 'error': 'Token has been revoked'}), 401
    
    # Get user info
    user = User.query.get(user_id)
    if not user or not user.account_activation_status:
        return jsonify({'valid': False, 'error': 'User not found or inactive'}), 401
    
    return jsonify({
        'valid': True,
        'user_id': user.id,
        'username': user.username,
        'expires_at': payload.get('exp')
    }), 200

@auth_bp.route('/revoke-tokens', methods=['POST'])
@token_required
@handle_exceptions
def revoke_all_tokens():
    """Revoke all tokens for the current user"""
    user = request.current_user
    
    try:
        revoke_user_tokens(user.id)
        
        # Revoke all refresh tokens in database
        for refresh_token in user.refresh_tokens:
            refresh_token.revoke()
        
        db.session.commit()
        
        return jsonify({'message': 'All tokens revoked successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Token revocation error: {e}")
        return jsonify({'error': 'Token revocation failed'}), 500

# Health check endpoint
@auth_bp.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'service': 'auth-microservice'
    }), 200