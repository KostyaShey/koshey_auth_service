from flask import Blueprint, request, jsonify, current_app
from datetime import datetime

from database import db
from models.user import User
from utils.validators import validate_user_registration_data, validate_name
from utils.password_utils import validate_password_strength
from utils.decorators import token_required, validate_json, handle_exceptions
from middleware.auth_middleware import AuthMiddleware

users_bp = Blueprint('users', __name__)

@users_bp.route('/profile', methods=['GET'])
@token_required
@handle_exceptions
def get_profile():
    """Get current user's profile"""
    user = request.current_user
    
    return jsonify({
        'user': user.to_dict(),
        'message': 'Profile retrieved successfully'
    }), 200

@users_bp.route('/profile', methods=['PUT'])
@token_required
@AuthMiddleware.rate_limit(max_requests=10, window=300)  # 10 updates per 5 minutes
@handle_exceptions
def update_profile():
    """Update current user's profile"""
    user = request.current_user
    data = request.json or {}
    
    try:
        updated_fields = []
        
        # Update name
        if 'name' in data:
            name = data['name'].strip()
            is_valid, errors = validate_name(name, "Name")
            if not is_valid:
                return jsonify({'error': 'Invalid name', 'details': errors}), 400
            user.name = name
            updated_fields.append('name')
        
        # Update surname
        if 'surname' in data:
            surname = data['surname'].strip()
            is_valid, errors = validate_name(surname, "Surname")
            if not is_valid:
                return jsonify({'error': 'Invalid surname', 'details': errors}), 400
            user.surname = surname
            updated_fields.append('surname')
        
        # Update phone number
        if 'phone_number' in data:
            phone_number = data['phone_number']
            if phone_number:
                phone_number = phone_number.strip()
                # Check if phone number is already used by another user
                existing_user = User.find_by_phone(phone_number)
                if existing_user and existing_user.id != user.id:
                    return jsonify({'error': 'Phone number already in use'}), 409
                user.phone_hash = User._hash_phone(phone_number)
            else:
                user.phone_hash = None
            updated_fields.append('phone_number')
        
        if updated_fields:
            user.updated_at = datetime.utcnow()
            db.session.commit()
            
            return jsonify({
                'message': 'Profile updated successfully',
                'updated_fields': updated_fields,
                'user': user.to_dict()
            }), 200
        else:
            return jsonify({'message': 'No fields to update'}), 200
            
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Profile update error: {e}")
        return jsonify({'error': 'Profile update failed'}), 500

@users_bp.route('/change-password', methods=['POST'])
@token_required
@AuthMiddleware.rate_limit(max_requests=5, window=300)  # 5 password changes per 5 minutes
@validate_json(['current_password', 'new_password'])
@handle_exceptions
def change_password():
    """Change user's password"""
    user = request.current_user
    data = request.json
    
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    
    # Verify current password
    if not user.verify_password(current_password):
        return jsonify({'error': 'Current password is incorrect'}), 400
    
    # Validate new password
    is_valid, errors = validate_password_strength(new_password)
    if not is_valid:
        return jsonify({'error': 'New password does not meet requirements', 'details': errors}), 400
    
    # Check if new password is different from current
    if user.verify_password(new_password):
        return jsonify({'error': 'New password must be different from current password'}), 400
    
    try:
        user.set_password(new_password)
        db.session.commit()
        
        # Log password change
        current_app.logger.info(f"Password changed for user {user.id}")
        
        return jsonify({'message': 'Password changed successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Password change error: {e}")
        return jsonify({'error': 'Password change failed'}), 500

@users_bp.route('/delete-account', methods=['DELETE'])
@token_required
@AuthMiddleware.rate_limit(max_requests=3, window=3600)  # 3 deletion attempts per hour
@validate_json(['password'])
@handle_exceptions
def delete_account():
    """Delete user's account"""
    user = request.current_user
    password = request.json.get('password')
    
    # Verify password before deletion
    if not user.verify_password(password):
        return jsonify({'error': 'Password is incorrect'}), 400
    
    try:
        # Revoke all tokens
        from utils.token_utils import revoke_user_tokens
        revoke_user_tokens(user.id)
        
        # Delete refresh tokens
        for refresh_token in user.refresh_tokens:
            db.session.delete(refresh_token)
        
        # Delete user
        db.session.delete(user)
        db.session.commit()
        
        current_app.logger.info(f"Account deleted for user {user.id}")
        
        return jsonify({'message': 'Account deleted successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Account deletion error: {e}")
        return jsonify({'error': 'Account deletion failed'}), 500

@users_bp.route('/sessions', methods=['GET'])
@token_required
@handle_exceptions
def get_active_sessions():
    """Get user's active sessions (refresh tokens)"""
    user = request.current_user
    
    try:
        active_sessions = []
        for refresh_token in user.refresh_tokens:
            if not refresh_token.revoked and not refresh_token.is_expired():
                active_sessions.append({
                    'id': refresh_token.id,
                    'created_at': refresh_token.created_at.isoformat(),
                    'expires_at': refresh_token.expires_at.isoformat()
                })
        
        return jsonify({
            'active_sessions': active_sessions,
            'total_count': len(active_sessions)
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Sessions retrieval error: {e}")
        return jsonify({'error': 'Failed to retrieve sessions'}), 500

@users_bp.route('/sessions/<session_id>', methods=['DELETE'])
@token_required
@handle_exceptions
def revoke_session(session_id):
    """Revoke a specific session"""
    user = request.current_user
    
    try:
        refresh_token = RefreshToken.query.filter_by(
            id=session_id,
            user_id=user.id
        ).first()
        
        if not refresh_token:
            return jsonify({'error': 'Session not found'}), 404
        
        refresh_token.revoke()
        db.session.commit()
        
        return jsonify({'message': 'Session revoked successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Session revocation error: {e}")
        return jsonify({'error': 'Session revocation failed'}), 500

@users_bp.route('/account-info', methods=['GET'])
@token_required
@handle_exceptions
def get_account_info():
    """Get detailed account information"""
    user = request.current_user
    
    # Get account statistics
    active_sessions_count = sum(
        1 for token in user.refresh_tokens 
        if not token.revoked and not token.is_expired()
    )
    
    account_info = {
        'user': user.to_dict(include_sensitive=True),
        'security': {
            'active_sessions': active_sessions_count,
            'last_login': user.last_login_date.isoformat() if user.last_login_date else None,
            'account_created': user.account_creation_date.isoformat(),
            'failed_login_attempts': user.failed_login_attempts,
            'account_locked': user.is_account_locked()
        }
    }
    
    return jsonify(account_info), 200

# Admin endpoints (can be extended later with proper role management)
@users_bp.route('/admin/users', methods=['GET'])
@token_required  # Add admin_required decorator when roles are implemented
@handle_exceptions
def list_users():
    """List all users (admin only)"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        
        # Limit per_page to prevent abuse
        per_page = min(per_page, 100)
        
        users = User.query.paginate(
            page=page,
            per_page=per_page,
            error_out=False
        )
        
        return jsonify({
            'users': [user.to_dict() for user in users.items],
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': users.total,
                'pages': users.pages
            }
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Users listing error: {e}")
        return jsonify({'error': 'Failed to retrieve users'}), 500

# Import at the end to avoid circular imports
from models.user import RefreshToken