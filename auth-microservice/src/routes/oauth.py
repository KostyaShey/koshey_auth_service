from flask import Blueprint, request, jsonify, current_app, redirect, url_for
from datetime import datetime, timedelta
import secrets
import base64

from models.user import User, db
from models.oauth2 import OAuth2Client, OAuth2AuthorizationCode, OAuth2Token
from utils.token_utils import (
    create_access_token, create_refresh_token, create_client_credentials_token,
    introspect_token, validate_scope, validate_client_credentials,
    generate_authorization_code, exchange_authorization_code,
    revoke_token_by_value, verify_token
)
from utils.validators import validate_user_registration_data
from utils.decorators import validate_json, handle_exceptions
from middleware.auth_middleware import AuthMiddleware

oauth_bp = Blueprint('oauth', __name__)

@oauth_bp.route('/token', methods=['POST'])
@AuthMiddleware.rate_limit(max_requests=10, window=60)  # 10 requests per minute
@handle_exceptions
def token_endpoint():
    """OAuth2 Token Endpoint - Support multiple grant types"""
    
    # Get client credentials from Authorization header or request body
    client_id = None
    client_secret = None
    
    # Check Authorization header (Basic Auth)
    auth_header = request.headers.get('Authorization', '')
    if auth_header.startswith('Basic '):
        try:
            credentials = base64.b64decode(auth_header[6:]).decode('utf-8')
            client_id, client_secret = credentials.split(':', 1)
        except Exception:
            return jsonify({'error': 'invalid_client', 'error_description': 'Invalid client credentials'}), 401
    else:
        # Check request body
        client_id = request.form.get('client_id')
        client_secret = request.form.get('client_secret')
    
    if not client_id or not client_secret:
        return jsonify({'error': 'invalid_client', 'error_description': 'Client authentication required'}), 401
    
    # Validate client credentials
    if not validate_client_credentials(client_id, client_secret):
        return jsonify({'error': 'invalid_client', 'error_description': 'Invalid client credentials'}), 401
    
    grant_type = request.form.get('grant_type')
    
    if grant_type == 'authorization_code':
        return handle_authorization_code_grant(client_id)
    elif grant_type == 'refresh_token':
        return handle_refresh_token_grant(client_id)
    elif grant_type == 'client_credentials':
        return handle_client_credentials_grant(client_id)
    elif grant_type == 'password':
        return handle_password_grant(client_id)
    else:
        return jsonify({
            'error': 'unsupported_grant_type',
            'error_description': f'Grant type {grant_type} is not supported'
        }), 400

def handle_authorization_code_grant(client_id: str):
    """Handle authorization code grant"""
    code = request.form.get('code')
    redirect_uri = request.form.get('redirect_uri')
    code_verifier = request.form.get('code_verifier')  # PKCE
    
    if not code or not redirect_uri:
        return jsonify({
            'error': 'invalid_request',
            'error_description': 'Missing required parameters'
        }), 400
    
    # Exchange authorization code for tokens
    token_response = exchange_authorization_code(code, client_id, redirect_uri, code_verifier)
    
    if not token_response:
        return jsonify({
            'error': 'invalid_grant',
            'error_description': 'Invalid authorization code'
        }), 400
    
    return jsonify(token_response), 200

def handle_refresh_token_grant(client_id: str):
    """Handle refresh token grant"""
    refresh_token = request.form.get('refresh_token')
    scope = request.form.get('scope')  # Optional scope parameter
    
    if not refresh_token:
        return jsonify({
            'error': 'invalid_request',
            'error_description': 'Missing refresh token'
        }), 400
    
    # Verify refresh token
    payload = verify_token(refresh_token)
    if not payload or payload.get('type') != 'refresh_token':
        return jsonify({
            'error': 'invalid_grant',
            'error_description': 'Invalid refresh token'
        }), 400
    
    # Verify client_id matches
    if payload.get('client_id') != client_id:
        return jsonify({
            'error': 'invalid_grant',
            'error_description': 'Client ID mismatch'
        }), 400
    
    user_id = payload.get('sub')
    token_scope = scope or payload.get('scope', 'read write')
    
    # Create new access token
    access_token = create_access_token(
        user_id=user_id,
        client_id=client_id,
        scope=token_scope
    )
    
    return jsonify({
        'access_token': access_token,
        'token_type': 'Bearer',
        'expires_in': int(current_app.config['JWT_ACCESS_TOKEN_EXPIRES'].total_seconds()),
        'scope': token_scope
    }), 200

def handle_client_credentials_grant(client_id: str):
    """Handle client credentials grant"""
    scope = request.form.get('scope', 'read')
    
    # Validate client supports client_credentials grant
    client = OAuth2Client.find_by_client_id(client_id)
    if not client or not client.has_grant_type('client_credentials'):
        return jsonify({
            'error': 'unauthorized_client',
            'error_description': 'Client not authorized for client credentials grant'
        }), 400
    
    # Validate requested scope
    requested_scopes = set(scope.split(' '))
    client_scopes = set(client.get_scopes())
    
    if not requested_scopes.issubset(client_scopes):
        return jsonify({
            'error': 'invalid_scope',
            'error_description': 'Requested scope exceeds client permissions'
        }), 400
    
    # Create client credentials access token
    access_token = create_client_credentials_token(client_id, scope)
    
    return jsonify({
        'access_token': access_token,
        'token_type': 'Bearer',
        'expires_in': int(current_app.config['JWT_ACCESS_TOKEN_EXPIRES'].total_seconds()),
        'scope': scope
    }), 200

def handle_password_grant(client_id: str):
    """Handle resource owner password credentials grant (for trusted clients only)"""
    username = request.form.get('username')
    password = request.form.get('password')
    scope = request.form.get('scope', 'read write')
    
    if not username or not password:
        return jsonify({
            'error': 'invalid_request',
            'error_description': 'Missing username or password'
        }), 400
    
    # Validate client is trusted for password grant
    client = OAuth2Client.find_by_client_id(client_id)
    if not client or not client.has_grant_type('password'):
        return jsonify({
            'error': 'unauthorized_client',
            'error_description': 'Client not authorized for password grant'
        }), 400
    
    # Authenticate user
    user = User.find_by_username(username) or User.find_by_email(username)
    
    if not user or not user.verify_password(password):
        return jsonify({
            'error': 'invalid_grant',
            'error_description': 'Invalid username or password'
        }), 400
    
    if not user.account_activation_status:
        return jsonify({
            'error': 'invalid_grant',
            'error_description': 'Account not activated'
        }), 400
    
    if user.is_account_locked():
        return jsonify({
            'error': 'invalid_grant',
            'error_description': 'Account is locked'
        }), 400
    
    # Update login information
    user.reset_failed_login()
    user.update_last_login()
    
    # Create tokens
    access_token = create_access_token(
        user_id=user.id,
        client_id=client_id,
        scope=scope
    )
    
    refresh_token = create_refresh_token(
        user_id=user.id,
        client_id=client_id,
        scope=scope
    )
    
    return jsonify({
        'access_token': access_token,
        'refresh_token': refresh_token,
        'token_type': 'Bearer',
        'expires_in': int(current_app.config['JWT_ACCESS_TOKEN_EXPIRES'].total_seconds()),
        'scope': scope
    }), 200

@oauth_bp.route('/introspect', methods=['POST'])
@AuthMiddleware.rate_limit(max_requests=30, window=60)  # 30 requests per minute
@handle_exceptions
def token_introspection():
    """Token Introspection Endpoint (RFC 7662)"""
    if not current_app.config.get('TOKEN_INTROSPECTION_ENABLED', True):
        return jsonify({'error': 'introspection_disabled'}), 503
    
    # Authenticate the introspection request
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Basic '):
        return jsonify({'error': 'invalid_client'}), 401
    
    try:
        credentials = base64.b64decode(auth_header[6:]).decode('utf-8')
        client_id, client_secret = credentials.split(':', 1)
    except Exception:
        return jsonify({'error': 'invalid_client'}), 401
    
    if not validate_client_credentials(client_id, client_secret):
        return jsonify({'error': 'invalid_client'}), 401
    
    # Get token to introspect
    token = request.form.get('token')
    token_type_hint = request.form.get('token_type_hint')
    
    if not token:
        return jsonify({'error': 'invalid_request'}), 400
    
    # Introspect token
    introspection_result = introspect_token(token)
    
    return jsonify(introspection_result), 200

@oauth_bp.route('/revoke', methods=['POST'])
@AuthMiddleware.rate_limit(max_requests=20, window=60)  # 20 requests per minute
@handle_exceptions
def token_revocation():
    """Token Revocation Endpoint (RFC 7009)"""
    if not current_app.config.get('TOKEN_REVOCATION_ENABLED', True):
        return jsonify({'error': 'revocation_disabled'}), 503
    
    # Authenticate the revocation request
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Basic '):
        return jsonify({'error': 'invalid_client'}), 401
    
    try:
        credentials = base64.b64decode(auth_header[6:]).decode('utf-8')
        client_id, client_secret = credentials.split(':', 1)
    except Exception:
        return jsonify({'error': 'invalid_client'}), 401
    
    if not validate_client_credentials(client_id, client_secret):
        return jsonify({'error': 'invalid_client'}), 401
    
    # Get token to revoke
    token = request.form.get('token')
    token_type_hint = request.form.get('token_type_hint')
    
    if not token:
        return jsonify({'error': 'invalid_request'}), 400
    
    # Revoke token
    success = revoke_token_by_value(token, token_type_hint)
    
    if success:
        return '', 200  # RFC 7009 says to return 200 with empty body
    else:
        return jsonify({'error': 'invalid_request'}), 400

@oauth_bp.route('/authorize', methods=['GET', 'POST'])
@handle_exceptions
def authorization_endpoint():
    """OAuth2 Authorization Endpoint"""
    if request.method == 'GET':
        # Show authorization page
        return render_authorization_page()
    else:
        # Handle authorization decision
        return handle_authorization_decision()

def render_authorization_page():
    """Render authorization consent page"""
    # Get authorization parameters
    client_id = request.args.get('client_id')
    redirect_uri = request.args.get('redirect_uri')
    scope = request.args.get('scope', 'read')
    state = request.args.get('state')
    response_type = request.args.get('response_type')
    
    # Validate parameters
    if not client_id or not redirect_uri or response_type != 'code':
        return jsonify({'error': 'invalid_request'}), 400
    
    # Validate client
    client = OAuth2Client.find_by_client_id(client_id)
    if not client:
        return jsonify({'error': 'invalid_client'}), 400
    
    # Validate redirect URI
    if redirect_uri not in client.get_redirect_uris():
        return jsonify({'error': 'invalid_redirect_uri'}), 400
    
    # For now, return JSON response (in production, render HTML form)
    return jsonify({
        'message': 'Authorization required',
        'client_id': client_id,
        'client_name': client.client_name,
        'scope': scope,
        'redirect_uri': redirect_uri,
        'state': state,
        'action': 'POST to this endpoint with user_id and consent=true'
    }), 200

def handle_authorization_decision():
    """Handle user's authorization decision"""
    # This would normally come from authenticated user session
    user_id = request.form.get('user_id')  # In production, get from session
    consent = request.form.get('consent') == 'true'
    
    client_id = request.form.get('client_id')
    redirect_uri = request.form.get('redirect_uri')
    scope = request.form.get('scope', 'read')
    state = request.form.get('state')
    
    if not consent:
        # User denied authorization
        error_params = 'error=access_denied'
        if state:
            error_params += f'&state={state}'
        return redirect(f"{redirect_uri}?{error_params}")
    
    if not user_id:
        return jsonify({'error': 'user_not_authenticated'}), 401
    
    # Validate user exists
    user = User.query.get(user_id)
    if not user or not user.account_activation_status:
        return jsonify({'error': 'invalid_user'}), 400
    
    # Generate authorization code
    try:
        auth_code = generate_authorization_code(client_id, user_id, redirect_uri, scope)
        
        # Redirect back to client with authorization code
        response_params = f'code={auth_code}'
        if state:
            response_params += f'&state={state}'
        
        return redirect(f"{redirect_uri}?{response_params}")
        
    except Exception as e:
        current_app.logger.error(f"Authorization code generation failed: {e}")
        error_params = 'error=server_error'
        if state:
            error_params += f'&state={state}'
        return redirect(f"{redirect_uri}?{error_params}")

@oauth_bp.route('/clients', methods=['POST'])
@handle_exceptions
def register_client():
    """Register new OAuth2 client (for development/testing)"""
    data = request.json or {}
    
    client_name = data.get('client_name')
    redirect_uris = data.get('redirect_uris', [])
    grant_types = data.get('grant_types', ['authorization_code', 'refresh_token'])
    scopes = data.get('scopes', ['read', 'write'])
    
    if not client_name:
        return jsonify({'error': 'Client name is required'}), 400
    
    try:
        # Generate client credentials
        client_id = f"client_{secrets.token_urlsafe(16)}"
        client_secret = secrets.token_urlsafe(32)
        
        # Create client
        client = OAuth2Client(
            client_id=client_id,
            client_secret=client_secret,
            client_name=client_name,
            redirect_uris=redirect_uris,
            grant_types=grant_types,
            scopes=scopes
        )
        
        db.session.add(client)
        db.session.commit()
        
        return jsonify({
            'client_id': client_id,
            'client_secret': client_secret,
            'client_name': client_name,
            'grant_types': grant_types,
            'scopes': scopes,
            'redirect_uris': redirect_uris
        }), 201
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Client registration error: {e}")
        return jsonify({'error': 'Client registration failed'}), 500

# Scope validation decorator
def require_scope(required_scope: str):
    """Decorator to require specific OAuth2 scope"""
    def decorator(f):
        from functools import wraps
        
        @wraps(f)
        def decorated_function(*args, **kwargs):
            auth_header = request.headers.get('Authorization', '')
            if not auth_header.startswith('Bearer '):
                return jsonify({'error': 'access_denied', 'error_description': 'Bearer token required'}), 401
            
            token = auth_header.split(' ')[1]
            payload = verify_token(token)
            
            if not payload:
                return jsonify({'error': 'invalid_token'}), 401
            
            token_scope = payload.get('scope', '')
            if not validate_scope(token_scope, required_scope):
                return jsonify({
                    'error': 'insufficient_scope',
                    'error_description': f'Scope {required_scope} required'
                }), 403
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator
