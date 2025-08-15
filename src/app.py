import os
import logging
from datetime import datetime
from flask import Flask, jsonify, request
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import redis
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Import configurations
from config.settings import *

# Import shared database instance
from database import db

# Initialize extensions
migrate = Migrate()
jwt = JWTManager()

def create_app(config_name='default'):
    """Application factory pattern"""
    app = Flask(__name__)
    
    # Load configuration
    app.config.from_object('config.settings')
    
    # Initialize extensions with app
    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)
    
    # Initialize CORS
    CORS(app, origins=CORS_ORIGINS, supports_credentials=True)
    
    # Initialize rate limiter
    limiter = Limiter(
        key_func=get_remote_address,
        default_limits=[RATELIMIT_DEFAULT],
        storage_uri=RATELIMIT_STORAGE_URL
    )
    limiter.init_app(app)
    
    # Configure logging
    if not app.debug and not app.testing:
        if not os.path.exists('logs'):
            os.mkdir('logs')
        
        file_handler = logging.FileHandler('logs/auth_service.log')
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)
        app.logger.info('Auth microservice startup')
    
    # Import models to ensure they're registered
    from models.user import User, RefreshToken
    
    # Register blueprints
    from routes.auth import auth_bp
    from routes.users import users_bp
    from routes.oauth import oauth_bp
    
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(users_bp, url_prefix='/users')
    app.register_blueprint(oauth_bp, url_prefix='/oauth')
    
    # Global error handlers
    @app.errorhandler(400)
    def bad_request(error):
        return jsonify({'error': 'Bad request'}), 400
    
    @app.errorhandler(401)
    def unauthorized(error):
        return jsonify({'error': 'Unauthorized'}), 401
    
    @app.errorhandler(403)
    def forbidden(error):
        return jsonify({'error': 'Forbidden'}), 403
    
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({'error': 'Not found'}), 404
    
    @app.errorhandler(405)
    def method_not_allowed(error):
        return jsonify({'error': 'Method not allowed'}), 405
    
    @app.errorhandler(429)
    def rate_limit_exceeded(error):
        return jsonify({
            'error': 'Rate limit exceeded',
            'message': str(error.description)
        }), 429
    
    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        app.logger.error(f'Server Error: {error}')
        return jsonify({'error': 'Internal server error'}), 500
    
    # Health check endpoint
    @app.route('/health', methods=['GET'])
    def health_check():
        """Health check endpoint for monitoring"""
        try:
            # Check database connection
            db.session.execute(db.text('SELECT 1'))
            db_status = 'healthy'
        except Exception:
            db_status = 'unhealthy'
        
        try:
            # Check Redis connection
            redis_client = redis.Redis.from_url(REDIS_URL)
            redis_client.ping()
            redis_status = 'healthy'
        except Exception:
            redis_status = 'unhealthy'
        
        status_code = 200 if db_status == 'healthy' and redis_status == 'healthy' else 503
        
        return jsonify({
            'status': 'healthy' if status_code == 200 else 'unhealthy',
            'timestamp': datetime.utcnow().isoformat(),
            'service': 'auth-service',
            'version': '1.0.0',
            'checks': {
                'database': db_status,
                'redis': redis_status
            }
        }), status_code
    
    # Metrics endpoint
    @app.route('/metrics', methods=['GET'])
    def metrics():
        """Metrics endpoint for monitoring"""
        try:
            user_count = User.query.count()
            active_users = User.query.filter_by(account_activation_status=True).count()
            
            return jsonify({
                'timestamp': datetime.utcnow().isoformat(),
                'metrics': {
                    'total_users': user_count,
                    'active_users': active_users,
                    'inactive_users': user_count - active_users
                }
            }), 200
        except Exception as e:
            app.logger.error(f'Metrics error: {e}')
            return jsonify({'error': 'Failed to retrieve metrics'}), 500
    
    # Root endpoint
    @app.route('/', methods=['GET'])
    def root():
        """Root endpoint with API information"""
        return jsonify({
            'service': 'Auth Microservice',
            'version': '1.0.0',
            'status': 'running',
            'endpoints': {
                'auth': '/auth',
                'users': '/users',
                'oauth': '/oauth',
                'health': '/health',
                'metrics': '/metrics'
            },
            'oauth_endpoints': {
                'token': '/oauth/token',
                'introspect': '/oauth/introspect',
                'revoke': '/oauth/revoke',
                'authorize': '/oauth/authorize',
                'clients': '/oauth/clients'
            },
            'documentation': '/docs'  # Future: Add Swagger/OpenAPI docs
        }), 200
    
    # CORS preflight handling
    @app.before_request
    def handle_preflight():
        if request.method == "OPTIONS":
            response = jsonify({'message': 'OK'})
            response.headers.add("Access-Control-Allow-Origin", "*")
            response.headers.add('Access-Control-Allow-Headers', "*")
            response.headers.add('Access-Control-Allow-Methods', "*")
            return response
    
    # Security headers
    @app.after_request
    def after_request(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        if not app.debug:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        return response
    
    return app

# Create app instance
app = create_app()

if __name__ == '__main__':
    with app.app_context():
        # Create all database tables
        db.create_all()
        
        # Clean up expired tokens on startup
        from models.user import RefreshToken
        RefreshToken.cleanup_expired()
    
    # Run the application
    app.run(
        host='0.0.0.0',
        port=int(os.environ.get('PORT', 5000)),
        debug=os.environ.get('DEBUG', 'false').lower() == 'true'
    )