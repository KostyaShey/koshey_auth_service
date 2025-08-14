import pytest
import json
import sys
import os

# Add src directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from app import create_app
from database import db
from models.user import User

@pytest.fixture
def app():
    """Create and configure a new app instance for each test."""
    app = create_app('testing')
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    
    with app.app_context():
        db.create_all()
        yield app
        db.drop_all()

@pytest.fixture
def client(app):
    """A test client for the app."""
    return app.test_client()

def test_health_check(client):
    """Test health check endpoint."""
    response = client.get('/health')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['service'] == 'auth-microservice'

def test_root_endpoint(client):
    """Test root endpoint."""
    response = client.get('/')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['service'] == 'Auth Microservice'

def test_user_registration(client):
    """Test user registration."""
    user_data = {
        'email': 'test@example.com',
        'username': 'testuser',
        'password': 'SecurePass123!',
        'name': 'Test',
        'surname': 'User'
    }
    
    response = client.post('/auth/register', 
                          data=json.dumps(user_data),
                          content_type='application/json')
    
    assert response.status_code == 201
    data = json.loads(response.data)
    assert 'user_id' in data
    assert data['email_verification_required'] == True

def test_password_validation(client):
    """Test password validation."""
    user_data = {
        'email': 'test@example.com',
        'username': 'testuser',
        'password': 'weak',  # Weak password
        'name': 'Test',
        'surname': 'User'
    }
    
    response = client.post('/auth/register', 
                          data=json.dumps(user_data),
                          content_type='application/json')
    
    assert response.status_code == 400
    data = json.loads(response.data)
    assert 'Password does not meet requirements' in data['error']

def test_duplicate_user_registration(client):
    """Test duplicate user registration."""
    user_data = {
        'email': 'test@example.com',
        'username': 'testuser',
        'password': 'SecurePass123!',
        'name': 'Test',
        'surname': 'User'
    }
    
    # Register user first time
    client.post('/auth/register', 
                data=json.dumps(user_data),
                content_type='application/json')
    
    # Try to register same user again
    response = client.post('/auth/register', 
                          data=json.dumps(user_data),
                          content_type='application/json')
    
    assert response.status_code == 409

def test_login_unverified_user(client):
    """Test login with unverified user."""
    # Register user
    user_data = {
        'email': 'test@example.com',
        'username': 'testuser',
        'password': 'SecurePass123!',
        'name': 'Test',
        'surname': 'User'
    }
    
    client.post('/auth/register', 
                data=json.dumps(user_data),
                content_type='application/json')
    
    # Try to login without verification
    login_data = {
        'username': 'testuser',
        'password': 'SecurePass123!'
    }
    
    response = client.post('/auth/login',
                          data=json.dumps(login_data),
                          content_type='application/json')
    
    assert response.status_code == 403
    data = json.loads(response.data)
    assert 'Account not activated' in data['error']

def test_verify_token_endpoint(client):
    """Test token verification endpoint."""
    response = client.get('/auth/verify-token')
    assert response.status_code == 400
    
    # Test with invalid token
    response = client.get('/auth/verify-token',
                         headers={'Authorization': 'Bearer invalid-token'})
    assert response.status_code == 401
