#!/usr/bin/env python3
import sys
import os
import json

# Add src directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from app import create_app
from database import db

def debug_login_test():
    """Debug the login test to see what's happening"""
    app = create_app('testing')
    
    with app.app_context():
        db.create_all()
        client = app.test_client()
        
        # Register user
        user_data = {
            'email': 'test@example.com',
            'username': 'testuser',
            'password': 'SecurePass123!',
            'name': 'Test',
            'surname': 'User'
        }
        
        print("=== REGISTRATION ===")
        reg_response = client.post('/auth/register', 
                                   data=json.dumps(user_data),
                                   content_type='application/json')
        print(f"Registration status: {reg_response.status_code}")
        print(f"Registration response: {json.loads(reg_response.data)}")
        
        # Check user in database
        from models.user import User
        user = User.find_by_username('testuser')
        if user:
            print(f"\n=== USER CHECK ===")
            print(f"User found: {user.username}")
            print(f"Account activation status: {user.account_activation_status}")
            print(f"User ID: {user.id}")
            print(f"Email hash: {user.email_hash}")
        else:
            print("ERROR: User not found in database")
            return
        
        # Try login
        login_data = {
            'username': 'testuser',
            'password': 'SecurePass123!'
        }
        
        print(f"\n=== LOGIN ATTEMPT ===")
        login_response = client.post('/auth/login',
                                     data=json.dumps(login_data),
                                     content_type='application/json')
        print(f"Login status: {login_response.status_code}")
        print(f"Login response: {json.loads(login_response.data)}")

if __name__ == "__main__":
    debug_login_test()
