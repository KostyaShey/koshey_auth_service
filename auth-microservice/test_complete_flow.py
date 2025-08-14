#!/usr/bin/env python3
"""
Test the complete registration -> activation -> login flow
"""
import requests
import json
import time
import sys
import os

# Add src to path
sys.path.append('./src')
sys.path.append('.')

BASE_URL = 'http://localhost:5000'

def test_complete_flow():
    print("=== Testing Complete Registration -> Activation -> Login Flow ===\n")
    
    # Test user data
    timestamp = int(time.time())
    test_user = {
        'username': f'testuser_complete_{timestamp}',
        'email': f'testcomplete{timestamp}@gmail.com',
        'password': 'SecureP@ssw0rd!',
        'name': 'Test',
        'surname': 'User'
    }
    
    print("1. Registering user...")
    reg_response = requests.post(f'{BASE_URL}/auth/register', json=test_user)
    print(f"   Registration Status: {reg_response.status_code}")
    
    if reg_response.status_code != 201:
        print(f"   ❌ Registration failed: {reg_response.text}")
        return False
    
    print("   ✅ User registered successfully")
    
    print("\n2. Getting verification token from database...")
    try:
        from src.app import create_app
        from src.models.user import User
        
        app = create_app()
        with app.app_context():
            user = User.find_by_username(test_user['username'])
            if not user:
                print("   ❌ User not found in database")
                return False
            
            verification_token = user.email_verification_token
            print(f"   📧 Verification token: {verification_token[:8]}...")
            
            print("\n3. Activating account via API...")
            activation_response = requests.post(
                f'{BASE_URL}/auth/verify-email',
                json={'token': verification_token}
            )
            print(f"   Activation Status: {activation_response.status_code}")
            
            if activation_response.status_code == 200:
                print("   ✅ Account activated successfully")
            else:
                print(f"   ❌ Activation failed: {activation_response.text}")
                return False
    
    except Exception as e:
        print(f"   ❌ Error accessing database: {e}")
        return False
    
    print("\n4. Attempting login after activation...")
    login_data = {
        'username': test_user['username'],
        'password': test_user['password']
    }
    
    login_response = requests.post(f'{BASE_URL}/auth/login', json=login_data)
    print(f"   Login Status: {login_response.status_code}")
    
    if login_response.status_code == 200:
        login_data = login_response.json()
        print("   ✅ Login successful!")
        print(f"   Access token: {login_data['access_token'][:20]}...")
        return True
    else:
        print(f"   ❌ Login failed: {login_response.text}")
        return False

if __name__ == '__main__':
    success = test_complete_flow()
    if success:
        print("\n🎉 Complete flow test PASSED!")
    else:
        print("\n❌ Complete flow test FAILED!")
