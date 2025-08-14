#!/usr/bin/env python3
"""
Test script to demonstrate account activation flow
"""
import requests
import json
import time

BASE_URL = 'http://localhost:5000'

def test_account_activation_flow():
    print("=== Testing Account Activation Flow ===\n")
    
    # Test user data
    test_user = {
        'username': f'testuser_activation_{int(time.time())}',
        'email': f'testactivation{int(time.time())}@gmail.com',
        'password': 'SecureP@ssw0rd!',
        'name': 'Test',
        'surname': 'User'
    }
    
    print("1. Registering user...")
    print(f"   Username: {test_user['username']}")
    print(f"   Email: {test_user['email']}")
    
    # Register user
    reg_response = requests.post(f'{BASE_URL}/auth/register', json=test_user)
    print(f"   Registration Status: {reg_response.status_code}")
    
    if reg_response.status_code != 201:
        print(f"   ❌ Registration failed: {reg_response.text}")
        return False
    
    reg_data = reg_response.json()
    print(f"   ✅ User registered successfully")
    print(f"   User ID: {reg_data['user']['id']}")
    
    # Try login before activation
    print("\n2. Attempting login before activation...")
    login_data = {
        'username': test_user['username'],
        'password': test_user['password']
    }
    
    login_response = requests.post(f'{BASE_URL}/auth/login', json=login_data)
    print(f"   Login Status: {login_response.status_code}")
    print(f"   Login Response: {login_response.text}")
    
    if login_response.status_code == 403:
        print("   ✅ Login correctly blocked - account not activated")
    else:
        print("   ⚠️ Login should have been blocked")
    
    # Note: In a real scenario, account would be activated via email verification
    # For this test, we demonstrate that login fails until account is activated
    
    print("\n3. Account Activation Required")
    print("   In production: User would receive email with verification link")
    print("   Email verification endpoint: POST /auth/verify-email")
    print("   Required payload: {'token': '<email_verification_token>'}")
    
    return True

if __name__ == '__main__':
    success = test_account_activation_flow()
    if success:
        print("\n✅ Account activation flow test completed")
    else:
        print("\n❌ Account activation flow test failed")
