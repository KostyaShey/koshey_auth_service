import re
import phonenumbers
from email_validator import validate_email, EmailNotValidError
from typing import Tuple, List

def validate_email_format(email: str) -> Tuple[bool, str]:
    """Validate email format"""
    try:
        validated_email = validate_email(email)
        return True, validated_email.normalized
    except EmailNotValidError as e:
        return False, str(e)

def validate_username(username: str) -> Tuple[bool, List[str]]:
    """Validate username format and requirements"""
    errors = []
    
    if not username:
        errors.append("Username is required")
        return False, errors
    
    if len(username) < 3:
        errors.append("Username must be at least 3 characters long")
    
    if len(username) > 30:
        errors.append("Username must be no more than 30 characters long")
    
    if not re.match(r'^[a-zA-Z0-9_-]+$', username):
        errors.append("Username can only contain letters, numbers, hyphens, and underscores")
    
    if username.startswith('-') or username.startswith('_'):
        errors.append("Username cannot start with hyphen or underscore")
    
    return len(errors) == 0, errors

def validate_phone_number(phone: str, region: str = None) -> Tuple[bool, str]:
    """Validate and format phone number"""
    try:
        parsed_number = phonenumbers.parse(phone, region)
        if phonenumbers.is_valid_number(parsed_number):
            formatted_number = phonenumbers.format_number(
                parsed_number, 
                phonenumbers.PhoneNumberFormat.E164
            )
            return True, formatted_number
        else:
            return False, "Invalid phone number"
    except phonenumbers.NumberParseException as e:
        return False, f"Phone number parsing error: {e}"

def validate_name(name: str, field_name: str = "Name") -> Tuple[bool, List[str]]:
    """Validate name fields (name, surname)"""
    errors = []
    
    if not name:
        errors.append(f"{field_name} is required")
        return False, errors
    
    if len(name) < 1:
        errors.append(f"{field_name} must not be empty")
    
    if len(name) > 100:
        errors.append(f"{field_name} must be no more than 100 characters long")
    
    if not re.match(r'^[a-zA-ZÀ-ÿ\s\'-]+$', name):
        errors.append(f"{field_name} can only contain letters, spaces, hyphens, and apostrophes")
    
    return len(errors) == 0, errors

def sanitize_input(input_str: str) -> str:
    """Sanitize input string to prevent XSS"""
    if not input_str:
        return ""
    
    # Remove dangerous characters
    sanitized = re.sub(r'[<>"\']', '', input_str)
    # Remove excessive whitespace
    sanitized = re.sub(r'\s+', ' ', sanitized).strip()
    
    return sanitized

def validate_user_registration_data(data: dict) -> Tuple[bool, dict]:
    """Validate complete user registration data"""
    errors = {}
    
    # Validate email
    email = data.get('email', '').strip().lower()
    if email:
        is_valid, result = validate_email_format(email)
        if not is_valid:
            errors['email'] = [result]
        else:
            data['email'] = result
    else:
        errors['email'] = ['Email is required']
    
    # Validate username
    username = data.get('username', '').strip()
    if username:
        is_valid, username_errors = validate_username(username)
        if not is_valid:
            errors['username'] = username_errors
    else:
        errors['username'] = ['Username is required']
    
    # Validate password (this will be done by password_utils)
    password = data.get('password', '')
    if not password:
        errors['password'] = ['Password is required']
    
    # Validate name
    name = data.get('name', '').strip()
    if name:
        is_valid, name_errors = validate_name(name, "Name")
        if not is_valid:
            errors['name'] = name_errors
        else:
            data['name'] = sanitize_input(name)
    else:
        errors['name'] = ['Name is required']
    
    # Validate surname
    surname = data.get('surname', '').strip()
    if surname:
        is_valid, surname_errors = validate_name(surname, "Surname")
        if not is_valid:
            errors['surname'] = surname_errors
        else:
            data['surname'] = sanitize_input(surname)
    else:
        errors['surname'] = ['Surname is required']
    
    # Validate phone number (optional)
    phone = data.get('phone_number', '').strip()
    if phone:
        is_valid, result = validate_phone_number(phone)
        if not is_valid:
            errors['phone_number'] = [result]
        else:
            data['phone_number'] = result
    
    return len(errors) == 0, errors
