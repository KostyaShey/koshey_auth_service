from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text
from sqlalchemy.ext.hybrid import hybrid_property
import bcrypt
import hashlib
import uuid

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email_hash = Column(String(64), unique=True, nullable=False, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    password_hash = Column(String(128), nullable=False)
    account_creation_date = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_login_date = Column(DateTime, nullable=True)
    name = Column(String(100), nullable=False)
    surname = Column(String(100), nullable=False)
    account_activation_status = Column(Boolean, default=False, nullable=False)
    phone_hash = Column(String(64), nullable=True)
    email_verification_token = Column(String(128), nullable=True)
    password_reset_token = Column(String(128), nullable=True)
    password_reset_expires = Column(DateTime, nullable=True)
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    def __init__(self, email, username, password, name, surname, phone_number=None):
        self.email_hash = self._hash_email(email)
        self.username = username
        self.password_hash = self._hash_password(password)
        self.name = name
        self.surname = surname
        if phone_number:
            self.phone_hash = self._hash_phone(phone_number)
        self.email_verification_token = str(uuid.uuid4())

    @staticmethod
    def _hash_email(email):
        """Hash email for privacy while maintaining uniqueness"""
        return hashlib.sha256(email.lower().encode('utf-8')).hexdigest()

    @staticmethod
    def _hash_phone(phone):
        """Hash phone number for privacy while maintaining searchability"""
        return hashlib.sha256(phone.encode('utf-8')).hexdigest()

    @staticmethod
    def _hash_password(password):
        """Hash password using bcrypt"""
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def verify_password(self, password):
        """Verify password against hash"""
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))

    def set_password(self, password):
        """Set new password"""
        self.password_hash = self._hash_password(password)
        self.updated_at = datetime.utcnow()

    @classmethod
    def find_by_email(cls, email):
        """Find user by email"""
        email_hash = cls._hash_email(email)
        return cls.query.filter_by(email_hash=email_hash).first()

    @classmethod
    def find_by_username(cls, username):
        """Find user by username"""
        return cls.query.filter_by(username=username).first()

    @classmethod
    def find_by_phone(cls, phone_number):
        """Find user by phone number"""
        phone_hash = cls._hash_phone(phone_number)
        return cls.query.filter_by(phone_hash=phone_hash).first()

    def update_last_login(self):
        """Update last login timestamp"""
        self.last_login_date = datetime.utcnow()
        self.updated_at = datetime.utcnow()
        db.session.commit()

    def activate_account(self):
        """Activate user account"""
        self.account_activation_status = True
        self.email_verification_token = None
        self.updated_at = datetime.utcnow()
        db.session.commit()

    def is_account_locked(self):
        """Check if account is locked due to failed login attempts"""
        if self.locked_until and self.locked_until > datetime.utcnow():
            return True
        return False

    def increment_failed_login(self):
        """Increment failed login attempts and lock if necessary"""
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= 5:
            self.locked_until = datetime.utcnow() + timedelta(minutes=30)
        self.updated_at = datetime.utcnow()
        db.session.commit()

    def reset_failed_login(self):
        """Reset failed login attempts"""
        self.failed_login_attempts = 0
        self.locked_until = None
        self.updated_at = datetime.utcnow()
        db.session.commit()

    def generate_password_reset_token(self):
        """Generate password reset token"""
        self.password_reset_token = str(uuid.uuid4())
        self.password_reset_expires = datetime.utcnow() + timedelta(hours=1)
        self.updated_at = datetime.utcnow()
        db.session.commit()
        return self.password_reset_token

    def to_dict(self, include_sensitive=False):
        """Convert user to dictionary"""
        data = {
            'id': self.id,
            'username': self.username,
            'name': self.name,
            'surname': self.surname,
            'account_creation_date': self.account_creation_date.isoformat() if self.account_creation_date else None,
            'last_login_date': self.last_login_date.isoformat() if self.last_login_date else None,
            'account_activation_status': self.account_activation_status,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
        
        if include_sensitive:
            data.update({
                'failed_login_attempts': self.failed_login_attempts,
                'locked_until': self.locked_until.isoformat() if self.locked_until else None
            })
        
        return data

    def __repr__(self):
        return f"<User(id={self.id}, username={self.username})>"


class RefreshToken(db.Model):
    __tablename__ = 'refresh_tokens'

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), db.ForeignKey('users.id'), nullable=False)
    token_hash = Column(String(128), unique=True, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    revoked = Column(Boolean, default=False, nullable=False)

    user = db.relationship('User', backref=db.backref('refresh_tokens', lazy=True))

    def __init__(self, user_id, token, expires_at):
        self.user_id = user_id
        self.token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
        self.expires_at = expires_at

    @classmethod
    def find_by_token(cls, token):
        """Find refresh token by token value"""
        token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
        return cls.query.filter_by(token_hash=token_hash, revoked=False).first()

    def is_expired(self):
        """Check if token is expired"""
        return datetime.utcnow() > self.expires_at

    def revoke(self):
        """Revoke the token"""
        self.revoked = True
        db.session.commit()

    @classmethod
    def cleanup_expired(cls):
        """Remove expired tokens"""
        expired_tokens = cls.query.filter(cls.expires_at < datetime.utcnow()).all()
        for token in expired_tokens:
            db.session.delete(token)
        db.session.commit()


# Import at the end to avoid circular imports
from datetime import timedelta