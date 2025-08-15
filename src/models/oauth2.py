from datetime import datetime, timedelta
from sqlalchemy import Column, String, DateTime, Boolean, Integer, Text
import uuid
import hashlib
import secrets

# Import shared db instance from database module
from database import db

class OAuth2Client(db.Model):
    __tablename__ = 'oauth2_clients'

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    client_id = Column(String(48), unique=True, nullable=False, index=True)
    client_secret_hash = Column(String(128), nullable=False)
    client_name = Column(String(100), nullable=False)
    redirect_uris = Column(Text, nullable=True)  # JSON string of URIs
    grant_types = Column(Text, nullable=False)  # JSON string of grant types
    scopes = Column(Text, nullable=False)  # JSON string of scopes
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    def __init__(self, client_id, client_secret, client_name, redirect_uris=None, grant_types=None, scopes=None):
        self.client_id = client_id
        self.client_secret_hash = self._hash_secret(client_secret)
        self.client_name = client_name
        self.redirect_uris = ','.join(redirect_uris) if redirect_uris else ''
        self.grant_types = ','.join(grant_types) if grant_types else 'authorization_code,refresh_token'
        self.scopes = ','.join(scopes) if scopes else 'read,write'

    @staticmethod
    def _hash_secret(secret):
        """Hash client secret"""
        return hashlib.sha256(secret.encode('utf-8')).hexdigest()

    def verify_secret(self, secret):
        """Verify client secret"""
        return self.client_secret_hash == self._hash_secret(secret)

    def get_redirect_uris(self):
        """Get redirect URIs as list"""
        return self.redirect_uris.split(',') if self.redirect_uris else []

    def get_grant_types(self):
        """Get grant types as list"""
        return self.grant_types.split(',') if self.grant_types else []

    def get_scopes(self):
        """Get scopes as list"""
        return self.scopes.split(',') if self.scopes else []

    def has_scope(self, scope):
        """Check if client has specific scope"""
        return scope in self.get_scopes()

    def has_grant_type(self, grant_type):
        """Check if client supports grant type"""
        return grant_type in self.get_grant_types()

    @classmethod
    def find_by_client_id(cls, client_id):
        """Find client by client_id"""
        return cls.query.filter_by(client_id=client_id, is_active=True).first()

    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'client_id': self.client_id,
            'client_name': self.client_name,
            'redirect_uris': self.get_redirect_uris(),
            'grant_types': self.get_grant_types(),
            'scopes': self.get_scopes(),
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class OAuth2AuthorizationCode(db.Model):
    __tablename__ = 'oauth2_authorization_codes'

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    code = Column(String(128), unique=True, nullable=False, index=True)
    client_id = Column(String(48), db.ForeignKey('oauth2_clients.client_id'), nullable=False)
    user_id = Column(String(36), db.ForeignKey('users.id'), nullable=False)
    redirect_uri = Column(String(255), nullable=False)
    scope = Column(String(255), nullable=False)
    code_challenge = Column(String(128), nullable=True)  # PKCE
    code_challenge_method = Column(String(10), nullable=True)  # PKCE
    expires_at = Column(DateTime, nullable=False)
    used = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    client = db.relationship('OAuth2Client', backref=db.backref('authorization_codes', lazy=True))
    user = db.relationship('User', backref=db.backref('authorization_codes', lazy=True))

    def __init__(self, client_id, user_id, redirect_uri, scope, code_challenge=None, code_challenge_method=None):
        self.code = secrets.token_urlsafe(32)
        self.client_id = client_id
        self.user_id = user_id
        self.redirect_uri = redirect_uri
        self.scope = scope
        self.code_challenge = code_challenge
        self.code_challenge_method = code_challenge_method
        self.expires_at = datetime.utcnow() + timedelta(minutes=10)  # 10 minutes expiry

    def is_expired(self):
        """Check if authorization code is expired"""
        return datetime.utcnow() > self.expires_at

    def is_valid(self):
        """Check if authorization code is valid"""
        return not self.used and not self.is_expired()

    def use_code(self):
        """Mark code as used"""
        self.used = True
        db.session.commit()

    @classmethod
    def find_by_code(cls, code):
        """Find authorization code by code"""
        return cls.query.filter_by(code=code).first()

    @classmethod
    def cleanup_expired(cls):
        """Remove expired authorization codes"""
        expired_codes = cls.query.filter(cls.expires_at < datetime.utcnow()).all()
        for code in expired_codes:
            db.session.delete(code)
        db.session.commit()


class OAuth2Token(db.Model):
    __tablename__ = 'oauth2_tokens'

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    token_type = Column(String(20), nullable=False)  # 'access_token' or 'refresh_token'
    token_hash = Column(String(128), unique=True, nullable=False, index=True)
    client_id = Column(String(48), db.ForeignKey('oauth2_clients.client_id'), nullable=False)
    user_id = Column(String(36), db.ForeignKey('users.id'), nullable=True)  # Null for client credentials
    scope = Column(String(255), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    revoked = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    client = db.relationship('OAuth2Client', backref=db.backref('tokens', lazy=True))
    user = db.relationship('User', backref=db.backref('oauth2_tokens', lazy=True))

    def __init__(self, token, token_type, client_id, scope, expires_at, user_id=None):
        self.token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
        self.token_type = token_type
        self.client_id = client_id
        self.user_id = user_id
        self.scope = scope
        self.expires_at = expires_at

    def is_expired(self):
        """Check if token is expired"""
        return datetime.utcnow() > self.expires_at

    def is_valid(self):
        """Check if token is valid"""
        return not self.revoked and not self.is_expired()

    def revoke(self):
        """Revoke the token"""
        self.revoked = True
        db.session.commit()

    def get_scopes(self):
        """Get scopes as list"""
        return self.scope.split(' ') if self.scope else []

    def has_scope(self, scope):
        """Check if token has specific scope"""
        return scope in self.get_scopes()

    @classmethod
    def find_by_token(cls, token):
        """Find token by token value"""
        token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
        return cls.query.filter_by(token_hash=token_hash, revoked=False).first()

    @classmethod
    def cleanup_expired(cls):
        """Remove expired tokens"""
        expired_tokens = cls.query.filter(cls.expires_at < datetime.utcnow()).all()
        for token in expired_tokens:
            db.session.delete(token)
        db.session.commit()

    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'token_type': self.token_type,
            'client_id': self.client_id,
            'user_id': self.user_id,
            'scope': self.scope,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'revoked': self.revoked,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


# Import User model to avoid circular imports
from models.user import User
