"""
unit tests for security utilities.

these tests verify the core security functions including:
- password hashing and verification
- password strength validation
- jwt token creation and validation
"""

import pytest
from jose import jwt
from datetime import datetime, timedelta, timezone

from app.core.security import (
    hash_password,
    verify_password,
    validate_password_strength,
    create_token,
    decode_token
)
from app.core.config import JWT_ALGORITHM, JWT_SECRET_KEY

class TestPasswordFunctions:
    """tests for password hashing and verification functions."""
    
    def test_hash_password(self):
        """test that hash_password returns a string and is not the original password."""
        
        password = "TestPassword123"
        hashed = hash_password(password)
        
        assert isinstance(hashed, str)
        assert hashed != password
        assert len(hashed) > 0
    
    def test_verify_password_valid(self):
        """test that verify_password returns True for valid password."""
        
        password = "TestPassword123"
        hashed = hash_password(password)
        
        assert verify_password(password, hashed) is True
        
    def test_verify_password_invalid(self):
        """test that verify_password returns False for invalid password."""
        
        password = "TestPassword123"
        wrong_password = "WrongPassword123"
        hashed = hash_password(password)
        
        assert verify_password(wrong_password, hashed) is False
        
class TestPasswordValidation:
    """tests for password strength validation."""
    
    def test_validate_password_valid(self):
        """test that validate_password_strength returns True for valid passwords."""
        
        valid_passwords = [
            "Password123",
            "StrongP4ssword",
            "Abcdef1234",
            "Test@Password1"
        ]
        
        for password in valid_passwords:
            assert validate_password_strength(password) is True
            
    def test_validate_password_too_short(self):
        """test that validate_password_strength raises ValueError for short passwords."""
        
        with pytest.raises(ValueError, match="password must be at least 8 characters long"):
            validate_password_strength("Short1")
            
    def test_validate_password_no_uppercase(self):
        """test that validate_password_strength raises ValueError for passwords with no uppercase."""
        with pytest.raises(ValueError, match="password must contain at least one uppercase letter"):
            validate_password_strength("password123")
    
    def test_validate_password_no_lowercase(self):
        """test that validate_password_strength raises ValueError for passwords with no lowercase."""
        with pytest.raises(ValueError, match="password must contain at least one lowercase letter"):
            validate_password_strength("PASSWORD123")
    
    def test_validate_password_no_digit(self):
        """test that validate_password_strength raises ValueError for passwords with no digit."""
        with pytest.raises(ValueError, match="password must contain at least one digit"):
            validate_password_strength("PasswordOnly")
            
class TestTokenFunctions:
    """tests for JWT token creation and validation."""
    
    def test_create_token(self):
        """test that create_token returns a JWT string with expected claims."""
        
        data = {"sub": "user123", "email": "test@example.com"}
        token = create_token(data)
        
        assert isinstance(token, str)

        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        
        assert payload["sub"] == data["sub"]
        assert payload["email"] == data["email"]
        
        assert "exp" in payload
        assert "iat" in payload
        assert "jti" in payload
        
    def test_decode_token_valid(self):
        """ test that decode_token correctly decodes a valid token."""
        
        data = {"sub": "user123", "email": "test@example.com"}
        token = create_token(data)
        
        payload = decode_token(token)
        
        assert payload["sub"] == data["sub"]
        assert payload["email"] == data["email"]
        
    def test_decode_token_expired(self):
        """test that decode_token raises ValueError for expired tokens."""
        
        now = datetime.now(timezone.utc)
        data = {
            "sub": "user123", 
            "exp": now - timedelta(seconds=1)
        }
        token = jwt.encode(data, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
        
        with pytest.raises(ValueError, match="invalid or expired token"):
            decode_token(token)
            
    def test_decode_token_invalid_signature(self):
        """test that decode_token raises ValueError for tokens with invalid signature."""
        
        data = {"sub": "user123"}
        token = jwt.encode(data, "wrong_secret", algorithm=JWT_ALGORITHM)
        
        with pytest.raises(ValueError, match="invalid or expired token"):
            decode_token(token)