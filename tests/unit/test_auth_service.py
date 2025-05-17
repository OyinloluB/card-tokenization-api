# tests/unit/test_auth_service.py
import pytest
from fastapi import HTTPException
from unittest.mock import patch, MagicMock
from sqlalchemy.exc import SQLAlchemyError
from jose import jwt
import uuid

from app.services.auth_service import get_user_by_email, create_user, verify_user
from app.schemas.user import UserCreate
from app.models.user import User
from app.core.config import JWT_SECRET_KEY, JWT_ALGORITHM
from tests.test_config import override_get_db

class TestGetUserByEmail:
    """tests for get_user_by_email function."""
    
    def test_get_user_by_email_existing(self, test_db, test_user):
        """test retrieving an existing user by email."""
        
        db = next(override_get_db())
        
        user = get_user_by_email(db, test_user.email)
        
        assert user is not None
        assert user.id == test_user.id
        assert user.email == test_user.email
        
    def test_get_user_by_email_nonexistent(self, test_db):
        """test retrieving a non-existent user by email."""
        db = next(override_get_db())
        
        user = get_user_by_email(db, "nonexistent@example.com")
        
        assert user is None

class TestCreateUser:
    """test for create_user function."""
    
    def test_create_user_success(self, test_db):
        """test successful user creation."""
        
        db = next(override_get_db())
        
        user_data = UserCreate(
            email="newuser@example.com",
            password="SecurePassword123"
        )
        
        user = create_user(db, user_data)
        
        assert user is not None
        assert user.email == user_data.email
        assert user.hashed_password is not None
        assert user.hashed_password != user_data.password
        
        db.delete(user)
        db.commit()
        
    def test_create_user_db_error(self, test_db):
        """test handling of database errors during user creation."""
        
        db = next(override_get_db())
        
        user_data = UserCreate(
            email="error@example.com",
            password="SecurePassword123"
        )
        
        with patch.object(db, 'commit', side_effect=SQLAlchemyError("Database error")):
            with pytest.raises(HTTPException) as exc_info:
                create_user(db, user_data)
                
        assert exc_info.value.status_code == 500
        assert "database error occurred" in str(exc_info.value.detail)

class TestVerifyUser:
    """tests for verify_user function."""
    
    @patch('app.services.auth_service.decode_token')
    def test_verify_user_success(self, mock_decode_token, test_db, test_user):
        """test successful user token verification."""

        db = next(override_get_db())
        
        # prepare mock values
        token_payload = {"sub": str(test_user.id), "email": test_user.email}
        mock_decode_token.return_value = token_payload
        
        # create credentials mock
        credentials = MagicMock()
        credentials.credentials = "mock.jwt.token"
        
        # override db query to return test_user directly
        with patch.object(db, 'query') as mock_query:
            mock_filter = MagicMock()
            mock_query.return_value.filter.return_value = mock_filter
            mock_filter.first.return_value = test_user
            
            result = verify_user(credentials, db)
            
            assert result == token_payload
            mock_decode_token.assert_called_once_with(credentials.credentials) 
    
    @patch('app.services.auth_service.decode_token')
    def test_verify_user_invalid_token(self, mock_decode_token, test_db):
        """test handling of invalid token."""
   
        db = next(override_get_db())
        credentials = MagicMock()
        credentials.credentials = "invalid.token"
        
        # configure mock to raise error with the error message format
        mock_decode_token.side_effect = ValueError("invalid or expired token: Invalid header string")
        
        with pytest.raises(ValueError) as exc_info:
            verify_user(credentials, db)
        
        assert "invalid or expired token" in str(exc_info.value)
    
    @patch('app.services.auth_service.decode_token')
    def test_verify_user_missing_sub(self, mock_decode_token, test_db):
        """test handling of token without user ID."""

        db = next(override_get_db())
        credentials = MagicMock()
        credentials.credentials = "token.without.sub"
        
        mock_decode_token.return_value = {"email": "user@example.com"}
        
        with pytest.raises(HTTPException) as exc_info:
            verify_user(credentials, db)
        
        assert exc_info.value.status_code == 400
        assert "user ID missing in token" in str(exc_info.value.detail)
            
    @patch('app.services.auth_service.decode_token')
    def test_verify_user_nonexistent_user(self, mock_decode_token, test_db):
        """test handling of token with non-existent user ID."""

        db = next(override_get_db())
        credentials = MagicMock()
        credentials.credentials = "token.with.nonexistent.user"
        
        mock_decode_token.return_value = {"sub": "nonexistent-user-id"}
        
        with patch.object(db, 'query') as mock_query:
            mock_filter = MagicMock()
            mock_query.return_value.filter.return_value = mock_filter
            mock_filter.first.return_value = None
            
            with pytest.raises(HTTPException) as exc_info:
                verify_user(credentials, db)
            
            assert exc_info.value.status_code == 404
            assert "user not found" in str(exc_info.value.detail)
