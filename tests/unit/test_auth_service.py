# tests/unit/test_auth_service.py
import pytest
from fastapi import HTTPException
from unittest.mock import patch, MagicMock
from sqlalchemy.exc import SQLAlchemyError

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