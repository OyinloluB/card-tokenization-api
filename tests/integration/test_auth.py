# tests/integration/test_auth.py
import pytest
from fastapi import status
from jose import jwt

from app.core.config import JWT_ALGORITHM, JWT_SECRET_KEY
from tests.test_config import client

class TestAuthEndpoints:
    """Tests for authentication API endpoints."""
    
    def test_signup_success(self):
        """Test successful user signup."""
        # Create signup data
        signup_data = {
            "email": "signup_test@example.com",
            "password": "TestPassword123"
        }
        
        # Make the request
        response = client.post("/auth/signup", json=signup_data)
        
        # Verify response
        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()
        assert "message" in data
        assert "user_id" in data
        assert data["message"] == "user created successfully"
    
    def test_signup_duplicate_email(self, test_user):
        """Test signup with an email that's already registered."""
        # Create signup data with existing email
        signup_data = {
            "email": test_user.email,
            "password": "TestPassword123"
        }
        
        # Make the request
        response = client.post("/auth/signup", json=signup_data)
        
        # Verify response
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        data = response.json()
        assert "detail" in data
        assert "email already registered" in data["detail"]
    
    def test_signup_weak_password(self):
        """Test signup with a weak password."""
        test_cases = [
            # Too short
            {
                "data": {"email": "weak1@example.com", "password": "Short1"},
                "expected": "password must be at least 8 characters long"
            },
            # No uppercase
            {
                "data": {"email": "weak2@example.com", "password": "password123"},
                "expected": "password must contain at least one uppercase letter"
            },
            # No lowercase
            {
                "data": {"email": "weak3@example.com", "password": "PASSWORD123"},
                "expected": "password must contain at least one lowercase letter"
            },
            # No digits
            {
                "data": {"email": "weak4@example.com", "password": "PasswordOnly"},
                "expected": "password must contain at least one digit"
            }
        ]
        
        for case in test_cases:
            # Make the request
            response = client.post("/auth/signup", json=case["data"])
            
            # Verify response
            assert response.status_code == status.HTTP_400_BAD_REQUEST
            data = response.json()
            assert "detail" in data
            assert case["expected"] in data["detail"]
    
    def test_login_success(self, test_user):
        """Test successful login."""
        # Create login data
        login_data = {
            "email": test_user.email,
            "password": "TestPassword123"  # matches the test_user fixture
        }
        
        # Make the request
        response = client.post("/auth/login", json=login_data)
        
        # Verify response
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "access_token" in data
        assert "token_type" in data
        assert "user_id" in data
        assert data["token_type"] == "bearer"
        
        # Verify token can be decoded
        payload = jwt.decode(data["access_token"], JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        assert payload["sub"] == data["user_id"]
        assert payload["email"] == test_user.email
    
    def test_login_invalid_credentials(self, test_user):
        """Test login with invalid credentials."""
        # Test cases
        test_cases = [
            # Wrong email
            {
                "data": {"email": "wrong@example.com", "password": "TestPassword123"},
                "expected": "invalid email or password"
            },
            # Wrong password
            {
                "data": {"email": test_user.email, "password": "WrongPassword123"},
                "expected": "invalid email or password"
            }
        ]
        
        for case in test_cases:
            # Make the request
            response = client.post("/auth/login", json=case["data"])
            
            # Verify response
            assert response.status_code == status.HTTP_401_UNAUTHORIZED
            data = response.json()
            assert "detail" in data
            assert case["expected"] in data["detail"]