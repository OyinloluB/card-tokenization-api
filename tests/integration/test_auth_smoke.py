import pytest
from fastapi import status

from tests.test_config import client

class TestAuthEndpointsSmoke:
    """smoke tests for authentication API endpoints."""
    
    def test_signup_route_exists(self):
        """test that the signup endpoint exists."""
        response = client.post("/auth/signup", json={})
        assert response.status_code != status.HTTP_404_NOT_FOUND
    
    def test_login_route_exists(self):
        """test that the login endpoint exists."""
        response = client.post("/auth/login", json={})
        assert response.status_code != status.HTTP_404_NOT_FOUND