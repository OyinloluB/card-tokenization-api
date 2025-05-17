"""
basic functionality tests for the api.

contains simple tests for core functionality like the health check endpoint.
"""

from fastapi import status
from tests.test_config import client

def test_health_check():
    """test that the health check endpoint returns ok."""
    
    response = client.get("/health")
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"status": "ok"}