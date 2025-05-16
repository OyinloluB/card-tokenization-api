# tests/integration/test_basic.py
from fastapi import status
from tests.test_config import client

def test_health_check():
    """Test that the health check endpoint returns OK."""
    response = client.get("/health")
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"status": "ok"}