import pytest
from fastapi import status

from tests.test_config import client

class TestCardEndpointsSmoke:
    """smoke tests for card API endpoints to verify routes exist."""
    
    def test_card_post_route_exists(self):
        """test that the POST /card endpoint exists."""
        
        response = client.post("/card", json={})
        assert response.status_code != status.HTTP_404_NOT_FOUND
        
    def test_card_get_routes_exist(self):
        """test that the GET /card endpoints exist."""
        
        # list all cards
        response = client.get("/card")
        assert response.status_code != status.HTTP_404_NOT_FOUND
        
        # get specific card
        response = client.get("/card/some-id")
        assert response.status_code != status.HTTP_404_NOT_FOUND
    
    def test_card_modification_routes_exist(self):
        """test that the card modification endpoints exist."""
        
        # revoke card
        response = client.patch("/card/some-id/revoke")
        assert response.status_code != status.HTTP_404_NOT_FOUND
        
        # delete card
        response = client.delete("/card/some-id")
        assert response.status_code != status.HTTP_404_NOT_FOUND
        
        # refresh card
        response = client.post("/card/some-id/refresh")
        assert response.status_code != status.HTTP_404_NOT_FOUND