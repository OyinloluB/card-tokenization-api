import pytest
from datetime import datetime, timezone, timedelta
from fastapi import HTTPException
from unittest.mock import patch, MagicMock

from app.services.card_service import (
    mask_card_number,
    save_card_to_db,
    get_all_cards,
    get_card_by_id,
    revoke_card_by_id,
    delete_card_by_id,
    refresh_card_by_id,
    verify_card
)
from app.schemas.card import CardTokenCreate, CardScope
from app.models.card import CardToken
from app.core.security import decode_token
from tests.test_config import override_get_db

class TestMaskCardNumber:
    """Tests for mask_card_number function."""
    
    def test_mask_card_number(self):
        """Test that card numbers are properly masked."""
        # Test various card numbers
        test_cases = [
            {"input": "4111111111111111", "expected": "************1111"},
            {"input": "5555555555554444", "expected": "************4444"},
            {"input": "378282246310005", "expected": "***********0005"}
        ]
        
        for case in test_cases:
            masked = mask_card_number(case["input"])
            assert masked == case["expected"]
            assert len(masked) == len(case["input"])
            assert masked[-4:] == case["input"][-4:]
            assert all(c == '*' for c in masked[:-4])

class TestCardOperations:
    """Tests for card operations."""
    
    def test_save_card_to_db(self, test_db, test_user):
        """Test saving a card to the database."""
        db = next(override_get_db())
        user_id = str(test_user.id)
        
        # Create card data
        card_data = CardTokenCreate(
            card_number="4111111111111111",
            cardholder_name="Test User",
            expiry_month=12,
            expiry_year=datetime.now().year + 1,
            cvv="123",
            scope=CardScope.FULL_ACCESS
        )
        
        # Save the card
        card = save_card_to_db(db, card_data, user_id)
        
        # Verify card was saved with correct attributes
        assert card is not None
        assert card.user_id == test_user.id
        assert card.masked_card_number == "************1111"
        assert card.cardholder_name == "Test User"
        assert card.scope == "full-access"
        assert card.is_revoked is False
        
        # Verify token can be decoded
        payload = decode_token(card.jwt_token)
        assert payload["cardholder_name"] == "Test User"
        assert payload["scope"] == "full-access"
        
        # Clean up
        db.delete(card)
        db.commit()
    
    def test_get_all_cards(self, test_db, test_user, test_card):
        """Test retrieving all cards for a user."""
        db = next(override_get_db())
        user_id = str(test_user.id)
        
        # Get all cards
        cards = get_all_cards(db, user_id)
        
        # Verify at least one card is returned
        assert len(cards) >= 1
        assert any(str(card.id) == str(test_card.id) for card in cards)
    
    def test_get_card_by_id(self, test_db, test_user, test_card):
        """Test retrieving a card by ID."""
        db = next(override_get_db())
        user_id = str(test_user.id)
        
        # Get the card
        card = get_card_by_id(db, str(test_card.id), user_id)
        
        # Verify card was found
        assert card is not None
        assert str(card.id) == str(test_card.id)
        assert card.user_id == test_user.id
    
    def test_get_card_by_id_nonexistent(self, test_db, test_user):
        """Test retrieving a non-existent card."""
        db = next(override_get_db())
        user_id = str(test_user.id)
        
        # Try to get a card with a non-existent ID
        import uuid
        card = get_card_by_id(db, str(uuid.uuid4()), user_id)
        
        # Verify no card was found
        assert card is None
    
    def test_revoke_card_by_id(self, test_db, test_user, test_card):
        """Test revoking a card."""
        db = next(override_get_db())
        
        # Revoke the card
        updated_card = revoke_card_by_id(db, test_card, test_card.jwt_token)
        
        # Verify card was revoked
        assert updated_card.is_revoked is True
        
        # Verify card in database is revoked
        card_in_db = db.query(CardToken).filter_by(id=test_card.id).first()
        assert card_in_db.is_revoked is True
    
    def test_revoke_card_by_id_token_mismatch(self, test_db, test_user, test_card):
        """Test revoking a card with wrong token."""
        db = next(override_get_db())
        
        # Try to revoke with wrong token
        with pytest.raises(ValueError) as exc_info:
            revoke_card_by_id(db, test_card, "wrong.token.value")
        
        # Verify error message
        assert "token mismatch" in str(exc_info.value)
        
        # Verify card in database is not revoked
        card_in_db = db.query(CardToken).filter_by(id=test_card.id).first()
        assert card_in_db.is_revoked is False
    
    def test_delete_card_by_id(self, test_db, test_user):
        """Test deleting a card."""
        db = next(override_get_db())
        user_id = str(test_user.id)
        
        # Create a card to delete
        card_data = CardTokenCreate(
            card_number="4111111111111111",
            cardholder_name="Delete Me",
            expiry_month=12,
            expiry_year=datetime.now().year + 1,
            cvv="123",
            scope=CardScope.FULL_ACCESS
        )
        
        card = save_card_to_db(db, card_data, user_id)
        card_id = str(card.id)
        jwt_token = card.jwt_token
        
        # Delete the card
        delete_card_by_id(db, card, jwt_token)
        
        # Verify card was deleted
        deleted_card = db.query(CardToken).filter_by(id=card.id).first()
        assert deleted_card is None
    
    def test_refresh_card_by_id(self, test_db, test_user, test_card):
        """Test refreshing a card."""
        db = next(override_get_db())
        
        # Get the original expiration time
        original_expires_at = test_card.expires_at
        original_token = test_card.jwt_token
        
        # Wait a moment to ensure timestamps differ
        from time import sleep
        sleep(0.1)
        
        # Refresh the card
        updated_card = refresh_card_by_id(db, test_card, test_card.jwt_token)
        
        # Verify the card was refreshed
        assert updated_card.expires_at > original_expires_at
        assert updated_card.jwt_token != original_token
        
        # Verify both tokens can be decoded
        payload1 = decode_token(original_token)
        payload2 = decode_token(updated_card.jwt_token)
        
        # Verify payloads contain the same card info
        assert payload1["cardholder_name"] == payload2["cardholder_name"]
        assert payload1["scope"] == payload2["scope"]
    
    def test_verify_card(self, test_db, test_card):
        """Test verifying a card token."""
        # Create mock credentials
        credentials = MagicMock()
        credentials.credentials = test_card.jwt_token
        db = next(override_get_db())
        
        # Verify the card
        result = verify_card(credentials, db)
        
        # Check result contains correct info
        assert "payload" in result
        assert "sub" in result
        assert result["sub"] == str(test_card.user_id)
        
        # Verify payload
        assert result["payload"]["cardholder_name"] == test_card.cardholder_name
        assert result["payload"]["scope"] == test_card.scope