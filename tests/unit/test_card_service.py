import pytest
from pydantic import field_validator
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
    """tests for the mask_card_number function."""
    
    def test_mask_card_number_16_digits(self):
        card_number = "4111111111111111"
        
        masked = mask_card_number(card_number)
        
        assert masked == "************1111"
        assert len(masked) == len(card_number)
        assert masked[-4:] == "1111"
        assert all(c == '*' for c in masked[:-4])
        
    def test_mask_card_number_different_lengths(self):
        """test masking card numbers of different lengths."""
            
        test_cases = [
            {"input": "378282246310005", "expected": "***********0005"},  # 15 digits (AMEX)
            {"input": "5555555555554444", "expected": "************4444"},  # 16 digits (MasterCard)
            {"input": "6011111111111117", "expected": "************1117"},  # 16 digits (Discover)
            {"input": "3530111333300000", "expected": "************0000"},  # 16 digits (JCB)
            {"input": "5019717010103742", "expected": "************3742"},  # 16 digits (Dankort)
            {"input": "6799990100000000019", "expected": "***************0019"}  # 19 digits (Union Pay)
        ]
        
        for case in test_cases:
            masked = mask_card_number(case["input"])
            assert masked == case["expected"]
            assert len(masked) == len(case["input"])
            assert masked[-4:] == case["input"][-4:]
            assert all(c == '*' for c in masked[:-4])

class TestGetAllCards:
    """tests for the get_all_cards function."""
    
    def test_get_all_cards(self, test_db, test_user):
        """test retrieving all cards for a user."""
        
        db = next(override_get_db())
        user_id = str(test_user.id)
        
        # create mock cards
        mock_card1 = MagicMock(spec=CardToken)
        mock_card1.id = "card-id-1"
        mock_card1.masked_card_number = "************1111"
        mock_card1.cardholder_name = "Test User 1"
        
        mock_card2 = MagicMock(spec=CardToken)
        mock_card2.id = "card-id-2"
        mock_card2.masked_card_number = "************2222"
        mock_card2.cardholder_name = "Test User 2"
        
        with patch('app.services.card_service.datetime') as mock_datetime:
            mock_now = datetime(2025, 1, 1, tzinfo=timezone.utc)
            mock_datetime.now.return_value = mock_now
            
            with patch.object(db, 'query') as mock_query_method:
                mock_query = MagicMock()
                mock_query_method.return_value = mock_query
                
                mock_filter = MagicMock()
                mock_query.filter.return_value = mock_filter
                
                mock_filter.all.return_value = [mock_card1, mock_card2]
                
                cards = get_all_cards(db, user_id)
        
                assert len(cards) == 2
                assert cards[0].id == "card-id-1"
                assert cards[1].id == "card-id-2"
                assert cards[0].masked_card_number == "************1111"
                assert cards[1].masked_card_number == "************2222"
                
                # verify correct query was made
                mock_query_method.assert_called_once_with(CardToken)
                
                mock_query.filter.assert_called_once()
                mock_filter.all.assert_called_once()
                
class TestGetCardById:
    """tests for the get_card_by_id function."""
    
    def test_get_card_by_id_success(self, test_db, test_user):
        """test retrieving a card by ID when it exists."""
        
        db = next(override_get_db())
        user_id = str(test_user.id)
        card_id = "test-card-id"
        
        mock_card = MagicMock(spec=CardToken)
        mock_card.id = card_id
        mock_card.masked_card_number = "************1111"
        mock_card.cardholder_name = "Test User"
        mock_card.user_id = test_user.id
        mock_card.expires_at = datetime.now(timezone.utc) + timedelta(days=30)
        
        with patch.object(db, 'query') as mock_query_method:
            mock_query = MagicMock()
            mock_query_method.return_value = mock_query
            
            mock_filter = MagicMock()
            mock_query.filter.return_value = mock_filter
            
            mock_filter.first.return_value = mock_card
            
            card = get_card_by_id(db, card_id, user_id)
            
            assert card is not None
            assert card.id == card.id
            assert card.masked_card_number == "************1111"
            assert card.cardholder_name == "Test User"
            
            mock_query_method.assert_called_once_with(CardToken)
            mock_query.filter.assert_called_once()
            mock_filter.first.assert_called_once()
            
    def test_get_card_by_id_not_found(self, test_db, test_user):
        """test retrieving a card that doesn't exist."""
        
        db = next(override_get_db())
        user_id = str(test_user.id)
        card_id = "nonexistent-card-id"
        
        with patch.object(db, 'query') as mock_query_method:
            mock_query = MagicMock()
            mock_query_method.return_value = mock_query
            
            mock_filter = MagicMock()
            mock_query.filter.return_value = mock_filter
            
            mock_filter.first.return_value = None
            
            card = get_card_by_id(db, card_id, user_id)
            
            assert card is None
            mock_query_method.assert_called_once_with(CardToken)
            mock_query.filter.assert_called_once()
            mock_filter.first.assert_called_once()
            
    def test_get_card_by_id_expired(self, test_db, test_user):
        """test retrieving a card that has expired."""
        
        db = next(override_get_db())
        user_id = str(test_user.id)
        card_id = "expired-card-id"
        
        mock_card = MagicMock(spec=CardToken)
        mock_card.id = card_id
        mock_card.masked_card_number = "************1111"
        mock_card.cardholder_name = "Test User"
        mock_card.user_id = test_user.id
        mock_card.expires_at = datetime.now(timezone.utc) - timedelta(days=30)
        
        with patch.object(db, 'query') as mock_query_method:
            mock_query = MagicMock()
            mock_query_method.return_value = mock_query
            
            mock_filter = MagicMock()
            mock_query.filter.return_value = mock_filter
            
            # set the final result
            mock_filter.first.return_value = mock_card
            
            # execute
            card = get_card_by_id(db, card_id, user_id)
            
            # function should return None for expired cards
            assert card is None
            
            # verify correct query was made
            mock_query_method.assert_called_once_with(CardToken)
            mock_query.filter.assert_called_once()
            mock_filter.first.assert_called_once()
            
class TestRevokeCardById:
    """tests for the recoke_card_by_id function."""
    
    def test_revoke_card_success(self, test_db, test_user):
        """test successfully revoking a card."""
        
        db = next(override_get_db())
        
        mock_card = MagicMock(spec=CardToken)
        mock_card.id = "test-card-id"
        mock_card.jwt_token = "valid.jwt.token"
        mock_card.is_revoked = False
        
        with patch.object(db, 'commit') as mock_commit:
            with patch.object(db, 'refresh') as mock_refresh:
                updated_card = revoke_card_by_id(db, mock_card, "valid.jwt.token")
            
                assert updated_card.is_revoked is True
                mock_commit.assert_called_once()
                mock_refresh.assert_called_once_with(mock_card)
        
    
    def test_revoke_card_token_mismatch(self, test_db, test_user):
        """test revoking a card with the wrong token."""
        
        db = next(override_get_db())
        
        mock_card = MagicMock(spec=CardToken)
        mock_card.id = "test-card-id"
        mock_card.jwt_token = "valid.jwt.token"
        mock_card.is_revoked = False
        
        with pytest.raises(ValueError) as exc_info:
            revoke_card_by_id(db, mock_card, "wrong.jwt.token")
            
        assert "token mismatch" in str(exc_info.value)
        assert mock_card.is_revoked is False
    
    def test_revoke_already_revoked_card(self, test_db, test_user):
        """test revoking a card that's already revoked."""
        
        db = next(override_get_db())
        
        mock_card = MagicMock(spec=CardToken)
        mock_card.id = "test-card-id"
        mock_card.jwt_token = "valid.jwt.token"
        mock_card.is_revoked = True
        
        with pytest.raises(ValueError) as exc_info:
            revoke_card_by_id(db, mock_card, "valid.jwt.token")
            
        assert "already revoked" in str(exc_info.value)
            
class TestDeleteCardById:
    """tests for the delete_card_by_id function."""

    def test_delete_card_success(self, test_db, test_user):
        """test successfully deleting a card."""
        
        db = next(override_get_db())

        mock_card = MagicMock(spec=CardToken)
        mock_card.id = "test-card-id"
        mock_card.jwt_token = "valid.jwt.token"

        with patch.object(db, 'delete') as mock_delete:
            with patch.object(db, 'commit') as mock_commit:
                delete_card_by_id(db, mock_card, "valid.jwt.token")
                
                mock_delete.assert_called_once_with(mock_card)
                mock_commit.assert_called_once()
                
    def test_delete_card_token_mismatch(self, test_db, test_user):
        """test deleting a card with wrong token."""
        
        db = next(override_get_db())
        
        mock_card = MagicMock(spec=CardToken)
        mock_card.id = "test-card-id"
        mock_card.jwt_token = "valid.jwt.token"
        
        with pytest.raises(ValueError) as exc_info:
            delete_card_by_id(db, mock_card, "wrong.jwt.token")
            
        assert "token mismatch" in str(exc_info.value)