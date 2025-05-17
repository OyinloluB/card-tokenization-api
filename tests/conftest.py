"""
test fixtures for the card tokenization API.

this module provides reusable test fixtures including:
- test user creation and authentication
- test card token generation
- authentication headers for API requests
- database session management

fixtures handle their own setup and cleanup to ensure test isolation.
"""

import pytest
from jose import jwt
import uuid
from datetime import datetime, timedelta, timezone

from app.core.config import JWT_ALGORITHM, JWT_SECRET_KEY
from app.models.user import User
from app.models.card import CardToken
from app.schemas.user import UserCreate
from app.schemas.card import CardTokenCreate
from app.services.card_service import save_card_to_db
from app.services.auth_service import create_user
from tests.test_config import test_db, client, override_get_db

@pytest.fixture
def test_user(test_db):
    """create a test user for authentication testing."""
    
    db = next(override_get_db())
    
    # create a test user
    user_data = UserCreate(
        email="test@example.com",
        password="TestPassword123"
    )
    
    user = create_user(db, user_data)
    
    yield user
    
    db.query(User).filter(User.id == user.id).delete()
    db.commit()
    
@pytest.fixture
def user_token(test_user):
    """create a JWT token for the test user."""
    
    token_data = {
        "sub": str(test_user.id),
        "email": test_user.email,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=30),
        "iat": datetime.now(timezone.utc),
        "jti": str(uuid.uuid4())
    }
    
    return jwt.encode(token_data, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

@pytest.fixture
def test_card(test_db, test_user):
    """create a test card token for testing."""
    
    db = next(override_get_db())
    
    card_data = CardTokenCreate(
        card_number="4111111111111111",
        cardholder_name="Test User",
        expiry_month=12,
        expiry_year=datetime.now().year + 1,
        cvv="123",
        scope="full-access"
    )
    
    try:
        card = save_card_to_db(db, card_data, str(test_user.id))
        
        yield card
        
        # cleanup
        db.query(CardToken).filter(CardToken.id == card.id).delete()
        db.commit()
    except Exception as e:
        # handle potential sqlite/uuid errors
        print(f"warning: failed to create test card: {e}")
        yield None

@pytest.fixture
def card_token(test_card):
    """get the JWT token from the test card."""
    
    return test_card.jwt_token if test_card else None

@pytest.fixture
def auth_headers(user_token):
    """headers for authenticated requests."""
    
    return {"Authorization": f"Bearer {user_token}"}

@pytest.fixture
def card_headers(card_token):
    """headers for card token requests."""
    
    if card_token:
        return {"Authorization": f"Bearer {card_token}"}
    return {}