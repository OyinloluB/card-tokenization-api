# tests/conftest.py
import pytest
from fastapi.testclient import TestClient
from jose import jwt
from datetime import datetime, timedelta, timezone
import uuid

from app.main import app
from app.core.config import JWT_ALGORITHM, JWT_SECRET_KEY
from app.models.user import User
from app.models.card import CardToken
from tests.test_config import test_db, client, override_get_db

@pytest.fixture
def test_user(test_db):
    """create a test user for authentication testing."""
    from sqlalchemy.orm import Session
    from app.services.auth_service import create_user
    from app.schemas.user import UserCreate
    
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
    """Create a test card token for testing."""
    from app.schemas.card import CardTokenCreate
    from app.services.card_service import save_card_to_db
    
    db = next(override_get_db())
    
    card_data = CardTokenCreate(
        card_number="4111111111111111",
        cardholder_name="Test User",
        expiry_month=12,
        expiry_year=datetime.now().year + 1,
        cvv="123",
        scope="full-access"
    )
    
    card = save_card_to_db(db, card_data, str(test_user.id))
    
    yield card
    
    # Clean up
    db.query(CardToken).filter(CardToken.id == card.id).delete()
    db.commit()

@pytest.fixture
def card_token(test_card):
    """Get the JWT token from the test card."""
    return test_card.jwt_token

@pytest.fixture
def auth_headers(user_token):
    """Headers for authenticated requests."""
    return {"Authorization": f"Bearer {user_token}"}

@pytest.fixture
def card_headers(card_token):
    """Headers for card token requests."""
    return {"Authorization": f"Bearer {card_token}"}