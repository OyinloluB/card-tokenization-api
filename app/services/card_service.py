import logging

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session

from app.core.config import TOKEN_EXPIRE_SECONDS
from app.core.security import create_token, decode_token, security
from app.models.card import CardToken
from app.schemas.card import CardTokenCreate
from app.services.utils import get_db

logger = logging.getLogger(__name__)
        
def mask_card_number(card_number: str) -> str:
    """mask all but the last 4 digits of a card number."""
    
    return f"{'*' * (len(card_number) - 4)}{card_number[-4:]}"

def save_card_to_db(db: Session, card_data: CardTokenCreate, user_id: str) -> CardToken:
    """
    create a new card token in the database.
    
    args:
        db: database session
        card_data: card information to tokenize
        user_id: id of the user creating the token
        
    returns:
        created CardToken object
    """
    
    payload = {
        "cardholder_name": card_data.cardholder_name,
        "expiry_month": card_data.expiry_month,
        "expiry_year": card_data.expiry_year,
        "scope": card_data.scope.value
    }
    
    jwt_str = create_token(payload)
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=TOKEN_EXPIRE_SECONDS)
    
    db_card = CardToken(
        jwt_token=jwt_str,
        masked_card_number=mask_card_number(card_data.card_number),
        cardholder_name=card_data.cardholder_name,
        expires_at=expires_at,
        user_id=user_id,
        scope=card_data.scope.value
    )
    
    db.add(db_card)
    db.commit()
    db.refresh(db_card)
    
    return db_card

def get_all_cards(db: Session, user_id: str) -> list[CardToken]:
    """
    get all active card tokens for a user.
    
    args:
        db: database session
        user_id: id of the user
        
    returns:
        list of active CardToken objects
    """
    
    now = datetime.now(timezone.utc)
    return db.query(CardToken).filter(
        CardToken.user_id == user_id,
        CardToken.expires_at > now,
        CardToken.is_revoked == False
    ).all()

def get_card_by_id(db: Session, card_id: str, user_id: str) -> CardToken | None:
    """
    get a specific card token by id.
    
    args:
        db: database session
        card_id: id of the card token
        user_id: id of the user
        
    returns:
        CardToken if found and active, None otherwise
    """
    
    card = db.query(CardToken).filter(
        CardToken.id == card_id,
        CardToken.user_id == user_id
    ).first()
    
    if not card:
        return None
    
    now = datetime.now(timezone.utc)
    if card.expires_at < now:
        return None
    
    return card

def revoke_card_by_id(db: Session, card: CardToken, jwt_token: str) -> CardToken:
    """
    revoke a card token.
    
    args:
        db: database session
        card: card token object
        jwt_token: jwt token string for verification
        
    returns:
        updated CardToken object
        
    raises:
        ValueError: if card not found or already revoked
    """
    
    if card.jwt_token != jwt_token:
        raise ValueError("token mismatch")
    if card.is_revoked:
        raise ValueError("card is already revoked")

    card.is_revoked = True
    db.commit()
    db.refresh(card)

    return card

def delete_card_by_id(db: Session, card: CardToken, jwt_token: str) -> None:
    """
    delete a card token permanently.
    
    args:
        db: database session
        card: card token object
        jwt_token: jwt token string for verification
        
    raises:
        ValueError: if card not found
    """
    
    if card.jwt_token != jwt_token:
        raise ValueError("token mismatch")

    db.delete(card)
    db.commit()

def refresh_card_by_id(db: Session, card: CardToken, jwt_token: str) -> CardToken:
    """
    refresh a card token's expiration time.
    
    args:
        db: database session
        card: card token object
        jwt_token: jwt token string for verification
        
    returns:
        updated CardToken object
        
    raises:
        ValueError: if card not found, revoked, or expired
    """
    
    if card.jwt_token != jwt_token:
        raise ValueError("token mismatch")
    if card.is_revoked:
        raise ValueError("card is already revoked")
    if card.expires_at < datetime.now(timezone.utc):
        raise ValueError("card has expired")
    
    payload = decode_token(card.jwt_token)
    
    card.jwt_token = create_token(payload)
    card.expires_at = datetime.now(timezone.utc) + timedelta(seconds=TOKEN_EXPIRE_SECONDS)
    
    db.commit()
    db.refresh(card)
    
    return card

def verify_card(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    """
    verify a card token and get its payload.
    
    args:
        credentials: http authorization credentials
        db: database session
        
    returns:
        dictionary with token payload and user id
        
    raises:
        HTTPException: if token is invalid or revoked
    """
    
    jwt_token_str = credentials.credentials
    
    try:
        payload = decode_token(jwt_token_str)
        token_obj = db.query(CardToken).filter(CardToken.jwt_token == jwt_token_str).first()
        
        if not token_obj or token_obj.is_revoked:
            raise HTTPException(status_code=401, detail="card is revoked or invalid.")

        return {
            "payload": payload,
            "sub": str(token_obj.user_id)
        }
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))