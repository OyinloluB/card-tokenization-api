import logging

from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session

from app.core.config import TOKEN_EXPIRE_SECONDS
from app.core.security import create_token, decode_token
from app.models.card import CardToken
from app.schemas.card import CardTokenCreate
from app.services.utils import get_db

logger = logging.getLogger(__name__)
security = HTTPBearer()
        
def mask_card_number(card_number: str) -> str:
    if not card_number.isdigit() or len(card_number) < 13 or len(card_number) > 19:
        raise ValueError("Invalid card number format")

    return f"{'*' * (len(card_number) - 4)}{card_number[-4:]}"

def save_card_to_db(db: Session, card_data: CardTokenCreate, user_id: str) -> CardToken:    
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
    now = datetime.now(timezone.utc)
    return db.query(CardToken).filter(
        CardToken.user_id == user_id,
        CardToken.expires_at > now,
        CardToken.is_revoked == False
    ).all()

def get_card_by_id(db: Session, card_id: str, user_id: str) -> CardToken | None:
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

def revoke_card_by_id(db: Session, card_id: str, jwt_token: str) -> CardToken:
    card = db.query(CardToken).filter(CardToken.id == card_id, CardToken.jwt_token == jwt_token).first()

    if not card:
        raise ValueError("Card not found or token mismatch")
    if card.is_revoked:
        raise ValueError("Card is already revoked")

    card.is_revoked = True
    db.commit()
    db.refresh(card)

    return card

def delete_card(db: Session, card_id: str, jwt_token: str) -> None:
    card = db.query(CardToken).filter(CardToken.id == card_id, CardToken.jwt_token == jwt_token).first()
    
    if not card:
        raise ValueError("Card not found or token mismatch")

    db.delete(card)
    db.commit()

def refresh_card_by_id(db: Session, card_id: str, jwt_token: str) -> CardToken:
    card = db.query(CardToken).filter(CardToken.id == card_id, CardToken.jwt_token == jwt_token).first()
    
    if not card:
        raise ValueError("Card not found or token mismatch")
    if card.is_revoked:
        raise ValueError("Card is revoked")
    if card.expires_at < datetime.now(timezone.utc):
        raise ValueError("Card has expired")
    
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
    jwt_token_str = credentials.credentials
    payload = decode_token(jwt_token_str)
    
    token_obj = db.query(CardToken).filter(CardToken.jwt_token == jwt_token_str).first()
    if not token_obj or token_obj.is_revoked:
        raise HTTPException(status_code=401, detail="Card is revoked or invalid.")

    return {
        "payload": payload,
        "sub": str(token_obj.user_id)
    }