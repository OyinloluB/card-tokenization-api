# generating tokens with expiration
# decoding & validating tokens
# maybe: refresh logic later

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from datetime import datetime, timedelta, timezone
from jose import jwt, JWTError
from sqlalchemy.orm import Session

from app.core.config import JWT_SECRET_KEY, JWT_ALGORITHM, TOKEN_EXPIRE_SECONDS
from app.models.card import CardToken
from app.schemas.card import CardTokenCreate
from app.db.session import SessionLocal

security = HTTPBearer
 
# get db session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
        
def mask_card_number(card_number: str) -> str:
    return f"{'*' * (len(card_number) - 4)}{card_number[-4:]}"

def create_card(data: dict) -> str: 
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(seconds=TOKEN_EXPIRE_SECONDS)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt

def decode_card(card: str) -> dict:
    try:
        payload = jwt.decode(card, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except JWTError:
        raise ValueError("Invalid or expired card")
    
def save_card_to_db(db: Session, card_data: CardTokenCreate, user_id: str) -> CardToken:
    payload = {
        "cardholder_name": card_data.cardholder_name,
        "expiry_month": card_data.expiry_month,
        "expiry_year": card_data.expiry_year,
        "scope": card_data.scope.value
    }
    
    jwt_str = create_card(payload)
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=TOKEN_EXPIRE_SECONDS)
    
    db_card = CardToken(
        card=jwt_str,
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

def revoke_card_by_id(db: Session, card_id: str, user_id: str) -> CardToken:
    card = db.query(CardToken).filter(CardToken.id == card_id, CardToken.user_id == user_id).first()

    if not card:
        raise ValueError("Card not found")

    if card.is_revoked:
        raise ValueError("Card is already revoked")

    card.is_revoked = True
    db.commit()
    db.refresh(card)

    return card

def delete_card(db: Session, card_id: str, user_id: str) -> None:
    card = db.query(CardToken).filter(CardToken.id == card_id, CardToken.user_id == user_id).first()
    
    if not card:
        raise ValueError("Card not found or you do not have access to delete it.")

    db.delete(card)
    db.commit()

def refresh_card_by_id(db: Session, card_id: str, user_id: str) -> CardToken:
    card = db.query(CardToken).filter(CardToken.id == card_id, CardToken.user_id == user_id).first()
    
    if not card:
        raise ValueError("Card not found")
    
    if card.is_revoked:
        raise ValueError("Card is revoked")
    
    if card.expires_at < datetime.now(timezone.utc):
        raise ValueError("Card has expired")
    
    payload = decode_card(card.jwt_token)
    
    new_card_token = create_card(payload)
    new_expires_at = datetime.now(timezone.utc) + timedelta(seconds=TOKEN_EXPIRE_SECONDS)
    
    new_token = CardToken(
        user_id=card.user_id,
        jwt_token=new_card_token,
        mask_card_number=card.masked_card_number,
        cardholder_name=card.cardholder_name,
        expires_at=new_expires_at
    )
    
    db.add(new_token)
    db.commit()
    db.refresh(new_token)
    return new_token

def verify_card(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    token_str = credentials.credentials
    
    try:
        payload = decode_card(token_str)
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))
    
    token_obj = db.query(CardToken).filter(CardToken.card == token_str).first()
    if not token_obj or token_obj.is_revoked:
        raise HTTPException(status_code=401, detail="Card is revoked or invalid.")

    return payload