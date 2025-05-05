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
    """
    returns a masked card number
    """
    return f"{'*' * (len(card_number) - 4)}{card_number[-4:]}"

def create_card(data: dict) -> str:
    """
    creates a jwt card with an expiration time.
    `data`: payload
    """
    
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(seconds=TOKEN_EXPIRE_SECONDS)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt

def decode_card(card: str) -> dict:
    """
    decodes the jwt card and returns the payload.
    raises jwterror if invalid or expired.
    """
    
    try:
        payload = jwt.decode(card, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except JWTError:
        raise ValueError("Invalid or expired card")
    
def save_card_to_db(db: Session, card_data: CardTokenCreate, user_id: str) -> CardToken:
    """
    creates and stores a new jwt card in the database
    """
    
    payload = {
        "cardholder_name": card_data.cardholder_name,
        "expiry_month": card_data.expiry_month,
        "expiry_year": card_data.expiry_year
    }
    
    jwt_str = create_card(payload)
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=TOKEN_EXPIRE_SECONDS)
    
    db_token = CardToken(
        card=jwt_str,
        masked_card_number=mask_card_number(card_data.card_number),
        cardholder_name=card_data.cardholder_name,
        expires_at=expires_at,
        user_id=user_id
    )
    
    db.add(db_token)
    db.commit()
    db.refresh(db_token)
    
    return db_token

def get_all_cards(db: Session, user_id: str) -> list[CardToken]:
    return db.query(CardToken).filter(CardToken.user_id == user_id).all()

def get_card_by_id(db: Session, card_id: str, user_id: str) -> CardToken | None:
    return db.query(CardToken).filter(CardToken.id == card_id, CardToken.user_id == user_id).first()

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