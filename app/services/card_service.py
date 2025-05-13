# generating tokens with expiration
# decoding & validating tokens
# maybe: refresh logic later

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from datetime import datetime, timedelta, timezone
from jose import jwt, JWTError
from sqlalchemy.orm import Session

from app.core.config import JWT_SECRET_KEY, JWT_ALGORITHM, TOKEN_EXPIRE_SECONDS
from app.models.user import User
from app.models.card import CardToken
from app.schemas.card import CardTokenCreate
from app.db.session import SessionLocal

security = HTTPBearer()
 
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

def decode_card_tokens(card: str) -> dict:
    try:
        payload = jwt.decode(card, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except JWTError:
        raise ValueError("Invalid or expired token")
    
def decode_user_tokens(user: str) -> dict:
    print(f"The value is: {user}")
    
    try:
        payload = jwt.decode(user, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        print(f"The value is: {payload}")
        return payload
    except JWTError:
        raise ValueError("Invalid or expired user token")
    
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
    
    payload = decode_card_tokens(card.jwt_token)
    
    card.jwt_token = create_card(payload)
    card.expires_at = datetime.now(timezone.utc) + timedelta(seconds=TOKEN_EXPIRE_SECONDS)
    
    db.commit()
    db.refresh(card)
    
    return card

def verify_card(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    jwt_token_str = credentials.credentials
    payload = decode_card_tokens(jwt_token_str)
    
    print(f"The value is: {payload}")
    
    token_obj = db.query(CardToken).filter(CardToken.jwt_token == jwt_token_str).first()
    if not token_obj or token_obj.is_revoked:
        raise HTTPException(status_code=401, detail="Card is revoked or invalid.")

    return {
        "payload": payload,
        "sub": str(token_obj.user_id)
    }

def verify_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    jwt_token_str = credentials.credentials
    payload = decode_user_tokens(jwt_token_str)

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=400, detail="User ID missing in token")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return payload