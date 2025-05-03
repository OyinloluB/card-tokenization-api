# generating tokens with expiration
# decoding & validating tokens
# maybe: refresh logic later

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from datetime import datetime, timedelta, timezone
from jose import jwt, JWTError
from sqlalchemy.orm import Session

from app.core.config import JWT_SECRET_KEY, JWT_ALGORITHM, TOKEN_EXPIRE_SECONDS
from app.models.token import Token
from app.schemas.token import TokenCreate
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

def create_token(data: dict) -> str:
    """
    creates a jwt token with an expiration time.
    `data`: payload
    """
    
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(seconds=TOKEN_EXPIRE_SECONDS)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt

def decode_token(token: str) -> dict:
    """
    decodes the jwt token and returns the payload.
    raises jwterror if invalid or expired.
    """
    
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except JWTError:
        raise ValueError("Invalid or expired token")
    
def save_token_to_db(db: Session, token_data: TokenCreate) -> Token:
    """
    creates and stores a new jwt token in the database
    """
    
    payload = {
        "cardholder_name": token_data.cardholder_name,
        "expiry_month": token_data.expiry_month,
        "expiry_year": token_data.expiry_year
    }
    
    jwt_str = create_token(payload)
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=TOKEN_EXPIRE_SECONDS)
    
    db_token = Token(
        token=jwt_str,
        masked_card_number=mask_card_number(token_data.card_number),
        expires_at=expires_at,
    )
    
    db.add(db_token)
    db.commit()
    db.refresh(db_token)
    
    return db_token

def get_all_tokens(db: Session) -> list[Token]:
    return db.query(Token).all()

def get_token_by_id(db: Session, token_id: str) -> Token | None:
    return db.query(Token).filter(Token.id == token_id).first()

def revoke_token_by_id(db: Session, token_id: str) -> Token:
    token = db.query(Token).filter(Token.id == token_id).first()

    if not token:
        raise ValueError("Token not found")

    if token.is_revoked:
        raise ValueError("Token is already revoked")

    token.is_revoked = True
    db.commit()
    db.refresh(token)

    return token

def verify_token(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    token_str = credentials.credentials
    
    try:
        payload = decode_token(token_str)
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))
    
    token_obj = db.query(Token).filter(Token.token == token_str).first()
    if not token_obj or token_obj.is_revoked:
        raise HTTPException(status_code=401, detail="Token is revoked or invalid.")

    return payload