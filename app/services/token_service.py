# generating tokens with expiration
# decoding & validating tokens
# maybe: refresh logic later

from datetime import datetime, timedelta, timezone
from jose import jwt, JWTError
from sqlalchemy.orm import Session

from app.core.config import JWT_SECRET_KEY, JWT_ALGORITHM, TOKEN_EXPIRE_SECONDS
from app.models.token import Token
from app.schemas.token import TokenCreate

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
    
    payload = {"reference_id": token_data.reference_id}
    jwt_str = create_token(payload)
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=TOKEN_EXPIRE_SECONDS)
    
    db_token = Token(
        token=jwt_str,
        expires_at=expires_at
    )
    
    db.add(db_token)
    db.commit()
    db.refresh(db_token)
    
    return db_token