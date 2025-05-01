# generating tokens with expiration
# decoding & validating tokens
# maybe: refresh logic later

from datetime import datetime, timedelta, timezone
from jose import jwt, JWTError
from app.core.config import JWT_SECRET_KEY, JWT_ALGORITHM, TOKEN_EXPIRE_SECONDS

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