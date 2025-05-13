"""
security utilities for the application.
handles token creation, validation, and password operations.
"""

from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
from jose import jwt, JWTError
import uuid
import logging
from typing import Dict, Any

from app.core.config import JWT_SECRET_KEY, JWT_ALGORITHM, TOKEN_EXPIRE_SECONDS

logger = logging.getLogger(__name__)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    """hash a password using bcrypt."""
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """verify a password against its hash."""
    return pwd_context.verify(plain_password, hashed_password)

def create_token(data: Dict[str, Any]) -> str:
    """
    create a JWT token with standard claims.
    
    args:
        data: data to encode in the token
        
    returns:
        JWT token string
    """
    
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    expire_seconds = TOKEN_EXPIRE_SECONDS
    expire = now + timedelta(seconds=expire_seconds)
    to_encode.update({
        "exp": expire,
        "iat": now,
        "jti": str(uuid.uuid4())
    })
    return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

def decode_token(token: str) -> Dict[str, Any]:
    """
    decode and validate a JWT token.
    
    args:
        token: JWT token string
        
    returns:
        decoded token payload
        
    raises:
        ValueError: if token is invalid or expired
    """
    
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except JWTError as e:
        logger.warning(f"invalid token: {str(e)}")
        raise ValueError(f"invalid or expired token: {str(e)}")