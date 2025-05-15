import logging

from sqlalchemy.orm import Session
from fastapi import HTTPException, Depends
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy.exc import SQLAlchemyError

from app.models.user import User
from app.schemas.user import UserCreate
from app.core.security import hash_password, decode_token, security
from app.services.utils import get_db

logger = logging.getLogger(__name__)

def get_user_by_email(db: Session, email: str) -> User | None:
    """
    get a user by email.
    
    args:
        db: database session
        email: user's email address
        
    returns:
        User if found, None otherwise
    """
    
    return db.query(User).filter(User.email == email).first()

def create_user(db: Session, user_data: UserCreate) -> User:
    """
    create a new user.
    
    args:
        db: database session
        user_data: user creation data
        
    returns:
        created User object
        
    raises:
        ValueError: if validation fails
        HTTPException: if database error occurs
    """

    try:
        hashed_pwd = hash_password(user_data.password)
        db_user = User(email=user_data.email, hashed_password=hashed_pwd)
        
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        
        return db_user
    
    except ValueError as e:
        raise
    
    except SQLAlchemyError as e:
        db.rollback()
        
        raise HTTPException(status_code=500, detail="database error occurred")
    
def verify_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    """
    verify a user JWT token and return the payload.
    
    this function:
    1. validates the jwt token format and signature
    2. extracts the user id from the token
    3. verifies the user exists in the database
    
    args:
        credentials: HTTP authorization credentials
        db: database session
        
    returns:
        token payload with user information
        
    raises:
        HTTPException: if token is invalid or user doesn't exist
    """

    jwt_token_str = credentials.credentials
    payload = decode_token(jwt_token_str)

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=400, detail="user ID missing in token")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="user not found")

    return payload