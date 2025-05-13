import logging

from sqlalchemy.orm import Session
from fastapi import HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.exc import SQLAlchemyError

from app.models.user import User
from app.schemas.user import UserCreate
from app.core.security import hash_password, decode_token
from app.services.utils import get_db

logger = logging.getLogger(__name__)
security = HTTPBearer()

def get_user_by_email(db: Session, email: str) -> User | None:
    return db.query(User).filter(User.email == email).first()

def create_user(db: Session, user_data: UserCreate) -> User:
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
        
        raise HTTPException(status_code=500, detail="Database error occurred")
    
def verify_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    jwt_token_str = credentials.credentials
    payload = decode_token(jwt_token_str)

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=400, detail="User ID missing in token")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return payload