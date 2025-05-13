from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from datetime import datetime, timezone

from app.core.security import verify_password
from app.schemas.user import UserCreate, UserLogin, MessageResponse, TokenResponse
from app.services.card_service import get_db
from app.services.auth_service import create_user, get_user_by_email, create_access_token, validate_password_strength

router = APIRouter(prefix="/auth", tags=["Authentication"])

@router.post("/signup", response_model=MessageResponse, status_code=status.HTTP_201_CREATED)
def signup(user: UserCreate, db: Session = Depends(get_db)):
    """
    register a new user.
    
    args:
        user: user creation data
        db: database session
        
    returns:
        success message with user ID
        
    raises:
        HTTPException: if email already exists or other error occurs
    """
    
    existing_user = get_user_by_email(db, user.email)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Email already registered"
        )
    
    try:
        validate_password_strength(user.password)
        
        new_user = create_user(db, user)
        return {"message": "User created successfully", "user_id": str(new_user.id)}
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error creating user"
        )

@router.post("/login", response_model=TokenResponse)
def login(user: UserLogin, db: Session = Depends(get_db)):
    """
    authenticate a user and return an access token.
    
    args:
        user: login credentials
        db: database session
        
    returns:
        access token and user ID
        
    raises:
        HTTPException: if credentials are invalid
    """

    db_user = get_user_by_email(db, user.email)
    if not db_user or not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid email or password"
        )
    
    db_user.last_login = datetime.now(timezone.utc)
    db.commit()

    token_data = {
        "sub": str(db_user.id),
        "email": db_user.email
    }
    
    token = create_access_token(token_data)
    return {"access_token": token, "token_type": "bearer", "user_id": str(db_user.id)}