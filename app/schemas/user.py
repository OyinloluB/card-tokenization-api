from pydantic import BaseModel, EmailStr, Field, field_validator
from datetime import datetime
from typing import Optional
import re

class UserBase(BaseModel):
    """base schema with common user fields."""
      
    email: EmailStr

class UserCreate(UserBase):
    """schema for creating a new user."""
    
    password: str = Field(..., min_length=8)
    
    @field_validator('password')
    @classmethod
    def password_strength(cls, v):
        """validate password strength."""
        if not re.search(r'[A-Z]', v):
            raise ValueError("password must contain at least one uppercase letter")
        if not re.search(r'[a-z]', v):
            raise ValueError("password must contain at least one lowercase letter")
        if not re.search(r'[0-9]', v):
            raise ValueError("password must contain at least one digit")
        return v

class UserLogin(BaseModel):
    """schema for user login credentials."""
    
    email: EmailStr
    password: str

class UserRead(UserBase):
    """schema for reading user data."""
    
    id: str
    created_at: datetime
    
    model_config = {
        "from_attributes": True
    }
class TokenResponse(BaseModel):
    """response schema for token operations."""
    access_token: str
    token_type: str = "bearer"
    user_id: Optional[str] = None
    
class MessageResponse(BaseModel):
    message: str
    user_id: Optional[str] = None