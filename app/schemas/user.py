"""
Pydantic schemas for user management and authentication.

These models define the structure of requests and responses for user-related operations,
as well as validation rules for user data.
"""

from pydantic import BaseModel, EmailStr, Field, field_validator
from datetime import datetime
from typing import Optional
import re


class UserBase(BaseModel):
    email: EmailStr


class UserCreate(UserBase):
    password: str = Field(..., min_length=8)
    
    @field_validator('password')
    @classmethod
    def password_strength(cls, v):
        """validate password strength."""
        if not re.search(r'[A-Z]', v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r'[a-z]', v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not re.search(r'[0-9]', v):
            raise ValueError("Password must contain at least one digit")
        return v


class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserRead(UserBase):
    id: str
    created_at: datetime
    
    model_config = {
        "from_attributes": True
    }
class AuthResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: str