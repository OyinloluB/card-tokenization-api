from pydantic import BaseModel, EmailStr, Field, field_validator
from datetime import datetime
from typing import Optional
import re

class UserBase(BaseModel):
    """base schema with common user fields."""
      
    email: EmailStr = Field(
        ...,
        description="User's email address (must be valid format)",
        example="user@example.com"
    )

class UserCreate(UserBase):
    """schema for creating a new user."""
    
    password: str = Field(
        ..., 
        min_length=8,
        description="User's password (min 8 chars, must include uppercase, lowercase and digit)",
        example="StrongP4ssword"
    )
    
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
    
    email: EmailStr = Field(
        ...,
        description="User's email address",
        example="user@example.com"
    )
    password: str = Field(
        ...,
        description="User's password",
        example="StrongP4ssword"
    )

class UserRead(UserBase):
    """schema for reading user data."""
    
    id: str = Field(
        ...,
        description="Unique identifier for the user",
        example="a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    )
    created_at: datetime = Field(
        ...,
        description="Timestamp when the user was created",
        example="2023-01-01T12:00:00Z"
    )
    
    model_config = {
        "from_attributes": True
    }
class TokenResponse(BaseModel):
    """response schema for token operations."""
    
    access_token: str = Field(
        ...,
        description="JWT access token for authentication",
        example="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    )
    token_type: str = Field(
        "bearer",
        description="Type of token (always 'bearer')",
        example="bearer"
    )
    user_id: Optional[str] = Field(
        None,
        description="ID of the authenticated user",
        example="a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    )
    
class MessageResponse(BaseModel):
    """response schema for operations that return a message."""
        
    message: str = Field(
        ...,
        description="Response message",
        example="user created successfully"
    )
    user_id: Optional[str] = Field(
        None,
        description="User ID (if applicable)",
        example="a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    )