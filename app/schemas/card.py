from enum import Enum
from pydantic import BaseModel, Field, model_validator, field_validator
from datetime import datetime
from typing import Optional
import re
from datetime import date

class CardScope(str, Enum):
    """defines the available permission scopes for card tokens."""
    
    READ_ONLY = "read-only"
    FULL_ACCESS = "full-access"
    REFRESH_ONLY = "refresh-only"
    
class CardTokenBase(BaseModel):
    """base schema with common card token fields."""
    
    cardholder_name: str = Field(
        ..., 
        min_length=2, 
        max_length=100,
        description="Name of the cardholder as it appears on the card",
        example="John Doe"
    )
    scope: CardScope = Field(
        default=CardScope.FULL_ACCESS,
        description="Permission scope for this token (controls what operations are allowed)",
        example="full-access"
    )

class CardTokenCreate(CardTokenBase):
    """schema for creating a new card token."""
    
    card_number: str = Field(
        ..., 
        min_length=13, 
        max_length=19, 
        pattern=r'^\d+$',
        description="Credit card number (13-19 digits, no spaces)",
        example="4111111111111111"
    )
    expiry_month: int = Field(
        ..., 
        ge=1, 
        le=12,
        description="Card expiration month (1-12)",
        example=12
    )
    expiry_year: int = Field(
        ..., 
        ge=2000,
        description="Card expiration year (4-digit format)",
        example=2025
    )
    cvv: str = Field(
        ..., 
        min_length=3, 
        max_length=4, 
        pattern=r'^\d+$',
        description="Card security code (3-4 digits)",
        example="123"
    )
    
    @field_validator('card_number')
    @classmethod
    def validate_card_number(cls, v):
        """validate card number using Luhn algorithm."""
        
        # remove any spaces or dashes
        v = re.sub(r'[\s-]', '', v)
        
        if not v.isdigit():
            raise ValueError("card number must contain only digits")
            
        # Luhn algorithm validation
        digits = [int(d) for d in v]
        checksum = digits.pop()
        digits.reverse()
        
        # double odd-indexed digits
        digits = [d * 2 if i % 2 else d for i, d in enumerate(digits)]
        # subtract 9 from numbers > 9
        digits = [d - 9 if d > 9 else d for d in digits]
        # check if sum + checksum is divisible by 10
        if (sum(digits) + checksum) % 10 != 0:
            raise ValueError("invalid card number")
            
        return v
    
    @model_validator(mode='after')
    def validate_expiry_date(self):
        """validate that expiry date is in the future."""
        
        current_year = date.today().year
        current_month = date.today().month
        
        if (self.expiry_year < current_year or 
            (self.expiry_year == current_year and self.expiry_month < current_month)):
            raise ValueError("card has expired")
            
        return self
    
class CardTokenRead(BaseModel):
    """schema for reading card token data."""
    
    id: str = Field(..., description="Unique identifier for the card token")
    jwt_token: str = Field(..., description="JWT token representing the card")
    masked_card_number: str = Field(..., description="Masked card number (only last 4 digits visible)")
    cardholder_name: str = Field(..., description="Name of the cardholder")
    is_revoked: bool = Field(..., description="Whether the token has been revoked")
    expires_at: datetime = Field(..., description="Token expiration timestamp")
    created_at: datetime = Field(..., description="Token creation timestamp")
    scope: CardScope = Field(..., description="Permission scope for this token")
    
    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "example": {
                "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                "jwt_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "masked_card_number": "***********1234",
                "cardholder_name": "John Doe",
                "is_revoked": False,
                "expires_at": "2023-12-31T23:59:59Z",
                "created_at": "2023-01-01T12:00:00Z",
                "scope": "full-access"
            }
        }
    }
    
class CardTokenUpdate(BaseModel):
    """schema for updating a card token."""
    
    scope: Optional[CardScope] = Field(
        None,
        description="New permission scope for the token",
        example="read-only"
    )
    
class CardDeleteResponse(BaseModel):
    """response schema for card deletion."""
    
    message: str = Field(
        ...,
        description="Success message",
        example="card deleted successfully"
    )