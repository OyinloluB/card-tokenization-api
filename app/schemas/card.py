from enum import Enum
from pydantic import BaseModel, Field, model_validator, field_validator
from datetime import datetime
from typing import Optional
import re
from datetime import date

class CardScope(str, Enum):
    READ_ONLY = "read-only"
    FULL_ACCESS = "full-access"
    REFRESH_ONLY = "refresh-only"
    
class CardTokenBase(BaseModel):
    cardholder_name: str = Field(..., min_length=2, max_length=100)
    scope: CardScope = Field(default=CardScope.FULL_ACCESS)

class CardTokenCreate(CardTokenBase):
    card_number: str = Field(..., min_length=13, max_length=19, pattern=r'^\d+$')
    expiry_month: int = Field(..., ge=1, le=12)
    expiry_year: int = Field(..., ge=2000)
    cvv: str = Field(..., min_length=3, max_length=4, pattern=r'^\d+$')
    
    @field_validator('card_number')
    @classmethod
    def validate_card_number(cls, v):
        """validate card number using Luhn algorithm."""
        # remove any spaces or dashes
        v = re.sub(r'[\s-]', '', v)
        
        if not v.isdigit():
            raise ValueError("Card number must contain only digits")
            
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
            raise ValueError("Invalid card number")
            
        return v
    
    @model_validator(mode='after')
    def validate_expiry_date(self):
        """validate that expiry date is in the future."""
        current_year = date.today().year
        current_month = date.today().month
        
        if (self.expiry_year < current_year or 
            (self.expiry_year == current_year and self.expiry_month < current_month)):
            raise ValueError("Card has expired")
            
        return self
    
class CardTokenRead(BaseModel):
    id: str
    jwt_token: str
    masked_card_number: str
    cardholder_name: str
    is_revoked: bool
    expires_at: datetime
    created_at: datetime
    scope: CardScope
    
    model_config = {
        "from_attributes": True
    }
    
class CardTokenUpdate(BaseModel):
    """schema for updating a card token."""
    scope: Optional[CardScope] = None