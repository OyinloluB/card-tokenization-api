# shape of the data
# structure of the api
# validation

from enum import Enum
from pydantic import BaseModel
from datetime import datetime
from typing import Optional

class CardScope(str, Enum):
    READ_ONLY = "read-only"
    FULL_ACCESS = "full-access"
    REFRESH_ONLY = "refresh-only"

class CardTokenCreate(BaseModel):
    card_number: str
    cardholder_name: str
    expiry_month: int
    expiry_year: int
    cvv: str
    scope: CardScope = CardScope.FULL_ACCESS
    
class CardTokenRead(BaseModel):
    id: str
    jwt_token: str
    masked_card_number: str
    cardholder_name: str
    is_revoked: bool
    expires_at: datetime
    created_at: datetime
    scope: CardScope
    
    # accept sqlalchemy objects
    class Config:
        orm_mode = True