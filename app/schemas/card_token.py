# shape of the data
# structure of the api
# validation

from pydantic import BaseModel
from datetime import datetime
from typing import Optional

class CardTokenCreate(BaseModel):
    card_number: str
    cardholder_name: str
    expiry_month: int
    expiry_year: int
    cvv: str
    
class CardTokenRead(BaseModel):
    id: str
    token: str
    masked_card_number: str
    cardholder_name: str
    is_revoked: bool
    expires_at: datetime
    created_at: datetime
    
    # accept sqlalchemy objects
    class Config:
        orm_mode = True