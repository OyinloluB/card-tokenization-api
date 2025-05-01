from pydantic import BaseModel
from datetime import datetime
from typing import Optional

class TokenCreate(BaseModel):
    reference_id: str
    
class TokenRead(BaseModel):
    id: str
    token: str
    expires_at: datetime
    is_revoked: bool
    created_at: datetime
    
    # accept orm
    class Config:
        orm_mode = True