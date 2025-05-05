# creating token model
# record of all generated tokens
# used to store tokens

from sqlalchemy import Column, String, DateTime, Boolean, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import uuid
from datetime import datetime, timezone

Base = declarative_base()

class CardToken(Base):
    __tablename__ = "card_tokens"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    jwt_token = Column(String, nullable=False, unique=True)
    masked_card_number = Column(String, nullable=False)
    cardholder_name = Column(String, nullable=False)
    scope = Column(String, nullable=False, default="full-access")
    expires_at = Column(DateTime(timezone=True), nullable=False)
    is_revoked = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    
    user = relationship("User", backref="card_tokens")