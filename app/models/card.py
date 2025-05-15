import uuid

from sqlalchemy import Column, String, DateTime, Boolean, ForeignKey, Index
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.db.session import Base
class CardToken(Base):
    """
    card token model for storing tokenized card information.
    
    this model stores the secure representation of credit card data,
    keeping only masked card numbers and using JWTs for the actual token.
    
    it implements:
    - two-level security (user ownership + specific token verification)
    - permission scopes to control what operations are allowed
    - expiration and revocation mechanisms
    """
    
    __tablename__ = "card_tokens"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True)
    
    jwt_token = Column(String(500), nullable=False, unique=True, index=True)
    masked_card_number = Column(String(24), nullable=False)
    cardholder_name = Column(String(100), nullable=False)
    scope = Column(String(20), nullable=False, default="full-access")
    
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    is_revoked = Column(Boolean, default=False, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    user = relationship("User", backref="card_tokens")
    
    __table_args__ = (
        Index('idx_card_tokens_active', 'is_revoked', 'expires_at'),
    )
    
    def __repr__(self):
        """string representation of the CardToken."""
        
        return f"<CardToken(id={self.id}, user_id={self.user_id}, expires_at={self.expires_at})>"