import uuid

from sqlalchemy import Column, String, DateTime, Boolean
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from app.db.session import Base

class User(Base):
    """
    user model for authentication and account management.
    
    this model stores user account information including:
    - identity (email and id)
    - authentication (hashed password)
    - account status (active status and login tracking)
    - timestamps for creation and updates
    
    it is connected to card tokens through a one-to-many relationship.
    """
    
    __tablename__ = "users"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String(255), unique=True, index=True, nullable=False)
    
    hashed_password = Column(String(255), nullable=False)
    
    is_active = Column(Boolean, default=True, index=True)
    last_login = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    def __repr__(self):
        """string representation of the User."""
        return f"<User(id={self.id}, email={self.email})>"