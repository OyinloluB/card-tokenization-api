from app.db.session import SessionLocal

def get_db():
    """
    yields a database session and ensures it's closed after use.
    
    this function creates a new SQLAlchemy session and yields it to the caller.
    after the caller is done, it ensures the session is properly closed,
    even if an exception occurred.
    
    yields:
        sqlalchemy Session: database session
    """
    
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()