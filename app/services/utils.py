from app.db.session import SessionLocal

def get_db():
    """yield a database session and ensure it's closed after use."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()