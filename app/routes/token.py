from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.schemas.token import TokenCreate, TokenRead
from app.services.token_service import save_token_to_db
from app.db.session import SessionLocal

router = APIRouter()

# get db session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# return TokenRead
@router.post("/token", response_model=TokenRead)
def issue_token(payload: TokenCreate, db: Session = Depends(get_db)):
    try:
        db_token = save_token_to_db(db, payload)
        return db_token
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))