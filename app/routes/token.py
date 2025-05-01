from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.schemas.token import TokenCreate, TokenRead
from app.services.token_service import save_token_to_db, revoke_token_by_id, get_all_tokens, get_token_by_id
from app.db.session import SessionLocal
from app.models.token import Token

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
    
@router.get("/token", response_model=list[TokenRead])
def list_tokens(db: Session = Depends(get_db)):
    try:
        return get_all_tokens(db)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/token/{id}", response_model=TokenRead)
def get_token_by_id(id: str, db: Session = Depends(get_db)):
    token = get_token_by_id(db, id)
    if not token:
        raise HTTPException(status_code=404, detail="Token not found")
    return token

@router.patch("/token/{id}/revoke", response_model=TokenRead)
def revoke_token(id: str, db: Session = Depends(get_db)):
    try:
        token = revoke_token_by_id(db, id)
        return token
    except ValueError as e:
        raise HTTPException(status_code=400 if "already" in str(e) else 404, detail=str(e))