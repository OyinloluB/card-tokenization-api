from fastapi import APIRouter, Depends, HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from app.schemas.token import TokenCreate, TokenRead
from app.services.token_service import (
    get_db,
    decode_token,
    save_token_to_db,
    revoke_token_by_id,
    get_all_tokens,
    get_token_by_id
)

security = HTTPBearer()
router = APIRouter()


@router.get("/protected")
def protected_route(
    credentials: HTTPAuthorizationCredentials = Security(security),
    db: Session = Depends(get_db)
):
    token_str = credentials.credentials
    payload = decode_token(token_str)
    return {
        "message": "You have access!",
        "reference_id": payload.get("reference_id"),
        "exp": payload.get("exp")
    }


@router.post("/token", response_model=TokenRead)
def issue_token(payload: TokenCreate, db: Session = Depends(get_db)):
    try:
        db_token = save_token_to_db(db, payload)
        return db_token
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/token", response_model=list[TokenRead])
def list_tokens(
    credentials: HTTPAuthorizationCredentials = Security(security),
    db: Session = Depends(get_db)
):
    token_str = credentials.credentials
    decode_token(token_str)
    return get_all_tokens(db)


@router.get("/token/{id}", response_model=TokenRead)
def get_token_by_id(
    id: str,
    credentials: HTTPAuthorizationCredentials = Security(security),
    db: Session = Depends(get_db)
):
    token_str = credentials.credentials
    decode_token(token_str)
    token = get_token_by_id(db, id)
    if not token:
        raise HTTPException(status_code=404, detail="Token not found")
    return token


@router.patch("/token/{id}/revoke", response_model=TokenRead)
def revoke_token(
    id: str,
    credentials: HTTPAuthorizationCredentials = Security(security),
    db: Session = Depends(get_db)
):
    token_str = credentials.credentials
    decode_token(token_str)
    try:
        token = revoke_token_by_id(db, id)
        return token
    except ValueError as e:
        raise HTTPException(
            status_code=400 if "already" in str(e) else 404,
            detail=str(e)
        )
