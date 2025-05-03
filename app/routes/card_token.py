from fastapi import APIRouter, Depends, HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from app.schemas.card_token import CardTokenCreate, CardTokenRead
from app.services.card_token_service import (
    get_db,
    decode_card_token,
    save_card_token_to_db,
    revoke_card_token_by_id,
    get_all_card_tokens,
    get_card_token_by_id
)

security = HTTPBearer()
router = APIRouter()


@router.get("/protected")
def protected_route(
    credentials: HTTPAuthorizationCredentials = Security(security),
    db: Session = Depends(get_db)
):
    token_str = credentials.credentials
    payload = decode_card_token(token_str)
    return {
        "message": "You have access!",
        "user_id": payload.get("sub"),
        "exp": payload.get("exp")
    }


@router.post("/token", response_model=CardTokenRead)
def issue_token(
    payload: CardTokenCreate,
    credentials: HTTPAuthorizationCredentials = Security(security),
    db: Session = Depends(get_db)
):
    token_str = credentials.credentials
    user_payload = decode_card_token(token_str)
    user_id = user_payload.get("sub")
    
    try:
        db_token = save_card_token_to_db(db, payload, user_id)
        return db_token
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/token", response_model=list[CardTokenRead])
def list_tokens(
    credentials: HTTPAuthorizationCredentials = Security(security),
    db: Session = Depends(get_db)
):
    token_str = credentials.credentials
    user_payload = decode_card_token(token_str)
    user_id = user_payload.get("sub")
    
    return get_all_card_tokens(db, user_id)

@router.get("/token/{id}", response_model=CardTokenRead)
def get_token_by_id(
    id: str,
    credentials: HTTPAuthorizationCredentials = Security(security),
    db: Session = Depends(get_db)
):
    token_str = credentials.credentials
    user_payload = decode_card_token(token_str)
    user_id = user_payload.get("sub")

    token = get_card_token_by_id(db, id, user_id)
    if not token:
        raise HTTPException(status_code=404, detail="Token not found")
    return token


@router.patch("/token/{id}/revoke", response_model=CardTokenRead)
def revoke_token(
    id: str,
    credentials: HTTPAuthorizationCredentials = Security(security),
    db: Session = Depends(get_db)
):
    token_str = credentials.credentials
    user_payload = decode_card_token(token_str)
    user_id = user_payload.get("sub")

    try:
        token = revoke_card_token_by_id(db, id, user_id)
        return token
    except ValueError as e:
        raise HTTPException(
            status_code=400 if "already" in str(e) else 404,
            detail=str(e)
        )
