from fastapi import APIRouter, Depends, HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from app.schemas.card import CardTokenCreate, CardTokenRead
from app.services.card_service import (
    get_db,
    decode_card,
    save_card_to_db,
    revoke_card_by_id,
    get_all_cards,
    get_card_by_id,
    delete_card
)

security = HTTPBearer()
router = APIRouter()


@router.get("/protected")
def protected_route(
    credentials: HTTPAuthorizationCredentials = Security(security),
    db: Session = Depends(get_db)
):
    card_str = credentials.credentials
    payload = decode_card(card_str)
    return {
        "message": "You have access!",
        "user_id": payload.get("sub"),
        "exp": payload.get("exp")
    }


@router.post("/card", response_model=CardTokenRead)
def issue_card(
    payload: CardTokenCreate,
    credentials: HTTPAuthorizationCredentials = Security(security),
    db: Session = Depends(get_db)
):
    card_str = credentials.credentials
    user_payload = decode_card(card_str)
    user_id = user_payload.get("sub")
    
    try:
        db = save_card_to_db(db, payload, user_id)
        return db
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/card", response_model=list[CardTokenRead])
def list_cards(
    credentials: HTTPAuthorizationCredentials = Security(security),
    db: Session = Depends(get_db)
):
    card_str = credentials.credentials
    user_payload = decode_card(card_str)
    user_id = user_payload.get("sub")
    
    return get_all_cards(db, user_id)

@router.get("/card/{id}", response_model=CardTokenRead)
def get_card_by_id(
    id: str,
    credentials: HTTPAuthorizationCredentials = Security(security),
    db: Session = Depends(get_db)
):
    card_str = credentials.credentials
    user_payload = decode_card(card_str)
    user_id = user_payload.get("sub")

    card = get_card_by_id(db, id, user_id)
    if not card:
        raise HTTPException(status_code=404, detail="Card not found")
    return card


@router.patch("/card/{id}/revoke", response_model=CardTokenRead)
def revoke_card(
    id: str,
    credentials: HTTPAuthorizationCredentials = Security(security),
    db: Session = Depends(get_db)
):
    card_str = credentials.credentials
    user_payload = decode_card(card_str)
    user_id = user_payload.get("sub")

    try:
        card = revoke_card_by_id(db, id, user_id)
        return card
    except ValueError as e:
        raise HTTPException(
            status_code=400 if "already" in str(e) else 404,
            detail=str(e)
        )

@router.delete("/card/{id}")
def delete_card(
    id: str,
    credentials: HTTPAuthorizationCredentials = Security(security), 
    db: Session = Depends(get_db)
):
    card_str = credentials.credentials
    user_payload = decode_card(card_str)
    user_id = user_payload.get("sub")
    
    try:
        delete_card(db, id, user_id)
        return {"message": "Card deleted successfully"}
    except ValueError as e:
       raise HTTPException(status_code=404, detail=str(e))
    