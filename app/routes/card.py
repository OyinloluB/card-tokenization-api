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
    delete_card,
    refresh_card_by_id,
    verify_card
)

security = HTTPBearer()
router = APIRouter()

@router.get("/protected", tags=["Utility"])
def protected_route(
    user_payload: dict = Depends(verify_card),
):
    """
    verifies that the JWT card token is valid.
    returns basic user info extracted from the token.
    """
    
    return {
        "message": "You have access!",
        "user_id": user_payload.get("sub"),
        "exp": user_payload.get("exp"),
        "scope": user_payload.get("scope")
    }

@router.post("/card", response_model=CardTokenRead)
def issue_card(
    payload: CardTokenCreate,
    user_payload: dict = Depends(verify_card),
    db: Session = Depends(get_db)
):
    user_id = user_payload.get("sub")
    
    try:
        db = save_card_to_db(db, payload, user_id)
        return db
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/card", response_model=list[CardTokenRead])
def list_cards(
    user_payload: dict = Depends(verify_card),
    db: Session = Depends(get_db)
):
    user_id = user_payload.get("sub")
    
    if user_payload.get("scope") not in ["read-only", "full-access", "refresh-only"]:
        raise HTTPException(status_code=403, detail="You don't have read permissions")
    
    return get_all_cards(db, user_id)

@router.get("/card/{id}", response_model=CardTokenRead)
def get_card_by_id(
    id: str,
    user_payload: dict = Depends(verify_card),
    db: Session = Depends(get_db)
):
    user_id = user_payload.get("sub")
    
    if user_payload.get("scope") not in ["read-only", "full-access", "refresh-only"]:
        raise HTTPException(status_code=403, detail="You don't have read permissions")

    card = get_card_by_id(db, id, user_id)
    if not card:
        raise HTTPException(status_code=404, detail="Card not found")
    return card

@router.patch("/card/{id}/revoke", response_model=CardTokenRead)
def revoke_card(
    id: str,
    user_payload: dict = Depends(verify_card),
    db: Session = Depends(get_db)
):
    user_id = user_payload.get("sub")
    
    if user_payload.get("scope") != "full-access":
        raise HTTPException(status_code=403, detail="You don't have revoke permissions")

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
    user_payload: dict = Depends(verify_card), 
    db: Session = Depends(get_db)
):
    user_id = user_payload.get("sub")
    
    if user_payload.get("scope") != "full-access":
        raise HTTPException(status_code=403, detail="You don't have delete permissions")
    
    try:
        delete_card(db, id, user_id)
        return {"message": "Card deleted successfully"}
    except ValueError as e:
       raise HTTPException(status_code=404, detail=str(e))
    
@router.post("/card/{id}/refresh", response_model=CardTokenRead)
def refresh_token(
    id: str,
    user_payload: dict = Depends(verify_card),
    db: Session = Depends(get_db)
):
    user_id = user_payload.get("sub")
    
    if user_payload.get("scope") not in ["refresh-only", "full-access"]:
        raise HTTPException(status_code=403, detail="You don't have refresh permissions")

    try:
        new_card = refresh_card_by_id(db, id, user_id)
        return new_card
    except ValueError as e:
        raise HTTPAuthorizationCredentials(status_code=400 if "already" in str(e) or "expired" in str(e) else 404, detail=str(e))