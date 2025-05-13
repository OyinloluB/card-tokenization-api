from fastapi import APIRouter, Depends, HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from typing import List

from app.schemas.card import CardTokenCreate, CardTokenRead, CardDeleteResponse
from app.services.card_service import (
    save_card_to_db,
    revoke_card_by_id,
    get_all_cards,
    get_card_by_id,
    delete_card_by_id,
    refresh_card_by_id,
    verify_card,
)
from app.services.auth_service import verify_user
from app.services.utils import get_db

security = HTTPBearer()
router = APIRouter(prefix="/cards", tags=["Cards"])

def require_scope(allowed_scopes: List[str]):
    """create a dependency that checks if the card token has the required scope."""
    
    def scope_checker(card_info: dict = Depends(verify_card)):
        payload = card_info["payload"]
        if payload.get("scope") not in allowed_scopes:
            raise HTTPException(
                status_code=403, 
                detail=f"insufficient permissions. Required scopes: {', '.join(allowed_scopes)}"
            )
        return card_info
    return scope_checker

@router.get("/protected", tags=["Utility"])
def protected_route(
    user_payload: dict = Depends(verify_card),
):
    """test endpoint to verify card token authentication."""
    
    return {
        "message": "you have access!",
        "user_id": user_payload.get("sub"),
        "exp": user_payload.get("payload", {}).get("exp"),
        "scope": user_payload.get("payload", {}).get("scope")
    }

@router.post("", response_model=CardTokenRead)
def issue_card(
    payload: CardTokenCreate,
    user_payload: dict = Depends(verify_user),
    db: Session = Depends(get_db)
):
    """create a new card."""
    
    user_id = user_payload.get("sub")
    
    try:
        card_token = save_card_to_db(db, payload, user_id)
        return card_token
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail="an unexpected error occurred")

@router.get("", response_model=List[CardTokenRead])
def list_cards(
    user_payload: dict = Depends(verify_user),
    db: Session = Depends(get_db)
):
    """list all active card tokens for the authenticated user."""
    
    user_id = user_payload.get("sub")
    return get_all_cards(db, user_id)

@router.get("/{id}", response_model=CardTokenRead)
def list_card_by_id(
    id: str,
    card_info: dict = Depends(require_scope(["read-only", "full-access", "refresh-only"])),
    db: Session = Depends(get_db)
):
    """get a specific card token by id."""
    
    user_id = card_info["sub"]
    
    card = get_card_by_id(db, id, user_id)
    
    if not card:
        raise HTTPException(status_code=404, detail="card not found")
    return card

@router.delete("/{id}", response_model=CardDeleteResponse)
def delete_card(
    id: str,
    card_info: dict = Depends(require_scope(["full-access"])),
    credentials: HTTPAuthorizationCredentials = Security(security),
    db: Session = Depends(get_db)
):
    """delete a card token."""
    
    jwt_token = credentials.credentials
    user_id = card_info["sub"]
    
    card = get_card_by_id(db, id, user_id)
    if not card:
        raise HTTPException(status_code=404, detail="card not found")
    
    try:
        delete_card_by_id(db, card, jwt_token)
        return {"message": "card deleted successfully"}
    except ValueError as e:
       raise HTTPException(status_code=404, detail=str(e))

@router.patch("/{id}/revoke", response_model=CardTokenRead)
def revoke_card(
   id: str,
   card_info: dict = Depends(require_scope(["full-access"])),
   credentials: HTTPAuthorizationCredentials = Security(security),
   db: Session = Depends(get_db)
):
    """revoke a card token."""
    
    jwt_token = credentials.credentials
    user_id = card_info["sub"]
    
    card = get_card_by_id(db, id, user_id)
    if not card:
        raise HTTPException(status_code=404, detail="card not found")
    
    try:
        return revoke_card_by_id(db, card, jwt_token)
    except ValueError as e:
        if "already" in str(e):
            raise HTTPException(status_code=400, detail=str(e))
        else:
            raise HTTPException(status_code=404, detail=str(e))
 
@router.post("/{id}/refresh", response_model=CardTokenRead)
def refresh_card(
    id: str,
    card_info: dict = Depends(require_scope(["refresh-only", "full-access"])),
    credentials: HTTPAuthorizationCredentials = Security(security),
    db: Session = Depends(get_db)
):
    """refresh a card token's expiration time."""
    
    jwt_token = credentials.credentials
    user_id = card_info["sub"]
    
    card = get_card_by_id(db, id, user_id)
    if not card:
        raise HTTPException(status_code=404, detail="card not found")
    
    try:
        return refresh_card_by_id(db, card, jwt_token)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))