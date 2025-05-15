from fastapi import APIRouter, Depends, HTTPException, Security, status
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
router = APIRouter(prefix="/card", tags=["Cards"])

def require_scope(allowed_scopes: List[str]):
    """
    create a dependency that checks if the card token has the required scope.
    
    args:
        allowed_scopes: list of scopes that are permitted to access the endpoint
        
    returns:
        a dependency function that checks the token scope
    """
    
    def scope_checker(card_info: dict = Depends(verify_card)):
        payload = card_info["payload"]
        if payload.get("scope") not in allowed_scopes:
            raise HTTPException(
                status_code=403, 
                detail=f"insufficient permissions. Required scopes: {', '.join(allowed_scopes)}"
            )
        return card_info
    return scope_checker

@router.get(
    "/protected", 
    tags=["Utility"],
    summary="Test protected endpoint",
    description="A test endpoint that verifies card token authentication is working."
)
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

@router.post(
    "", 
    response_model=CardTokenRead, 
    status_code=status.HTTP_201_CREATED,
    summary="Create new card token",
    description="Tokenizes a credit card, storing a secure token instead of the actual card data."
)
def issue_card(
    payload: CardTokenCreate,
    user_payload: dict = Depends(verify_user),
    db: Session = Depends(get_db)
):
    """
    create a new card token.
    
    this endpoint tokenizes credit card information, storing a secure token
    instead of the actual card data. only the last 4 digits of the card number
    are preserved in masked form.
    
    the token has the scope specified in the request (defaults to full-access).
    
    args:
        payload: card information to tokenize
        user_payload: authenticated user information
        db: database session
        
    returns:
        created card token with details
        
    raises:
        HTTPException: 
            - 400: if card data is invalid
            - 500: for unexpected errors
    """
    
    user_id = user_payload.get("sub")
    
    try:
        card_token = save_card_to_db(db, payload, user_id)
        return card_token
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail="an unexpected error occurred")

@router.get(
    "", 
    response_model=List[CardTokenRead],
    summary="List all cards",
    description="Lists all active card tokens for the authenticated user."
)
def list_cards(
    user_payload: dict = Depends(verify_user),
    db: Session = Depends(get_db)
):
    """
    list all active card tokens for the authenticated user.
    
    returns all non-expired, non-revoked card tokens belonging to the user.
    
    args:
        user_payload: authenticated user information
        db: database session
        
    returns:
        list of card tokens
    """
    
    user_id = user_payload.get("sub")
    return get_all_cards(db, user_id)

@router.get(
    "/{id}", 
    response_model=CardTokenRead,
    summary="Get card by ID",
    description="Retrieves a specific card token by its ID."
)
def list_card_by_id(
    id: str,
    card_info: dict = Depends(require_scope(["read-only", "full-access", "refresh-only"])),
    db: Session = Depends(get_db)
):
    """
    get a specific card token by id.
    
    retrieves a single card token by its unique identifier.
    requires a token with read-only, full-access, or refresh-only scope.
    
    args:
        id: unique identifier of the card token
        card_info: card authentication and scope information
        db: database session
        
    returns:
        card token details
        
    raises:
        HTTPException: 404 if card not found
    """
    
    user_id = card_info["sub"]
    
    card = get_card_by_id(db, id, user_id)
    
    if not card:
        raise HTTPException(status_code=404, detail="card not found")
    return card

@router.delete(
    "/{id}", 
    response_model=CardDeleteResponse,
    summary="Delete card token",
    description="Permanently deletes a card token."
)
def delete_card(
    id: str,
    card_info: dict = Depends(require_scope(["full-access"])),
    credentials: HTTPAuthorizationCredentials = Security(security),
    db: Session = Depends(get_db)
):
    """
    delete a card token.
    
    permanently removes a card token from the system.
    requires a token with full-access scope.
    
    args:
        id: unique identifier of the card token
        card_info: card authentication and scope information
        credentials: authorization credentials containing the JWT token
        db: database session
        
    returns:
        success message
        
    raises:
        HTTPException: 
            - 403: if insufficient permissions
            - 404: if card not found
    """
    
    
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

@router.patch(
    "/{id}/revoke", 
    response_model=CardTokenRead,
    summary="Revoke card token",
    description="Revokes a card token, preventing its further use."
)
def revoke_card(
   id: str,
   card_info: dict = Depends(require_scope(["full-access"])),
   credentials: HTTPAuthorizationCredentials = Security(security),
   db: Session = Depends(get_db)
):
    """
    revoke a card token.
    
    marks a card token as revoked, preventing its further use.
    requires a token with full-access scope.
    
    args:
        id: unique identifier of the card token
        card_info: card authentication and scope information
        credentials: authorization credentials containing the JWT token
        db: database session
        
    returns:
        updated card token details
        
    raises:
        HTTPException: 
            - 400: if card already revoked
            - 403: if insufficient permissions
            - 404: if card not found
    """
    
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
 
@router.post(
    "/{id}/refresh", 
    response_model=CardTokenRead,
    summary="Refresh card token",
    description="Refreshes a card token's expiration time."
)
def refresh_card(
    id: str,
    card_info: dict = Depends(require_scope(["refresh-only", "full-access"])),
    credentials: HTTPAuthorizationCredentials = Security(security),
    db: Session = Depends(get_db)
):
    """
    refresh a card token's expiration time.
    
    extends the validity period of a card token by issuing a new token
    with the same payload but a new expiration time.
    requires a token with refresh-only or full-access scope.
    
    args:
        id: unique identifier of the card token
        card_info: card authentication and scope information
        credentials: authorization credentials containing the JWT token
        db: database session
        
    returns:
        updated card token details
        
    raises:
        HTTPException: 
            - 400: if card is revoked or expired
            - 403: if insufficient permissions
            - 404: if card not found
    """
    
    jwt_token = credentials.credentials
    user_id = card_info["sub"]
    
    card = get_card_by_id(db, id, user_id)
    if not card:
        raise HTTPException(status_code=404, detail="card not found")
    
    try:
        return refresh_card_by_id(db, card, jwt_token)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))