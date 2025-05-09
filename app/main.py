from fastapi import FastAPI
from fastapi.security import HTTPBearer
from fastapi.openapi.utils import get_openapi
from contextlib import asynccontextmanager
from sqlalchemy.exc import OperationalError
from dotenv import load_dotenv

from app.db.session import engine
from app.models.card import Base
from app.routes import card, auth

import os

load_dotenv()

@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        with engine.connect() as conn:
            print("Connected to the database successfully!")
            
            # clean expired card jwt tokens
            from app.models.card import CardToken
            from sqlalchemy.orm import Session
            from datetime import datetime, timezone
            
            session = Session(bind=conn)
            now = datetime.now(timezone.utc)
            
            deleted = session.query(CardToken).filter(CardToken.expires_at < now).delete()
            session.commit()
            
            print(f"Deleted {deleted} expired virtual card(s).")
    except OperationalError:
        print("Failed to connect to the database.")
    yield

app = FastAPI(
    title="Card Tokenization API",
    version="1.0.0",
    lifespan=lifespan
)

security_scheme = HTTPBearer()


def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title="Card Tokenization API",
        version="1.0.0",
        description="API for tokenizing and managing virtual card credentials.",
        routes=app.routes,
    )
    openapi_schema["components"]["securitySchemes"] = {
        "HTTPBearer": {
            "type": "http",
            "scheme": "bearer"
        }
    }
    openapi_schema["security"] = [{"HTTPBearer": []}]
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi


@app.get("/health")
def health_check():
    return {"status": "ok"}

app.include_router(card.router)
app.include_router(auth.router)

Base.metadata.create_all(bind=engine)