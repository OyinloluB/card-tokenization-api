import os
import logging
from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.security import HTTPBearer
from fastapi.openapi.utils import get_openapi
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from sqlalchemy.exc import OperationalError, SQLAlchemyError
from sqlalchemy.orm import Session
from dotenv import load_dotenv

from app.db.session import engine
from app.models.card import Base, CardToken
from app.routes import card, auth

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    lifecycle event handler for the fastapi application.
    
    performs database connection verification and cleanup of expired tokens.
    """

    try:
        with engine.connect() as conn:
            logger.info("connected to the database successfully!")
            
            # clean expired card jwt tokens
            session = Session(bind=conn)
            now = datetime.now(timezone.utc)
            
            deleted = session.query(CardToken).filter(CardToken.expires_at < now).delete()
            session.commit()
            
            logger.info(f"deleted {deleted} expired virtual card(s).")
    except OperationalError:
        logger.error("failed to connect to the database.", exc_info=True)
    except SQLAlchemyError as e:
        logger.error(f"database error during startup: {str(e)}", exc_info=True)
    yield

# initialize FastAPI app with enhanced documentation
app = FastAPI(
    title="Card Tokenization API",
    version="1.0.0",
    lifespan=lifespan
)

security_scheme = HTTPBearer()

def custom_openapi():
    """customize the openapi schema with security definitions."""
    
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

environment = os.getenv("ENVIRONMENT", "development")
if environment == "production":
    # add CORS middleware for production
    origins = [x.strip() for x in os.getenv("CORS_ORIGINS", "*").split(",")]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

@app.get("/health")
def health_check():
    """check api health status."""
    
    return {"status": "ok"}

app.include_router(card.router)
app.include_router(auth.router)

Base.metadata.create_all(bind=engine)