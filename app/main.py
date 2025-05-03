from fastapi import FastAPI
from fastapi.security import HTTPBearer
from contextlib import asynccontextmanager
from sqlalchemy.exc import OperationalError
from dotenv import load_dotenv

from app.db.session import engine
from app.models.token import Base
from app.routes import token, auth

import os

load_dotenv()

print("DATABASE_URL:", os.getenv("DATABASE_URL"))

@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        with engine.connect() as conn:
            print("Connected to the database successfully.")
    except OperationalError:
        print("Failed to connect to the database.")
    yield

app = FastAPI(
    title="Tokenization API",
    version="1.0.0",
    lifespan=lifespan
)

security_scheme = HTTPBearer()

@app.get("/health")
def health_check():
    return {"status": "ok"}

app.include_router(token.router)
app.include_router(auth.router)

Base.metadata.create_all(bind=engine)