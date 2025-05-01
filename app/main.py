from fastapi import FastAPI
from contextlib import asynccontextmanager
from app.db.session import engine
from sqlalchemy.exc import OperationalError
from dotenv import load_dotenv
from app.routes import token
from app.models.token import Base

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

app = FastAPI(lifespan=lifespan)

@app.get("/health")
def health_check():
    return {"status": "ok"}

app.include_router(token.router)

Base.metadata.create_all(bind=engine)