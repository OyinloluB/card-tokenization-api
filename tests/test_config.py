"""
test configuration module.

this module sets up the test environment including:
- sqlite test database configuration
- test client setup 
- dependency overrides for testing
- fixtures for database setup/teardown
"""

import os
from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient
import pytest

TEST_DATABASE_URL = "sqlite:///./test.db"

os.environ["DATABASE_URL"] = TEST_DATABASE_URL

from app.db.session import Base
from app.main import app
from app.services.utils import get_db

test_engine = create_engine(TEST_DATABASE_URL)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

# test get_db function
def override_get_db() -> Generator:
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        
app.dependency_overrides[get_db] = override_get_db

client = TestClient(app)

@pytest.fixture(scope="function")
def test_db():
    # before each test: Create all tables in our test database
    Base.metadata.create_all(bind=test_engine)
    
    # run the test
    yield
    
    # after each test: Drop all tables to clean up
    Base.metadata.drop_all(bind=test_engine)