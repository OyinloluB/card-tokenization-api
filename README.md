# Card Tokenization API

A secure REST API for tokenizing credit card information, built with FastAPI and PostgreSQL.

## Overview

This project provides a secure way to handle payment card data without storing sensitive information. It uses JWT-based tokenization with different permission scopes and security features.

### Key Features

- **Secure Tokenization**: Convert sensitive card data into secure tokens
- **Permission Scopes**: Fine-grained access control with read-only, full-access, and refresh-only scopes
- **Token Lifecycle Management**: Create, revoke, refresh, and delete tokens
- **User Authentication**: Secure JWT-based user authentication

## Technologies

- **FastAPI**: Modern, high-performance web framework
- **PostgreSQL**: Robust relational database
- **SQLAlchemy**: Powerful ORM for database interactions
- **Pydantic**: Data validation and settings management
- **JWT**: JSON Web Tokens for secure authentication and tokenization

## Getting Started

### Prerequisites

- Python 3.10+
- PostgreSQL
- Docker and Docker Compose

### Installation

1. Clone the repository:

```
git clone https://github.com/OyinloluB/card-tokenization-api.git`
cd card-tokenization-api
```

2. Set up a virtual environment:

```
python -m venv venv
source venv/bin/activate
```

3. Install dependencies:

`pip install -r requirements.txt`

4. Create a `.env` file with the following variables:

```
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/tokenization_db
JWT_SECRET_KEY=your_secure_secret_key
JWT_ALGORITHM=HS256
TOKEN_EXPIRE_SECONDS=3600
```

### Running with Docker

1. Start the services:

`docker-compose up -d`

2. The API will be available at `http://localhost:8000`

### Running Locally

1. Start Docker
2. Run the application:
`uvicorn app.main:app --reload`
3. The API will be available at `http://localhost:8000`

## API Documentation

The API documentation is available at `/docs` or `/redoc` when the server is running.

### Key Endpoints

- **Authentication**
- POST `/auth/signup`: Register a new user
- POST `/auth/login`: Authenticate and get a user token

- **Card Tokenization**
- POST `/card`: Create a new card token
- GET `/cards`: List all card tokens
- GET `/card/{id}`: Get a specific card token
- PATCH `/card/{id}/revoke`: Revoke a card token
- DELETE `/card/{id}`: Delete a card token
- POST `/card/{id}/refresh`: Refresh a card token's expiration

## Security Model

This API implements a two-layer security model:
1. **User Authentication**: Verifies the user owns the cards they're accessing
2. **Token Verification**: Ensures the exact token that tokenized a card is used to manipulate it

### Permission Scopes

- **read-only**: Can only view card information
- **full-access**: Can perform all operations
- **refresh-only**: Can only refresh tokens