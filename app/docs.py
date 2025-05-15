"""
API documentation configuration for the Card Tokenization API.
"""

tags_metadata = [
    {
        "name": "Authentication",
        "description": "Operations for user registration and authentication.",
    },
    {
        "name": "Cards",
        "description": "Operations for managing card tokens including creation, revocation, refresh, and deletion.",
    },
    {
        "name": "Utility",
        "description": "Utility endpoints for health checks and diagnostics.",
    },
]

# API description
api_description = """
# Card Tokenization API

A secure API for tokenizing credit card information.

## Key Features

* **Secure Tokenization**: Convert sensitive card data into secure tokens
* **Permission Scopes**: Fine-grained access control with read-only, full-access, and refresh-only scopes
* **Token Lifecycle**: Create, revoke, refresh, and delete tokens
* **User Authentication**: Secure JWT-based user authentication

## Security Model

This API implements a two-layer security model:
1. **User Authentication**: Verifies the user owns the cards they're accessing
2. **Token Verification**: Ensures the exact token that tokenized a card is used to manipulate it

## Permission Scopes

* **read-only**: Can only view card information
* **full-access**: Can perform all operations
* **refresh-only**: Can only refresh tokens

## Authentication

All endpoints require authentication:
- For user operations: Use the token from `/auth/login`
- For card operations: Use either a user token or a card token with appropriate scope
"""

# security scheme definitions
security_schemes = {
    "HTTPBearer": {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT",
        "description": """
        JWT token authentication.
        
        * For user authentication endpoints, use the token from /auth/login
        * For card operations, use the specific card token with appropriate scope
        """
    }
}