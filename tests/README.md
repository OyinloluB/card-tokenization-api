# tests/README.md
# Testing Approach

## What We're Doing

I've set up this testing strategy after dealing with some SQLite vs PostgreSQL issues:

### Unit Tests
- I've focused on solid unit test coverage for the core business logic
- Most of the important stuff (services, security, validation) is tested thoroughly
- Check out the tests in `tests/unit/` to see what's covered

### Smoke Tests
- Simple tests that just check if our endpoints are actually there
- Avoids all the headaches with database and JWT validation
- Just confirms routes don't return 404s - good enough for now

### Known Issues
I ran into several problems with full integration tests:
- SQLite and PostgreSQL handle UUIDs differently (big pain point)
- JWT validation is a nightmare to test properly
- Some weird behavior with Pydantic validation in test vs. production

### Future Work
When I have time, I'd like to:
- Switch to using actual PostgreSQL for testing
- Build better fixtures for JWT stuff
- Maybe look into contract testing instead of fighting with the current approach

The smoke tests aren't perfect, but they're reliable and catch the obvious issues. The unit tests do the heavy lifting for now.

### Running Tests

To run the test suite:

```bash
# Run all tests
python -m pytest

# Run only unit tests
python -m pytest tests/unit/

# Run only smoke tests
python -m pytest tests/integration/