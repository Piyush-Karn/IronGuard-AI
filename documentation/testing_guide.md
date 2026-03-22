# IronGuard Testing Guide

This guide explains how to run, maintain, and extend the IronGuard test suite. We use a combination of **Pytest** for backend logic and **Vitest** for frontend API/UI logic.

---

## 1. Backend Testing (Pytest)

The backend tests are located in `ironguard_backend/tests/`.

### Prerequisites
Tests must be run inside the Docker container to ensure they have the correct environment and dependencies.

### Running Tests
Execute the following command from your terminal:
```bash
docker exec ironguard_backend-backend-1 pytest /app/tests -vv
```

### Mocking Strategy (conftest.py)
To ensure isolation and speed, we use a sophisticated mocking strategy:
- **Isolated App Factory**: Every test receives a fresh `FastAPI` instance via the `client` fixture. This bypasses the global application's middleware and lifespan side effects.
- **Singleton Patching**: We patch core service singletons (like `user_manager` and `client_registry`) directly on their instances to ensure consistent behavior across all routers.
- **Async Mocks**: All database and external service calls are replaced with `AsyncMock` to prevent real I/O.

---

## 2. Frontend Testing (Vitest)

The frontend tests are located in `frontend/src/`.

### Running Tests
Navigate to the `frontend` directory and run:
```bash
npm test
```
To run a specific test file:
```bash
npm test -- src/lib/api.test.ts
```

### Cryptography Polyfill
Because `jsdom` (the test environment) does not natively support the Web Crypto API, we polyfill `window.crypto` in `src/test/setup.ts` using Node's `node:crypto` module. This is critical for testing HMAC-SHA256 signing logic.

---

## 3. Key Test Areas

### Authentication & Roles
- **Backend**: `test_auth.py` and `test_admin_ops.py` verify that Role-Based Access Control (RBAC) is enforced at the router level.
- **Frontend**: `api.test.ts` verifies that the `X-User-Id` header is correctly attached to all requests.

### Gateway Security (HMAC)
- **Backend**: `test_gateway_security.py` tests the `GatewaySignatureMiddleware` by computing real signatures and verifying them against the backend's expected result.
- **Frontend**: `api.test.ts` verifies the `generateGatewayHeaders` function by checking the SHA-256 hash and HMAC signature generation.

---

## 4. Maintenance
- **Adding new endpoints**: When adding a new router, ensure it is included in the test `app` factory in `conftest.py`.
- **Database Changes**: If you add new MongoDB collections, update the `AsyncCollectionMock` in your test file or `conftest.py` as needed.
