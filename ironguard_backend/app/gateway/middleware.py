"""
app/gateway/middleware.py
==========================
FastAPI middleware that intercepts all /gateway/v1/ requests and
enforces HMAC signature verification before any route handler runs.

If verification fails: 401 or 403 returned immediately.
If verification passes: request proceeds to route handler normally.
"""

import logging
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from app.gateway.signing import verify_timestamp, verify_signature
from app.gateway.client_registry import client_registry

logger = logging.getLogger(__name__)

GATEWAY_PATH_PREFIX = "/gateway/v1/"


class GatewaySignatureMiddleware(BaseHTTPMiddleware):

    async def dispatch(self, request: Request, call_next):

        # Only intercept /gateway/v1/ routes
        if not request.url.path.startswith(GATEWAY_PATH_PREFIX):
            return await call_next(request)

        # ── 1. Extract required headers ───────────────────────────────────────
        client_id = request.headers.get("X-IG-Client-Id")
        timestamp = request.headers.get("X-IG-Timestamp")
        provided_sig = request.headers.get("X-IG-Signature")

        if not all([client_id, timestamp, provided_sig]):
            return JSONResponse(
                status_code=401,
                content={"detail": "Missing required headers: X-IG-Client-Id, X-IG-Timestamp, X-IG-Signature"},
                headers={"Access-Control-Allow-Origin": "*"}
            )

        # ── 2. Replay attack check ────────────────────────────────────────────
        ts_valid, ts_error = verify_timestamp(timestamp)
        if not ts_valid:
            logger.warning(f"Gateway replay attempt from client={client_id}: {ts_error}")
            return JSONResponse(
                status_code=401,
                content={"detail": f"Request rejected: {ts_error}"},
                headers={"Access-Control-Allow-Origin": "*"}
            )

        # ── 3. Lookup client and decrypt secret ──────────────────────────────
        raw_secret = await client_registry.get_decrypted_secret(client_id)
        if not raw_secret:
            logger.warning(f"Gateway request from unknown/inactive client_id={client_id}")
            return JSONResponse(
                status_code=403,
                content={"detail": "Unknown or inactive client"},
                headers={"Access-Control-Allow-Origin": "*"}
            )

        # ── 4. Verify signature using decrypted raw_secret ────────────────────
        body_bytes = await request.body()

        sig_valid = verify_signature(
            provided_sig, raw_secret, timestamp, client_id, body_bytes
        )

        if not sig_valid:
            logger.warning(f"Gateway signature mismatch for client={client_id}")
            return JSONResponse(
                status_code=401,
                content={"detail": "Signature verification failed"},
                headers={"Access-Control-Allow-Origin": "*"}
            )

        # ── 5. Attach client_id to request state for route handlers ──────────
        request.state.gateway_client_id = client_id

        # ── 6. Record usage (fire-and-forget, non-blocking) ───────────────────
        import asyncio
        asyncio.create_task(client_registry.record_usage(client_id))

        return await call_next(request)
