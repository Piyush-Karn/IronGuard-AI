import logging
import asyncio
from fastapi import Request
from fastapi.responses import JSONResponse
from app.gateway.signing import verify_timestamp, verify_signature
from app.gateway.client_registry import client_registry

logger = logging.getLogger(__name__)

GATEWAY_PATH_PREFIX = "/gateway/v1/"

class GatewaySignatureMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive)
        path = scope["path"]

        # Only intercept /gateway/v1/ routes
        if not path.startswith(GATEWAY_PATH_PREFIX):
            await self.app(scope, receive, send)
            return

        # ── 0. Skip OPTIONS Preflight ────────────────────────────────────────
        if scope["method"] == "OPTIONS":
            await self.app(scope, receive, send)
            return

        # ── 1. Extract required headers ───────────────────────────────────────
        headers = dict(scope["headers"])
        # Header keys in ASGI are lowercase bytes
        def get_header(name: str):
            return headers.get(name.lower().encode()).decode() if name.lower().encode() in headers else None

        client_id = get_header("X-IG-Client-Id")
        timestamp = get_header("X-IG-Timestamp")
        provided_sig = get_header("X-IG-Signature")

        if not all([client_id, timestamp, provided_sig]):
            response = JSONResponse(
                status_code=401,
                content={"detail": "Missing required headers: X-IG-Client-Id, X-IG-Timestamp, X-IG-Signature"},
                headers={"Access-Control-Allow-Origin": "*"}
            )
            await response(scope, receive, send)
            return

        # ── 2. Replay attack check ────────────────────────────────────────────
        ts_valid, ts_error = verify_timestamp(timestamp)
        if not ts_valid:
            logger.warning(f"Gateway replay attempt from client={client_id}: {ts_error}")
            response = JSONResponse(
                status_code=401,
                content={"detail": f"Request rejected: {ts_error}"},
                headers={"Access-Control-Allow-Origin": "*"}
            )
            await response(scope, receive, send)
            return

        # ── 3. Lookup client and decrypt secret ──────────────────────────────
        raw_secret = await client_registry.get_decrypted_secret(client_id)
        if not raw_secret:
            logger.warning(f"Gateway request from unknown/inactive client_id={client_id}")
            response = JSONResponse(
                status_code=403,
                content={"detail": "Unknown or inactive client"},
                headers={"Access-Control-Allow-Origin": "*"}
            )
            await response(scope, receive, send)
            return

        # ── 4. Verify signature ──────────────────────────────────────────────
        # To verify signature, we must read the body. 
        # But we must also ensure the body is available for the next app.
        body = b""
        more_body = True
        while more_body:
            message = await receive()
            body += message.get("body", b"")
            more_body = message.get("more_body", False)

        sig_valid = verify_signature(
            provided_sig, raw_secret, timestamp, client_id, body
        )

        if not sig_valid:
            logger.warning(f"Gateway signature mismatch for client={client_id}")
            response = JSONResponse(
                status_code=401,
                content={"detail": "Signature verification failed"},
                headers={"Access-Control-Allow-Origin": "*"}
            )
            await response(scope, receive, send)
            return

        # ── 5. Record usage (fire-and-forget) ────────────────────────────────
        asyncio.create_task(client_registry.record_usage(client_id))

        # ── 6. Inject client_id into scope for downstream access ─────────────
        if "state" not in scope:
            scope["state"] = {}
        scope["state"]["gateway_client_id"] = client_id

        # ── 7. Re-construct receive to include the body we already read ──────
        async def receive_with_body():
            return {"type": "http.request", "body": body, "more_body": False}

        await self.app(scope, receive_with_body, send)
