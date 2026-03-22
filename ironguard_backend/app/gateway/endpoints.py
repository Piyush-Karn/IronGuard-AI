"""
app/gateway/endpoints.py
=========================
External gateway endpoints. These mirror /api/v1/ endpoints but require
HMAC signature auth instead of X-User-Id. The middleware handles auth —
route handlers only deal with business logic.
"""

import asyncio
import logging
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from typing import Optional

from app.security_engine.decision import decision_engine
from app.proxy.llm_proxy import llm_proxy, ProxyError
from app.response_security.response_monitor import response_monitor
from app.monitoring.security_logger import security_logger
from app.models.schemas import ThreatLog, ClassifierOutput, PromptRequest
from app.gateway.client_registry import client_registry
from app.api.endpoints import ScanResponse, ProcessedResponse

logger = logging.getLogger(__name__)
router = APIRouter()


class GatewayPromptRequest(BaseModel):
    prompt: str
    session_id: Optional[str] = None
    user_id: Optional[str] = "gateway-user"  # client app's own user identifier
    external_content: Optional[str] = None


class GatewayPromptResponse(BaseModel):
    response: str
    action_taken: str
    risk_score: int
    base_risk_score: int
    attack_types: list[str]
    fingerprint_match: bool
    request_id: str


class GatewayScanRequest(BaseModel):
    prompt: str
    session_id: Optional[str] = None
    user_id: Optional[str] = "gateway-user"


class GatewayScanResponse(BaseModel):
    risk_score: int
    base_risk_score: int
    classification: str
    action: str
    attack_types: list[str]
    reasons: list[str]
    fingerprint_match: bool


@router.post("/prompt", response_model=GatewayPromptResponse)
async def gateway_prompt(request: GatewayPromptRequest, req: Request):
    """
    Full security pipeline + LLM forwarding.
    Equivalent to /api/v1/process_prompt but requires HMAC auth.
    """
    client_id = req.state.gateway_client_id
    ip_address = req.client.host if req.client else "unknown"

    # Full detection pipeline (reuses existing decision engine)
    norm_prompt, risk_explanation, action, classifier_result, fp_result, san_result = \
        await decision_engine.evaluate_request(
            request.prompt,
            user_id=f"gateway:{client_id}:{request.user_id}",
            session_id=request.session_id,
        )

    # Build log entry
    classifier_output = ClassifierOutput(
        label=classifier_result.label,
        confidence=classifier_result.confidence,
        is_malicious=classifier_result.is_malicious,
        latency_ms=classifier_result.latency_ms,
    )
    threat_log = ThreatLog(
        user_id=f"gateway:{client_id}",
        prompt=request.prompt,
        risk_score=risk_explanation.risk_score,
        classification=risk_explanation.classification,
        action_taken=action,
        ip_address=ip_address,
        reasons=risk_explanation.reasons,
        attack_types=risk_explanation.attack_types,
        raw_detection_score=risk_explanation.base_risk_score,
        classifier_output=classifier_output,
    )

    if action == "Blocked":
        await security_logger.log_event(threat_log)
        return GatewayPromptResponse(
            response="Request blocked by IronGuard security policy.",
            action_taken="Blocked",
            risk_score=risk_explanation.risk_score,
            base_risk_score=risk_explanation.base_risk_score,
            attack_types=risk_explanation.attack_types,
            fingerprint_match=fp_result.is_match,
            request_id=str(__import__("uuid").uuid4()),
        )

    # Determine forwarded prompt
    final_prompt = norm_prompt
    if action == "Sanitized" and san_result and san_result.sanitized_prompt:
        final_prompt = san_result.sanitized_prompt

    # Forward to LLM proxy (keys isolated here)
    proxy_result = await llm_proxy.route_request(
        provider="auto",
        prompt=final_prompt,
        user_id=f"gateway:{client_id}",
        external_content=request.external_content,
    )

    if isinstance(proxy_result, ProxyError):
        raise HTTPException(
            status_code=proxy_result.code,
            detail=proxy_result.message,
        )

    # Scan response
    scan_result = await response_monitor.scan(proxy_result.text)
    final_text = proxy_result.text
    log_action = action

    if scan_result.action == "block":
        final_text = "Response blocked by IronGuard response security."
        log_action = "Response Blocked"
    elif scan_result.action == "redact":
        final_text = scan_result.redacted_text or proxy_result.text
        log_action = "Response Redacted"

    threat_log.action_taken = log_action
    await security_logger.log_event(threat_log)

    return GatewayPromptResponse(
        response=final_text,
        action_taken=log_action,
        risk_score=risk_explanation.risk_score,
        base_risk_score=risk_explanation.base_risk_score,
        attack_types=risk_explanation.attack_types,
        fingerprint_match=fp_result.is_match,
        request_id=proxy_result.request_id,
    )


@router.post("/scan", response_model=GatewayScanResponse)
async def gateway_scan(request: GatewayScanRequest, req: Request):
    """
    Scan only — no LLM forwarding. Returns risk assessment.
    Equivalent to /api/v1/scan_prompt but requires HMAC auth.
    """
    norm_prompt, risk_explanation, action, classifier_result, fp_result, _ = \
        await decision_engine.evaluate_request(
            request.prompt,
            user_id=f"gateway:{req.state.gateway_client_id}:{request.user_id}",
            session_id=request.session_id,
        )

    # Log the scan event
    classifier_output = ClassifierOutput(
        label=classifier_result.label,
        confidence=classifier_result.confidence,
        is_malicious=classifier_result.is_malicious,
        latency_ms=classifier_result.latency_ms,
    )
    threat_log = ThreatLog(
        user_id=f"gateway:{req.state.gateway_client_id}",
        prompt=request.prompt,
        risk_score=risk_explanation.risk_score,
        classification=risk_explanation.classification,
        action_taken=f"Scan: {action}",
        ip_address=req.client.host if req.client else "unknown",
        reasons=risk_explanation.reasons,
        attack_types=risk_explanation.attack_types,
        raw_detection_score=risk_explanation.base_risk_score,
        classifier_output=classifier_output,
    )
    await security_logger.log_event(threat_log)

    return GatewayScanResponse(
        risk_score=risk_explanation.risk_score,
        base_risk_score=risk_explanation.base_risk_score,
        classification=risk_explanation.classification,
        action=action,
        attack_types=risk_explanation.attack_types,
        reasons=risk_explanation.reasons,
        fingerprint_match=fp_result.is_match,
    )


@router.post("/process", response_model=ProcessedResponse)
async def gateway_process_prompt(request: PromptRequest, req: Request):
    """
    Gateway-specific scan endpoint for Internal Dashboard consumption.
    Shares the same response model as the main API but uses HMAC auth.
    """
    client_id = req.state.gateway_client_id
    ip_address = req.client.host if req.client else "unknown"

    # 1. Full detection pipeline
    norm_prompt, risk_explanation, action, classifier_result, fp_result, san_result = \
        await decision_engine.evaluate_request(
            request.prompt,
            user_id=f"gateway:{client_id}:{request.user_id}",
            session_id=request.conversation_id,
        )

    # 2. Build response components
    classifier_output = ClassifierOutput(
        label=classifier_result.label,
        confidence=classifier_result.confidence,
        is_malicious=classifier_result.is_malicious,
        latency_ms=classifier_result.latency_ms,
    )

    if action == "Blocked":
        threat_log = ThreatLog(
            user_id=f"gateway:{client_id}",
            prompt=request.prompt,
            risk_score=risk_explanation.risk_score,
            classification=risk_explanation.classification,
            action_taken=action,
            ip_address=ip_address,
            reasons=risk_explanation.reasons,
            attack_types=risk_explanation.attack_types,
            raw_detection_score=risk_explanation.base_risk_score,
            classifier_output=classifier_output,
        )
        await security_logger.log_event(threat_log)
        return ProcessedResponse(
            risk_explanation=risk_explanation,
            action=action,
            classifier_output=classifier_output,
            violation_notes=["Request blocked by IronGuard Security Engine."],
            fingerprint_match=fp_result.is_match,
            raw_detection_score=risk_explanation.base_risk_score,
        )

    # 3. LLM Forwarding
    final_prompt = norm_prompt
    if action == "Sanitized" and san_result and san_result.sanitized_prompt:
        final_prompt = san_result.sanitized_prompt

    proxy_result = await llm_proxy.route_request(
        provider="auto",
        prompt=final_prompt,
        user_id=f"gateway:{client_id}",
    )

    if isinstance(proxy_result, ProxyError):
        raise HTTPException(status_code=502, detail=proxy_result.message)

    # MOD-2: Scan LLM response for safety violations
    scan_result = await response_monitor.scan(proxy_result.text)
    final_response_text = proxy_result.text
    log_action = action
    violations_for_log: list[str] = []

    if scan_result.action == "block":
        log_action = "Response Blocked"
        violations_for_log = [f"{v.type}: {v.matched_pattern}" for v in scan_result.violations]
        final_response_text = "Response blocked by IronGuard Response Security Scanner."
    elif scan_result.action == "redact":
        log_action = "Response Redacted"
        violations_for_log = [f"{v.type}: {v.matched_pattern}" for v in scan_result.violations]
        final_response_text = scan_result.redacted_text or proxy_result.text

    threat_log = ThreatLog(
        user_id=f"gateway:{client_id}",
        prompt=request.prompt,
        risk_score=risk_explanation.risk_score,
        classification=risk_explanation.classification,
        action_taken=log_action,
        ip_address=ip_address,
        reasons=risk_explanation.reasons,
        attack_types=risk_explanation.attack_types,
        raw_detection_score=risk_explanation.base_risk_score,
        classifier_output=classifier_output,
    )
    await security_logger.log_event(threat_log)

    return ProcessedResponse(
        risk_explanation=risk_explanation,
        action=log_action,
        classifier_output=classifier_output,
        llm_response=final_response_text,
        violation_notes=violations_for_log if violations_for_log else None,
        sanitized_prompt=san_result.sanitized_prompt if action == "Sanitized" else None,
        fingerprint_match=fp_result.is_match,
        raw_detection_score=risk_explanation.base_risk_score
    )
