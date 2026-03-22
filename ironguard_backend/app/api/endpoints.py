import asyncio
import os
import time
import logging
from datetime import datetime
from fastapi import APIRouter, HTTPException, Request, Depends, status
from pydantic import BaseModel
from typing import Optional, List

from app.api.auth import get_current_user_id, admin_only
from app.monitoring.user_manager import user_manager
from app.models.schemas import PromptRequest, RiskExplanation, ThreatLog, ClassifierOutput, Role

from app.security_engine.decision import decision_engine
from app.proxy.llm_proxy import llm_proxy, ProxyError               # MOD-1
from app.response_security.response_monitor import response_monitor  # MOD-2
from app.monitoring.user_behavior import user_behavior_monitor
from app.monitoring.security_logger import security_logger

logger = logging.getLogger(__name__)

router = APIRouter()

# --- User Profile & Stats (Restored) ---

@router.get("/auth/me")
async def get_me(
    user_id: str = Depends(get_current_user_id),
    email: Optional[str] = None,
    full_name: Optional[str] = None
):
    """
    Returns the current user's profile and role. 
    Syncs email and group name if provided.
    """
    role = await user_manager.get_user_role(user_id, email=email, full_name=full_name)
    is_verified = await user_manager.is_user_verified(user_id)
    return {"user_id": user_id, "role": role, "is_verified": is_verified}


@router.get("/users/me/stats")
async def get_my_stats(user_id: str = Depends(get_current_user_id)):
    """
    Returns personal security statistics for the authenticated user.
    """
    stats = await user_manager.get_user_stats(user_id)
    if not stats:
        raise HTTPException(status_code=404, detail="Stats not found")
    return stats

# --- Rate Limiting State (Verify Secret) ---
# In production, use Redis. For this demo, we use a simple in-memory dict.
verification_attempts = {} # {user_id/ip: (count, lockout_until)}

def check_verification_rate_limit(key: str):
    now = time.time()
    fail_limit = int(os.getenv("VERIFICATION_FAIL_LIMIT", "5"))
    cooldown = int(os.getenv("VERIFICATION_COOLDOWN_MINUTES", "15")) * 60

    if key in verification_attempts:
        count, lockout = verification_attempts[key]
        if now < lockout:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Too many failed attempts. Try again in {int((lockout - now)/60)} minutes."
            )
        if count >= fail_limit:
            # Reset after lockout expires
            verification_attempts[key] = (0, 0)
    return True

def record_verification_failure(key: str):
    now = time.time()
    fail_limit = int(os.getenv("VERIFICATION_FAIL_LIMIT", "5"))
    cooldown = int(os.getenv("VERIFICATION_COOLDOWN_MINUTES", "15")) * 60

    count, lockout = verification_attempts.get(key, (0, 0))
    count += 1
    if count >= fail_limit:
        lockout = now + cooldown
        logger.error(f"SECURITY_ALERT: Brute-force detected for {key}. Locked for {cooldown/60} mins.")
    
    verification_attempts[key] = (count, lockout)

# --- Verification Endpoints ---

class VerifySecretRequest(BaseModel):
    secret: str

@router.post("/auth/verify-secret")
async def verify_secret(v_req: VerifySecretRequest, req: Request, user_id: str = Depends(get_current_user_id)):
    """Verifies an employee's one-time authorization secret."""
    # Rate limit by both User ID and IP
    client_ip = req.client.host if req.client else "unknown"
    check_verification_rate_limit(user_id)
    check_verification_rate_limit(client_ip)

    success = await user_manager.verify_invite(user_id, v_req.secret)
    
    if success:
        verification_attempts.pop(user_id, None)
        verification_attempts.pop(client_ip, None)
        logger.info(f"User {user_id} successfully verified via secret from IP {client_ip}")
        return {"status": "success", "message": "Account verified successfully."}
    else:
        record_verification_failure(user_id)
        record_verification_failure(client_ip)
        logger.warning(f"Verification FAILED for user {user_id} from IP {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authorization secret."
        )

# --- Shadow Mode & Deprecated Endpoints ---

def log_shadow_usage(endpoint: str):
    """Logs usage of deprecated /api/v1 endpoints for migration tracking."""
    logger.warning(f"DEPRECATION_WARNING: Endpoint {endpoint} used. Please migrate to /gateway/v1/.")

async def enforce_verification(user_id: str):
    """Ensures non-admin users are verified before using AI."""
    is_verified = await user_manager.is_user_verified(user_id)
    if not is_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account not verified. Please provide your authorization secret."
        )

class ScanResponse(BaseModel):
    risk_explanation: RiskExplanation
    action: str
    classifier_output: Optional[ClassifierOutput] = None
    fingerprint_match: Optional[bool] = None
    fingerprint_method: Optional[str] = None
    raw_detection_score: int = 0


class ProcessedResponse(BaseModel):
    risk_explanation: RiskExplanation
    action: str
    classifier_output: Optional[ClassifierOutput] = None
    llm_response: Optional[str] = None
    violation_notes: Optional[List[str]] = None
    sanitized_prompt: Optional[str] = None      # shown only if sanitization occurred
    sanitization_info: Optional[dict] = None     # {method, rules_applied, similarity}
    fingerprint_match: Optional[bool] = None
    raw_detection_score: int = 0


@router.post("/scan_prompt", response_model=ScanResponse)
async def scan_prompt(request: PromptRequest, req: Request, user_id: str = Depends(get_current_user_id)):
    log_shadow_usage("/scan_prompt")
    await enforce_verification(user_id)
    
    ip_address = req.client.host if req.client else "unknown"

    # 1. Session termination check
    if await user_behavior_monitor.should_terminate_session(user_id):
        raise HTTPException(
            status_code=403,
            detail="Session terminated due to multiple malicious attempts."
        )


    # 3. Full hybrid evaluation — v3 returns 6 values
    norm_prompt, risk_explanation, action, classifier_result, fp_result, sanitization_result = \
        await decision_engine.evaluate_request(
            request.prompt,
            user_id=user_id,
            session_id=request.conversation_id
        )

    # 3.1 Session context update
    if request.conversation_id:
        from app.context.context_builder import context_builder
        asyncio.create_task(context_builder.add_to_context(
            request.conversation_id, user_id, request.prompt, risk_explanation.risk_score
        ))

    # 4. Trust score update
    await user_behavior_monitor.update_trust_score(
        user_id, risk_explanation.classification
    )

    # 5. Build classifier snapshot for logging
    classifier_output = ClassifierOutput(
        label=classifier_result.label,
        confidence=classifier_result.confidence,
        is_malicious=classifier_result.is_malicious,
        latency_ms=classifier_result.latency_ms,
    )

    # 6. Log event
    threat_log = ThreatLog(
        user_id=user_id,
        user_email=request.user_email,
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

    return ScanResponse(
        risk_explanation=risk_explanation,
        action=action,
        classifier_output=classifier_output,
        fingerprint_match=fp_result.is_match,
        fingerprint_method=fp_result.method_used if fp_result.is_match else None,
        raw_detection_score=risk_explanation.base_risk_score
    )


@router.get("/proxy/providers")
async def get_providers(user_id: str = Depends(get_current_user_id)):
    """
    Returns a list of available AI providers with configured API keys.
    Requires authentication to prevent probing by unauthenticated callers.
    """
    return await llm_proxy.get_available_providers()


@router.post("/process_prompt", response_model=ProcessedResponse)
async def process_prompt(request: PromptRequest, req: Request, user_id: str = Depends(get_current_user_id)):
    log_shadow_usage("/process_prompt")
    await enforce_verification(user_id)

    ip_address = req.client.host if req.client else "unknown"

    # 1. Session termination check
    if await user_behavior_monitor.should_terminate_session(user_id):
        raise HTTPException(
            status_code=403,
            detail="Session terminated due to multiple malicious attempts."
        )


    # 3. Full evaluation
    norm_prompt, risk_explanation, action, classifier_result, fp_result, sanitization_result = \
        await decision_engine.evaluate_request(
            request.prompt,
            user_id=user_id,
            session_id=request.conversation_id
        )

    # 3.1 Session context update
    if request.conversation_id:
        from app.context.context_builder import context_builder
        asyncio.create_task(context_builder.add_to_context(
            request.conversation_id, user_id, request.prompt, risk_explanation.risk_score
        ))

    # 4. Trust score update
    await user_behavior_monitor.update_trust_score(
        user_id, risk_explanation.classification
    )

    # 5. Build classifier output for logging
    classifier_output = ClassifierOutput(
        label=classifier_result.label,
        confidence=classifier_result.confidence,
        is_malicious=classifier_result.is_malicious,
        latency_ms=classifier_result.latency_ms,
    )

    # 6. If blocked — return immediately
    if action == "Blocked":
        threat_log = ThreatLog(
            user_id=user_id,
            user_email=request.user_email,
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

    # 7. Determine final prompt to forward
    if action == "Sanitized" and sanitization_result and sanitization_result.sanitized_prompt:
        final_prompt = sanitization_result.sanitized_prompt
    else:
        final_prompt = norm_prompt

    # 8. Forward to real LLM proxy
    proxy_result = await llm_proxy.route_request(
        provider=request.provider,
        prompt=final_prompt,
        user_id=user_id,
    )

    if isinstance(proxy_result, ProxyError):
        raise HTTPException(
            status_code=proxy_result.code if proxy_result.code != 429 else 429,
            detail=proxy_result.message,
        )

    llm_response_text = proxy_result.text

    # 9. MOD-2: Scan LLM response
    scan_result = await response_monitor.scan(llm_response_text)

    # 10. Log full exchange
    log_action = action
    violations_for_log: list[str] = []
    final_response_text = llm_response_text

    if scan_result.action == "block":
        log_action = "Response Blocked"
        violations_for_log = [f"{v.type}: {v.matched_pattern}" for v in scan_result.violations]
        final_response_text = "Response blocked by IronGuard Response Security Scanner."
    elif scan_result.action == "redact":
        log_action = "Response Redacted"
        violations_for_log = [f"{v.type}: {v.matched_pattern}" for v in scan_result.violations]
        final_response_text = scan_result.redacted_text or llm_response_text

    threat_log = ThreatLog(
        user_id=user_id,
        user_email=request.user_email,
        prompt=request.prompt,
        risk_score=risk_score if (risk_score := risk_explanation.risk_score) else 0,
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
        sanitized_prompt=final_prompt if action == "Sanitized" else None,
        sanitization_info={
            "method": sanitization_result.method,
            "rules_applied": sanitization_result.rules_applied,
            "intent_similarity": sanitization_result.intent_similarity_score,
        } if action == "Sanitized" and sanitization_result else None,
        fingerprint_match=fp_result.is_match,
        raw_detection_score=risk_explanation.base_risk_score
    )


class SimulateRequest(BaseModel):
    user_id: str
    prompt: str


@router.post("/simulate_attack")
async def simulate_attack(
    sim_req: SimulateRequest,
    req: Request,
    authenticated_user_id: str = Depends(get_current_user_id),
):
    log_shadow_usage("/simulate_attack")
    await enforce_verification(authenticated_user_id)  # use header, not body
    prompt_req = PromptRequest(user_id=authenticated_user_id, prompt=sim_req.prompt)
    return await scan_prompt(prompt_req, req, user_id=authenticated_user_id)


class UnblockRequest(BaseModel):
    user_id: str


@router.post("/unblock", dependencies=[Depends(admin_only)])
async def unblock_user(request: UnblockRequest):
    await user_behavior_monitor.reset_trust_score(request.user_id)
    new_status = await user_behavior_monitor.get_or_create_trust_score(request.user_id)
    return {
        "status": "success",
        "message": f"Trust score restored for user {request.user_id}",
        "current_state": {
            "trust_score": new_status.trust_score,
            "malicious_attempts": new_status.malicious_attempts,
        },
    }