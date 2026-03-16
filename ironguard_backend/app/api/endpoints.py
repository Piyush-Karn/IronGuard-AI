from fastapi import APIRouter, HTTPException, Request, Depends
from pydantic import BaseModel
from typing import Optional, List

from app.api.auth import get_current_user_id
from app.monitoring.user_manager import user_manager
from app.models.schemas import PromptRequest, RiskExplanation, ThreatLog, ClassifierOutput, Role

from app.services.prompt_processor import prompt_processor
from app.security_engine.decision import decision_engine
from app.proxy.llm_proxy import llm_proxy, ProxyError               # MOD-1
from app.response_security.response_monitor import response_monitor  # MOD-2
from app.monitoring.user_behavior import user_behavior_monitor
from app.monitoring.security_logger import security_logger

router = APIRouter()

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
    return {"user_id": user_id, "role": role}


@router.get("/users/me/stats")
async def get_my_stats(user_id: str = Depends(get_current_user_id)):
    """
    Returns personal security statistics for the authenticated user.
    """
    stats = await user_manager.get_user_stats(user_id)
    if not stats:
        raise HTTPException(status_code=404, detail="Stats not found")
    return stats


class ScanResponse(BaseModel):
    risk_explanation: RiskExplanation
    action: str
    classifier_output: Optional[ClassifierOutput] = None
    fingerprint_match: Optional[bool] = None
    fingerprint_method: Optional[str] = None


class ProcessedResponse(BaseModel):
    risk_explanation: RiskExplanation
    action: str
    classifier_output: Optional[ClassifierOutput] = None
    llm_response: Optional[str] = None
    violation_notes: Optional[List[str]] = None
    sanitized_prompt: Optional[str] = None      # shown only if sanitization occurred
    sanitization_info: Optional[dict] = None     # {method, rules_applied, similarity}
    fingerprint_match: Optional[bool] = None


@router.post("/scan_prompt", response_model=ScanResponse)
async def scan_prompt(request: PromptRequest, req: Request):
    ip_address = req.client.host if req.client else "unknown"

    # 1. Session termination check
    if await user_behavior_monitor.should_terminate_session(request.user_id):
        raise HTTPException(
            status_code=403,
            detail="Session terminated due to multiple malicious attempts."
        )

    # 2. Normalize (additional normalization happens in decision engine via NFKC)
    normalized_prompt = prompt_processor.normalize(request.prompt)

    # 3. Full hybrid evaluation — v2 returns 5 values
    risk_explanation, action, classifier_result, fp_result, sanitization_result = \
        await decision_engine.evaluate_request(normalized_prompt)

    # 4. Trust score update
    await user_behavior_monitor.update_trust_score(
        request.user_id, risk_explanation.classification
    )

    # 5. Build classifier snapshot for logging
    classifier_output = ClassifierOutput(
        label=classifier_result.label,
        confidence=classifier_result.confidence,
        is_malicious=classifier_result.is_malicious,
        latency_ms=classifier_result.latency_ms,
    )

    # 6. Log event (now includes classifier + fingerprint data)
    threat_log = ThreatLog(
        user_id=request.user_id,
        prompt=request.prompt,
        risk_score=risk_explanation.risk_score,
        classification=risk_explanation.classification,
        action_taken=action,
        ip_address=ip_address,
        reasons=risk_explanation.reasons,
        attack_types=risk_explanation.attack_types,
        classifier_output=classifier_output,
    )
    await security_logger.log_event(threat_log)

    return ScanResponse(
        risk_explanation=risk_explanation,
        action=action,
        classifier_output=classifier_output,
        fingerprint_match=fp_result.is_match,
        fingerprint_method=fp_result.method_used if fp_result.is_match else None,
    )


@router.post("/process_prompt", response_model=ProcessedResponse)
async def process_prompt(request: PromptRequest, req: Request):
    ip_address = req.client.host if req.client else "unknown"

    # 1. Session termination check
    if await user_behavior_monitor.should_terminate_session(request.user_id):
        raise HTTPException(
            status_code=403,
            detail="Session terminated due to multiple malicious attempts."
        )

    # 2. Normalize
    normalized_prompt = prompt_processor.normalize(request.prompt)

    # 3. Full evaluation (v2 decision engine)
    risk_explanation, action, classifier_result, fp_result, sanitization_result = \
        await decision_engine.evaluate_request(normalized_prompt)

    # 4. Trust score update
    await user_behavior_monitor.update_trust_score(
        request.user_id, risk_explanation.classification
    )

    # 5. Build classifier output for logging
    classifier_output = ClassifierOutput(
        label=classifier_result.label,
        confidence=classifier_result.confidence,
        is_malicious=classifier_result.is_malicious,
        latency_ms=classifier_result.latency_ms,
    )

    # 6. If blocked — return immediately, no LLM call
    if action == "Blocked":
        threat_log = ThreatLog(
            user_id=request.user_id,
            prompt=request.prompt,
            risk_score=risk_explanation.risk_score,
            classification=risk_explanation.classification,
            action_taken=action,
            ip_address=ip_address,
            reasons=risk_explanation.reasons,
            attack_types=risk_explanation.attack_types,
            classifier_output=classifier_output,
        )
        await security_logger.log_event(threat_log)
        return ProcessedResponse(
            risk_explanation=risk_explanation,
            action=action,
            classifier_output=classifier_output,
            violation_notes=["Request blocked by IronGuard Security Engine."],
            fingerprint_match=fp_result.is_match,
        )

    # 7. Determine final prompt to forward
    #    - If sanitized: use the sanitizer's output
    #    - If passed: use the NFKC-normalized prompt
    if action == "Sanitized" and sanitization_result and sanitization_result.sanitized_prompt:
        final_prompt = sanitization_result.sanitized_prompt
    else:
        final_prompt = normalized_prompt

    # 8. MOD-1: Forward to real LLM proxy
    proxy_result = await llm_proxy.route_request(
        provider="openai",
        prompt=final_prompt,
        user_id=request.user_id,
    )

    if isinstance(proxy_result, ProxyError):
        raise HTTPException(
            status_code=proxy_result.code if proxy_result.code != 429 else 429,
            detail=proxy_result.message,
        )

    llm_response_text = proxy_result.text

    # 9. MOD-2: Scan LLM response for safety violations
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
        user_id=request.user_id,
        prompt=request.prompt,
        risk_score=risk_explanation.risk_score,
        classification=risk_explanation.classification,
        action_taken=log_action,
        ip_address=ip_address,
        reasons=risk_explanation.reasons,
        attack_types=risk_explanation.attack_types,
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
    )


class SimulateRequest(BaseModel):
    user_id: str
    prompt: str


@router.post("/simulate_attack")
async def simulate_attack(sim_req: SimulateRequest, req: Request):
    prompt_req = PromptRequest(user_id=sim_req.user_id, prompt=sim_req.prompt)
    return await scan_prompt(prompt_req, req)


class UnblockRequest(BaseModel):
    user_id: str


@router.post("/unblock")
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