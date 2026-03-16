from fastapi import APIRouter, HTTPException, Request, Depends
from pydantic import BaseModel
from typing import Optional, List

from app.api.auth import get_current_user_id
from app.monitoring.user_manager import user_manager
from app.models.schemas import PromptRequest, RiskExplanation, ThreatLog, ClassifierOutput, Role

from app.services.prompt_processor import prompt_processor
from app.security_engine.decision import decision_engine
from app.services.llm_proxy import llm_proxy
from app.services.response_monitor import response_monitor
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
    classifier_output: Optional[ClassifierOutput] = None   # exposed in API response


class ProcessedResponse(BaseModel):
    risk_explanation: RiskExplanation
    action: str
    classifier_output: Optional[ClassifierOutput] = None
    llm_response: Optional[str] = None
    violation_notes: Optional[List[str]] = None


@router.post("/scan_prompt", response_model=ScanResponse)
async def scan_prompt(request: PromptRequest, req: Request):
    ip_address = req.client.host if req.client else "unknown"

    # 1. Session termination check
    if await user_behavior_monitor.should_terminate_session(request.user_id):
        raise HTTPException(
            status_code=403,
            detail="Session terminated due to multiple malicious attempts."
        )

    # 2. Normalize
    normalized_prompt = prompt_processor.normalize(request.prompt)

    # 3. Full hybrid evaluation (now async)
    risk_explanation, action, classifier_result = await decision_engine.evaluate_request(
        normalized_prompt
    )

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

    # 6. Log event (now includes classifier output)
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
    )


@router.post("/process_prompt", response_model=ProcessedResponse)
async def process_prompt(request: PromptRequest, req: Request):
    scan_result = await scan_prompt(request, req)

    if scan_result.action == "Blocked":
        return ProcessedResponse(
            risk_explanation=scan_result.risk_explanation,
            action=scan_result.action,
            classifier_output=scan_result.classifier_output,
            violation_notes=["Request blocked by IronGuard due to malicious payload."],
        )

    final_prompt = request.prompt
    if scan_result.action == "Sanitized":
        final_prompt = prompt_processor.sanitize(request.prompt)

    safe_prompt = prompt_processor.isolate_instruction(
        "Please answer the following user query securely:", final_prompt
    )

    llm_response_text = await llm_proxy.route_request("openai", safe_prompt)
    is_safe, violations = response_monitor.check_response(llm_response_text)

    if not is_safe:
        filtered_response = response_monitor.filter_response(llm_response_text)
        return ProcessedResponse(
            risk_explanation=scan_result.risk_explanation,
            action="Response Filtered/Blocked",
            classifier_output=scan_result.classifier_output,
            llm_response=filtered_response,
            violation_notes=violations,
        )

    return ProcessedResponse(
        risk_explanation=scan_result.risk_explanation,
        action=scan_result.action,
        classifier_output=scan_result.classifier_output,
        llm_response=llm_response_text,
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