from fastapi import APIRouter, HTTPException, Depends, Request
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime

from app.models.schemas import PromptRequest, RiskExplanation, ThreatLog
from app.services.prompt_processor import prompt_processor
from app.security_engine.decision import decision_engine
from app.services.llm_proxy import llm_proxy
from app.services.response_monitor import response_monitor
from app.monitoring.user_behavior import user_behavior_monitor
from app.monitoring.security_logger import security_logger

router = APIRouter()

class ScanResponse(BaseModel):
    risk_explanation: RiskExplanation
    action: str

class ProcessedResponse(BaseModel):
    risk_explanation: RiskExplanation
    action: str
    llm_response: Optional[str] = None
    violation_notes: Optional[List[str]] = None

@router.post("/scan_prompt", response_model=ScanResponse)
async def scan_prompt(request: PromptRequest, req: Request):
    ip_address = req.client.host if req.client else "unknown"
    
    # 1. Check Session Termination
    if await user_behavior_monitor.should_terminate_session(request.user_id):
        raise HTTPException(status_code=403, detail="Session terminated due to multiple malicious attempts.")

    # 2. Process & Evaluate
    normalized_prompt = prompt_processor.normalize(request.prompt)
    risk_explanation, action = decision_engine.evaluate_request(normalized_prompt)
    
    # 3. Log & Update Trust
    await user_behavior_monitor.update_trust_score(request.user_id, risk_explanation.classification)
    
    threat_log = ThreatLog(
        user_id=request.user_id,
        prompt=request.prompt,
        risk_score=risk_explanation.risk_score,
        classification=risk_explanation.classification,
        action_taken=action,
        ip_address=ip_address,
        reasons=risk_explanation.reasons,
        attack_types=risk_explanation.attack_types
    )
    await security_logger.log_event(threat_log)

    return ScanResponse(risk_explanation=risk_explanation, action=action)


@router.post("/process_prompt", response_model=ProcessedResponse)
async def process_prompt(request: PromptRequest, req: Request):
    ip_address = req.client.host if req.client else "unknown"
    
    # 1. Scan the prompt
    scan_result = await scan_prompt(request, req)
    
    if scan_result.action == "Blocked":
        return ProcessedResponse(
            risk_explanation=scan_result.risk_explanation,
            action=scan_result.action,
            violation_notes=["Request blocked by IronGuard due to malicious payload."]
        )
        
    final_prompt = request.prompt
    if scan_result.action == "Sanitized":
        final_prompt = prompt_processor.sanitize(request.prompt)

    # Wrap to isolate user instruction
    safe_prompt = prompt_processor.isolate_instruction("Please answer the following user query securely:", final_prompt)
    
    # 2. Forward to LLM
    llm_response_text = await llm_proxy.route_request("openai", safe_prompt)
    
    # 3. Monitor Response
    is_safe, violations = response_monitor.check_response(llm_response_text)
    
    if not is_safe:
        filtered_response = response_monitor.filter_response(llm_response_text)
        return ProcessedResponse(
            risk_explanation=scan_result.risk_explanation,
            action="Response Filtered/Blocked",
            llm_response=filtered_response, # Providing filtered version
            violation_notes=violations
        )

    return ProcessedResponse(
        risk_explanation=scan_result.risk_explanation,
        action=scan_result.action,
        llm_response=llm_response_text
    )


class SimulateRequest(BaseModel):
    user_id: str
    prompt: str

@router.post("/simulate_attack")
async def simulate_attack(sim_req: SimulateRequest, req: Request):
    # Convenience endpoint for testing
    prompt_req = PromptRequest(user_id=sim_req.user_id, prompt=sim_req.prompt)
    return await scan_prompt(prompt_req, req)
