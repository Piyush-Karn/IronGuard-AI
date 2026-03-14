from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime

class UserBase(BaseModel):
    username: str
    email: str

class UserCreate(UserBase):
    password: str

class UserResponse(UserBase):
    id: str
    created_at: datetime
    
class PromptRequest(BaseModel):
    user_id: str
    prompt: str
    conversation_id: Optional[str] = None
    
class RiskExplanation(BaseModel):
    risk_score: int
    classification: str # Safe, Suspicious, Malicious
    reasons: List[str]
    attack_types: List[str] # Prompt Injection, System Prompt Leak, Jailbreak Attempt, Policy Bypass, Data Exfiltration

class ThreatLog(BaseModel):
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    user_id: str
    prompt: str
    risk_score: int
    classification: str
    action_taken: str # Passed, Sanitized, Blocked
    ip_address: Optional[str] = None
    reasons: List[str]
    attack_types: List[str]

class UserTrustScore(BaseModel):
    user_id: str
    trust_score: int = 100
    malicious_attempts: int = 0
    last_updated: datetime = Field(default_factory=datetime.utcnow)

class AttackPattern(BaseModel):
    pattern_id: str
    description: str
    pattern_text: str
    attack_type: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
