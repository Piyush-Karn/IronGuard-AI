from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime
from enum import Enum

class Role(str, Enum):
    ADMIN = "admin"
    EMPLOYEE = "employee"


class UserBase(BaseModel):
    username: str
    email: str


class UserCreate(UserBase):
    password: str


class UserResponse(UserBase):
    id: str
    role: Role
    created_at: datetime


class PromptRequest(BaseModel):
    user_id: str
    prompt: str
    user_email: Optional[str] = None
    conversation_id: Optional[str] = None
    provider: Optional[str] = "auto"  # gemini, mistral, openai, anthropic


class RiskExplanation(BaseModel):
    risk_score: int
    base_risk_score: int = 0
    classification: str   # Safe | Suspicious | Malicious
    reasons: List[str]
    attack_types: List[str]
    # Prompt Injection | System Prompt Leak | Jailbreak Attempt | Policy Bypass
    # Data Exfiltration | Sensitive Data Extraction | Roleplay / Framing Jailbreak
    # Harmful Content


class ClassifierOutput(BaseModel):
    """Snapshot of the intent classifier result stored with every log entry."""
    label: str          # SAFE | PROMPT_INJECTION | JAILBREAK | ROLEPLAY_ATTACK
                        # DATA_EXFILTRATION | HARMFUL_INSTRUCTION
    confidence: float
    is_malicious: bool
    latency_ms: float


class ThreatLog(BaseModel):
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    user_id: str
    user_email: Optional[str] = None
    prompt: str
    risk_score: int
    classification: str
    action_taken: str               # Passed | Sanitized | Blocked
    ip_address: Optional[str] = None
    reasons: List[str]
    attack_types: List[str]
    raw_detection_score: int = 0
    classifier_output: Optional[ClassifierOutput] = None


class UserTrustScore(BaseModel):
    user_id: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    role: Role = Role.EMPLOYEE
    trust_score: int = 100
    malicious_attempts: int = 0
    last_updated: datetime = Field(default_factory=datetime.utcnow)


class UserRoleUpdate(BaseModel):
    user_id: str
    role: Role


class AttackPattern(BaseModel):
    pattern_id: str
    description: str
    pattern_text: str
    attack_type: str
    created_at: datetime = Field(default_factory=datetime.utcnow)

class ProviderKeyUpdate(BaseModel):
    provider: str  # gemini, mistral, openai, etc.
    api_key: str

class ProviderKeyResponse(BaseModel):
    provider: str
    is_active: bool
    updated_at: datetime