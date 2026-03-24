from pydantic import BaseModel
from typing import List, Optional


class Finding(BaseModel):
    layer: str
    credential_type: str
    description: str
    risk_tier: str
    redacted_value: str
    value_hash: str
    context_snippet: str
    char_position: int
    confidence: float

    model_config = {"extra": "allow"}


class ScanReport(BaseModel):
    scan_id: str
    timestamp: str
    source_type: str
    filename: Optional[str] = None
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    risk_score: float
    risk_label: str
    findings: List[Finding]
    context_signals: dict
    human_summary: str
    recommended_action: str
    llm_available: bool = False