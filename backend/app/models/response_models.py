
from pydantic import BaseModel, Field
from typing import List, Optional

class AnalysisResponse(BaseModel):
    """Standard response model for all analysis endpoints"""
    risk_score: int = Field(..., ge=0, le=100, description="Risk score 0-100")
    risk_level: str = Field(..., description="Risk level category")
    recommendation: str = Field(..., description="Security recommendation")
    threats: List[str] = Field(default_factory=list, description="Detected threats")
    details: List[str] = Field(default_factory=list, description="Security details")
    ml_confidence: Optional[float] = Field(None, description="ML model confidence 0-1")
    analysis_time_ms: float = Field(..., description="Analysis duration in milliseconds")
    analysis_type: str = Field(..., description="Type of analysis performed")
    
    class Config:
        schema_extra = {
            "example": {
                "risk_score": 85,
                "risk_level": "HIGH RISK",
                "recommendation": "🚨 Do NOT interact. Delete immediately.",
                "threats": [
                    "🚨 TYPOSQUATTING: Domain mimics 'paypal' (95% similar)",
                    "⚠️ SUSPICIOUS PATH: Contains 'verify'"
                ],
                "details": [
                    "✓ HTTPS: Encrypted connection",
                    "Domain age: Could not verify"
                ],
                "ml_confidence": 0.92,
                "analysis_time_ms": 347.56,
                "analysis_type": "url"
            }
        }

class HealthResponse(BaseModel):
    """Health check response"""
    status: str
    timestamp: float
    ml_model_status: str
    components: dict
    
class StatsResponse(BaseModel):
    """Statistics response"""
    system: str
    version: str
    detection_layers: int
    supported_formats: List[str]
    ml_model: str
    accuracy_target: str
    false_positive_target: str
    response_time_target: str
    features: dict
