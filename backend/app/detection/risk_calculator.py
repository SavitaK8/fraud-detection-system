
from typing import Dict, Tuple

class RiskCalculator:
    """
    Centralized risk calculation and level determination
    """
    
    @staticmethod
    def calculate_risk_level(score: int) -> Tuple[str, str]:
        """
        Determine risk level and recommendation based on score
        Returns: (risk_level, recommendation)
        """
        score = min(score, 100)  # Cap at 100
        
        if score >= 70:
            return (
                "HIGH RISK",
                "🚨 Do NOT interact. Delete immediately and report to authorities."
            )
        elif score >= 40:
            return (
                "MEDIUM RISK",
                "⚠️ Verify through official channels before taking any action."
            )
        elif score >= 20:
            return (
                "LOW RISK",
                "ℹ️ Stay vigilant. Double-check sender/source identity."
            )
        else:
            return (
                "SAFE",
                "✅ Content appears legitimate. No major threats detected."
            )
    
    @staticmethod
    def get_risk_color(risk_level: str) -> str:
        """Get color code for risk level"""
        colors = {
            "HIGH RISK": "red",
            "MEDIUM RISK": "yellow",
            "LOW RISK": "blue",
            "SAFE": "green"
        }
        return colors.get(risk_level, "gray")
    
    @staticmethod
    def aggregate_scores(scores: Dict[str, int], weights: Dict[str, float] = None) -> int:
        """
        Aggregate multiple detection scores with optional weights
        """
        if not weights:
            weights = {key: 1.0 for key in scores.keys()}
        
        total_weighted = sum(scores[key] * weights.get(key, 1.0) for key in scores)
        total_weight = sum(weights.values())
        
        return int(min(total_weighted / total_weight, 100))
    
    @staticmethod
    def format_response(score: int, threats: list, details: list, 
                       ml_confidence: float = None, analysis_type: str = None) -> Dict:
        """
        Create standardized response format
        """
        risk_level, recommendation = RiskCalculator.calculate_risk_level(score)
        
        return {
            'score': min(score, 100),
            'risk_level': risk_level,
            'recommendation': recommendation,
            'threats': threats,
            'details': details,
            'ml_confidence': ml_confidence,
            'analysis_type': analysis_type or 'unknown'
        }
