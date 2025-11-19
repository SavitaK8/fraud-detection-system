
import phonenumbers
from typing import Dict, List

class PhoneDetector:
    """
    Phone number analysis for fraud detection
    """
    
    def __init__(self):
        self.premium_prefixes_india = ['1860', '1600', '1868', '1869', '1900']
        self.high_risk_country_codes = [234, 254, 233, 880]  # Nigeria, Kenya, Ghana, Bangladesh
    
    def analyze(self, phone_number: str) -> Dict:
        """
        Analyze phone number for fraud indicators
        """
        score = 0
        threats = []
        details = []
        
        try:
            # Parse phone number
            parsed = phonenumbers.parse(phone_number, None)
            
            # Validate format
            if not phonenumbers.is_valid_number(parsed):
                score += 20
                threats.append("⚠️ INVALID FORMAT: Phone number format is invalid")
            else:
                details.append("✓ Valid phone number format")
            
            # Get number type
            number_type = phonenumbers.number_type(parsed)
            
            # Check for premium rate
            if number_type == phonenumbers.PhoneNumberType.PREMIUM_RATE:
                score += 50
                threats.append("🚨 PREMIUM RATE: High-cost phone number detected")
            
            # Get country code
            country_code = parsed.country_code
            
            # Check for high-risk regions
            if country_code in self.high_risk_country_codes:
                score += 15
                threats.append(f"⚠️ HIGH-RISK REGION: Number from fraud-prone area (+{country_code})")
            
            # Check Indian premium prefixes
            national_number = str(parsed.national_number)
            
            for prefix in self.premium_prefixes_india:
                if national_number.startswith(prefix):
                    score += 40
                    threats.append(f"🚨 PREMIUM SERVICE: High-cost service number (starts with {prefix})")
                    break
            
            # Add informational details
            details.append(f"ℹ️ Country code: +{country_code}")
            details.append(f"ℹ️ Number type: {number_type.name}")
            
            # Check if number is possible
            if not phonenumbers.is_possible_number(parsed):
                score += 15
                threats.append("⚠️ IMPOSSIBLE NUMBER: Number length invalid for region")
            
        except phonenumbers.NumberParseException as e:
            score += 25
            threats.append(f"⚠️ PARSE ERROR: {str(e)}")
        except Exception as e:
            score += 20
            threats.append(f"⚠️ ANALYSIS ERROR: {str(e)}")
        
        return self._create_response(score, threats, details)
    
    def _create_response(self, score: int, threats: List[str], details: List[str]) -> Dict:
        """Create standardized response"""
        score = min(score, 100)
        
        if score >= 70:
            risk_level = "HIGH RISK"
            recommendation = "🚨 Do NOT call or share information. Likely scam number."
        elif score >= 40:
            risk_level = "MEDIUM RISK"
            recommendation = "⚠️ Verify through official channels before engaging."
        elif score >= 20:
            risk_level = "LOW RISK"
            recommendation = "ℹ️ Exercise caution with this number."
        else:
            risk_level = "SAFE"
            recommendation = "✅ Phone number appears legitimate."
        
        return {
            'score': score,
            'risk_level': risk_level,
            'recommendation': recommendation,
            'threats': threats,
            'details': details,
            'analysis_type': 'phone'
        }
