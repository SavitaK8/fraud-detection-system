

from PIL import Image
import pytesseract
import io
from typing import Dict, List

class ImageDetector:
    """
    Image forensics and OCR-based fraud detection
    """
    
    def __init__(self):
        self.suspicious_keywords = [
            'verify', 'urgent', 'suspended', 'winner', 'prize',
            'claim', 'payment', 'transfer', 'bitcoin', 'wallet'
        ]
    
    def analyze(self, image_bytes: bytes, email_detector=None) -> Dict:
        """
        Analyze image for fraud indicators
        """
        score = 0
        threats = []
        details = []
        
        try:
            # Open image
            image = Image.open(io.BytesIO(image_bytes))
            
            # Check EXIF metadata
            exif_data = image.getexif()
            
            if not exif_data or len(exif_data) == 0:
                score += 15
                threats.append("⚠️ NO METADATA: EXIF data stripped (possible manipulation)")
            else:
                details.append(f"✓ EXIF data present ({len(exif_data)} tags)")
            
            # Check resolution
            width, height = image.size
            details.append(f"ℹ️ Image resolution: {width}x{height}")
            
            if width < 400 or height < 400:
                score += 12
                threats.append("⚠️ LOW RESOLUTION: Suspicious image quality")
            
            # Check file format
            image_format = image.format if image.format else "UNKNOWN"
            details.append(f"ℹ️ Format: {image_format}")
            
            if image_format not in ['PNG', 'JPEG', 'JPG']:
                score += 5
                threats.append(f"⚠️ UNUSUAL FORMAT: {image_format}")
            
            # Perform OCR text extraction
            try:
                extracted_text = pytesseract.image_to_string(image)
                
                if extracted_text.strip():
                    details.append(f"ℹ️ Extracted {len(extracted_text)} characters of text")
                    
                    # Check for suspicious keywords in extracted text
                    text_lower = extracted_text.lower()
                    found_keywords = [kw for kw in self.suspicious_keywords if kw in text_lower]
                    
                    if len(found_keywords) > 0:
                        score += len(found_keywords) * 8
                        threats.append(f"⚠️ SUSPICIOUS TEXT: Found keywords: {', '.join(found_keywords[:3])}")
                    
                    # If email detector available, analyze extracted text
                    if email_detector and len(extracted_text) > 20:
                        text_result = email_detector.analyze(extracted_text)
                        
                        if text_result['score'] > 40:
                            score += 30
                            threats.append("🚨 PHISHING TEXT: High-risk content in image")
                            # Add top 2 threats from text analysis
                            threats.extend(text_result['threats'][:2])
                        
                        details.append(f"✓ Text analysis: {text_result['risk_level']}")
                else:
                    details.append("ℹ️ No text extracted from image")
            
            except Exception as ocr_error:
                details.append(f"⚠️ OCR failed: {str(ocr_error)}")
            
            # Check aspect ratio (extremely wide/tall images can be suspicious)
            aspect_ratio = width / height if height > 0 else 1
            if aspect_ratio > 10 or aspect_ratio < 0.1:
                score += 8
                threats.append("⚠️ UNUSUAL DIMENSIONS: Extreme aspect ratio")
            
        except Exception as e:
            score += 20
            threats.append(f"⚠️ IMAGE ANALYSIS ERROR: {str(e)}")
        
        return self._create_response(score, threats, details)
    
    def _create_response(self, score: int, threats: List[str], details: List[str]) -> Dict:
        """Create standardized response"""
        score = min(score, 100)
        
        if score >= 70:
            risk_level = "HIGH RISK"
            recommendation = "🚨 Do NOT trust this image. Likely fraudulent content."
        elif score >= 40:
            risk_level = "MEDIUM RISK"
            recommendation = "⚠️ Verify image authenticity through official sources."
        elif score >= 20:
            risk_level = "LOW RISK"
            recommendation = "ℹ️ Image appears suspicious, verify if important."
        else:
            risk_level = "SAFE"
            recommendation = "✅ Image appears legitimate."
        
        return {
            'score': score,
            'risk_level': risk_level,
            'recommendation': recommendation,
            'threats': threats,
            'details': details,
            'analysis_type': 'image'
        }
