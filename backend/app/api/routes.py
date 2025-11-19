
from fastapi import APIRouter, HTTPException, File, UploadFile, Request
from pydantic import BaseModel, Field, validator
from typing import Optional, List
import time
from PIL import Image
import io
import pytesseract
import phonenumbers

from app.detection.url_detector import URLDetector
from app.detection.email_detector import EmailDetector

# Initialize router
router = APIRouter(tags=["Analysis"])

# Initialize detectors
url_detector = URLDetector()

# Request Models
class URLAnalysisRequest(BaseModel):
    url: str = Field(..., description="URL to analyze", min_length=1)
    
    @validator('url')
    def validate_url(cls, v):
        if not v.strip():
            raise ValueError('URL cannot be empty')
        return v.strip()

class EmailAnalysisRequest(BaseModel):
    content: str = Field(..., description="Email or text content", min_length=1)
    sender_email: Optional[str] = Field(None, description="Sender email address")
    
    @validator('content')
    def validate_content(cls, v):
        if not v.strip():
            raise ValueError('Content cannot be empty')
        return v.strip()

class PhoneAnalysisRequest(BaseModel):
    phone_number: str = Field(..., description="Phone number to analyze")
    
    @validator('phone_number')
    def validate_phone(cls, v):
        if not v.strip():
            raise ValueError('Phone number cannot be empty')
        return v.strip()

# Response Model
class AnalysisResponse(BaseModel):
    risk_score: int = Field(..., ge=0, le=100, description="Risk score 0-100")
    risk_level: str = Field(..., description="Risk level category")
    recommendation: str = Field(..., description="Security recommendation")
    threats: List[str] = Field(default_factory=list, description="Detected threats")
    details: List[str] = Field(default_factory=list, description="Security details")
    ml_confidence: Optional[float] = Field(None, description="ML model confidence")
    analysis_time_ms: float = Field(..., description="Analysis duration in milliseconds")
    analysis_type: str = Field(..., description="Type of analysis performed")

# API Endpoints

@router.post("/analyze/url", response_model=AnalysisResponse, summary="Analyze URL for threats")
async def analyze_url(request: URLAnalysisRequest, req: Request):
    """
    Analyze URL for phishing, typosquatting, and security threats
    
    - **url**: The URL to analyze (with or without http/https prefix)
    
    Returns comprehensive threat assessment with:
    - Risk score (0-100)
    - Detected threats
    - Security details
    - Actionable recommendations
    """
    start_time = time.time()
    
    try:
        # Perform URL analysis
        result = url_detector.analyze(request.url)
        
        # Calculate analysis time
        analysis_time = (time.time() - start_time) * 1000
        
        return AnalysisResponse(
            risk_score=result['score'],
            risk_level=result['risk_level'],
            recommendation=result['recommendation'],
            threats=result['threats'],
            details=result['details'],
            ml_confidence=result.get('ml_confidence'),
            analysis_time_ms=round(analysis_time, 2),
            analysis_type=result['analysis_type']
        )
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"URL analysis failed: {str(e)}")

@router.post("/analyze/email", response_model=AnalysisResponse, summary="Analyze email/text for phishing")
async def analyze_email(request: EmailAnalysisRequest, req: Request):
    """
    Analyze email or text content for phishing patterns
    
    - **content**: Email body or text message content
    - **sender_email**: (Optional) Sender's email address for validation
    
    Uses ML-based classification and pattern matching to detect:
    - Phishing keywords
    - Social engineering tactics
    - Urgency manipulation
    - Embedded malicious links
    """
    start_time = time.time()
    
    try:
        # Get ML detector from app state
        ml_detector = req.app.state.ml_detector
        
        # Initialize email detector with ML model
        email_detector = EmailDetector(ml_detector=ml_detector)
        
        # Perform email analysis
        result = email_detector.analyze(
            content=request.content,
            sender_email=request.sender_email
        )
        
        # Calculate analysis time
        analysis_time = (time.time() - start_time) * 1000
        
        return AnalysisResponse(
            risk_score=result['score'],
            risk_level=result['risk_level'],
            recommendation=result['recommendation'],
            threats=result['threats'],
            details=result['details'],
            ml_confidence=result.get('ml_confidence'),
            analysis_time_ms=round(analysis_time, 2),
            analysis_type=result['analysis_type']
        )
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Email analysis failed: {str(e)}")

@router.post("/analyze/phone", response_model=AnalysisResponse, summary="Analyze phone number")
async def analyze_phone(request: PhoneAnalysisRequest):
    """
    Analyze phone number for fraud indicators
    
    - **phone_number**: Phone number in any format (international or local)
    
    Checks for:
    - Premium rate numbers
    - Invalid formats
    - High-risk country codes
    - Known scam prefixes
    """
    start_time = time.time()
    
    try:
        score = 0
        threats = []
        details = []
        
        phone = request.phone_number
        
        # Parse phone number
        try:
            parsed = phonenumbers.parse(phone, None)
            
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
            
            # Check for high-risk regions (common scam origins)
            high_risk_codes = [234, 254, 233, 880]  # Nigeria, Kenya, Ghana, Bangladesh
            if country_code in high_risk_codes:
                score += 15
                threats.append(f"⚠️ HIGH-RISK REGION: Number from fraud-prone area (+{country_code})")
            
            # Check Indian premium prefixes
            national_number = str(parsed.national_number)
            premium_prefixes = ['1860', '1600', '1868', '1869', '1900']
            
            if any(national_number.startswith(prefix) for prefix in premium_prefixes):
                score += 40
                threats.append(f"🚨 PREMIUM SERVICE: High-cost service number detected")
            
            details.append(f"ℹ️ Country code: +{country_code}")
            details.append(f"ℹ️ Number type: {phonenumbers.number_type(parsed).name}")
            
        except phonenumbers.NumberParseException as e:
            score += 25
            threats.append(f"⚠️ PARSE ERROR: {str(e)}")
        
        # Determine risk level
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
        
        # Calculate analysis time
        analysis_time = (time.time() - start_time) * 1000
        
        return AnalysisResponse(
            risk_score=min(score, 100),
            risk_level=risk_level,
            recommendation=recommendation,
            threats=threats,
            details=details,
            ml_confidence=None,
            analysis_time_ms=round(analysis_time, 2),
            analysis_type='phone'
        )
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Phone analysis failed: {str(e)}")

@router.post("/analyze/image", response_model=AnalysisResponse, summary="Analyze image for fraud")
async def analyze_image(file: UploadFile = File(...), req: Request = None):
    """
    Analyze image for fraud indicators using OCR and metadata analysis
    
    - **file**: Image file (PNG, JPEG, etc.)
    
    Performs:
    - OCR text extraction
    - EXIF metadata analysis
    - Resolution and quality checks
    - Text content phishing analysis
    """
    start_time = time.time()
    
    try:
        # Read image
        contents = await file.read()
        image = Image.open(io.BytesIO(contents))
        
        score = 0
        threats = []
        details = []
        
        # Check EXIF metadata
        exif_data = image.getexif()
        
        if not exif_data:
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
        image_format = image.format
        details.append(f"ℹ️ Format: {image_format}")
        
        if image_format not in ['PNG', 'JPEG', 'JPG']:
            score += 5
            threats.append(f"⚠️ UNUSUAL FORMAT: {image_format}")
        
        # Perform OCR
        try:
            extracted_text = pytesseract.image_to_string(image)
            
            if extracted_text.strip():
                details.append(f"ℹ️ Extracted {len(extracted_text)} characters of text")
                
                # Analyze extracted text for phishing
                ml_detector = req.app.state.ml_detector if req else None
                email_detector = EmailDetector(ml_detector=ml_detector)
                
                text_result = email_detector.analyze(extracted_text)
                
                # Add text analysis results
                if text_result['score'] > 40:
                    score += 30
                    threats.append("🚨 PHISHING TEXT: Suspicious content in image")
                    threats.extend(text_result['threats'][:2])  # Add top 2 text threats
                
                details.append(f"✓ Text analysis: {text_result['risk_level']}")
            else:
                details.append("ℹ️ No text extracted from image")
        
        except Exception as ocr_error:
            details.append(f"⚠️ OCR failed: {str(ocr_error)}")
        
        # Determine risk level
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
        
        # Calculate analysis time
        analysis_time = (time.time() - start_time) * 1000
        
        return AnalysisResponse(
            risk_score=min(score, 100),
            risk_level=risk_level,
            recommendation=recommendation,
            threats=threats,
            details=details,
            ml_confidence=None,
            analysis_time_ms=round(analysis_time, 2),
            analysis_type='image'
        )
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Image analysis failed: {str(e)}")

@router.get("/stats", summary="Get detection statistics")
async def get_stats():
    """Get system statistics and capabilities"""
    return {
        "system": "Real-Time Fraud Detection System",
        "version": "1.0.0",
        "detection_layers": 12,
        "supported_formats": ["url", "email", "phone", "image"],
        "ml_model": "Random Forest (200 trees)",
        "accuracy_target": "90%+",
        "false_positive_target": "<5%",
        "response_time_target": "<500ms",
        "features": {
            "typosquatting_detection": "Levenshtein distance (95% accuracy)",
            "ml_classification": "TF-IDF + Random Forest",
            "ssl_validation": "Real-time certificate checks",
            "dns_verification": "A record validation",
            "ocr": "Tesseract text extraction",
            "phone_validation": "phonenumbers library",
            "whitelist": "30+ verified domains"
        }
    }
