

from pydantic import BaseModel, Field, validator
from typing import Optional

class URLAnalysisRequest(BaseModel):
    """Request model for URL analysis"""
    url: str = Field(..., description="URL to analyze", min_length=1, max_length=2048)
    
    @validator('url')
    def validate_url(cls, v):
        if not v.strip():
            raise ValueError('URL cannot be empty')
        return v.strip()
    
    class Config:
        schema_extra = {
            "example": {
                "url": "https://paypa1.com/verify"
            }
        }

class EmailAnalysisRequest(BaseModel):
    """Request model for email/text analysis"""
    content: str = Field(..., description="Email or text content", min_length=1)
    sender_email: Optional[str] = Field(None, description="Sender email address")
    
    @validator('content')
    def validate_content(cls, v):
        if not v.strip():
            raise ValueError('Content cannot be empty')
        return v.strip()
    
    class Config:
        schema_extra = {
            "example": {
                "content": "URGENT! Your account has been suspended. Click here to verify immediately.",
                "sender_email": "scam@tempmail.com"
            }
        }

class PhoneAnalysisRequest(BaseModel):
    """Request model for phone number analysis"""
    phone_number: str = Field(..., description="Phone number to analyze")
    
    @validator('phone_number')
    def validate_phone(cls, v):
        if not v.strip():
            raise ValueError('Phone number cannot be empty')
        return v.strip()
    
    class Config:
        schema_extra = {
            "example": {
                "phone_number": "+91 1860 123 4567"
            }
        }

class ProfileAnalysisRequest(BaseModel):
    """Request model for social media profile analysis"""
    profile_url: str = Field(..., description="Social media profile URL")
    username: Optional[str] = Field(None, description="Username")
    bio: Optional[str] = Field(None, description="Profile bio/description")
    
    class Config:
        schema_extra = {
            "example": {
                "profile_url": "https://twitter.com/suspicious_account",
                "username": "tech_support_24x7",
                "bio": "Official Microsoft support. DM for help!"
            }
        }
