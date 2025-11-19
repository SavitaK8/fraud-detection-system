

import re
import validators as external_validators
from typing import Optional

class InputValidator:
    """
    Validates and sanitizes user inputs
    """
    
    @staticmethod
    def sanitize_url(url: str) -> str:
        """Sanitize and normalize URL"""
        url = url.strip()
        
        # Add protocol if missing
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        return url
    
    @staticmethod
    def validate_url(url: str) -> bool:
        """Validate URL format"""
        try:
            return external_validators.url(url)
        except:
            return False
    
    @staticmethod
    def sanitize_text(text: str, max_length: int = 10000) -> str:
        """Sanitize text input"""
        # Remove null bytes
        text = text.replace('\x00', '')
        
        # Limit length
        if len(text) > max_length:
            text = text[:max_length]
        
        return text.strip()
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """Validate email format"""
        try:
            return external_validators.email(email)
        except:
            return False
    
    @staticmethod
    def sanitize_phone(phone: str) -> str:
        """Sanitize phone number"""
        # Remove common formatting characters
        phone = re.sub(r'[\s\-\(\)\.]+', '', phone)
        return phone.strip()
    
    @staticmethod
    def is_safe_filename(filename: str) -> bool:
        """Check if filename is safe"""
        # No path traversal
        if '..' in filename or '/' in filename or '\\' in filename:
            return False
        
        # Only alphanumeric, dash, underscore, and dot
        if not re.match(r'^[\w\-\.]+$', filename):
            return False
        
        return True
    
    @staticmethod
    def detect_sql_injection(text: str) -> bool:
        """Detect potential SQL injection attempts"""
        sql_keywords = [
            'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP',
            'UNION', 'EXEC', 'EXECUTE', '--', ';--', '/*', '*/'
        ]
        
        text_upper = text.upper()
        return any(keyword in text_upper for keyword in sql_keywords)
    
    @staticmethod
    def detect_xss(text: str) -> bool:
        """Detect potential XSS attempts"""
        xss_patterns = [
            '<script', 'javascript:', 'onerror=', 'onload=',
            '<iframe', '<object', '<embed'
        ]
        
        text_lower = text.lower()
        return any(pattern in text_lower for pattern in xss_patterns)
