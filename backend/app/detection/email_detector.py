
import re
from typing import Dict, List
from email_validator import validate_email, EmailNotValidError

class EmailDetector:
    """
    Email/Text Analysis Engine with:
    - ML-based classification
    - Keyword pattern matching
    - Social engineering detection
    - Urgency tactic identification
    - Embedded URL extraction
    """
    
    def __init__(self, ml_detector=None):
        self.ml_detector = ml_detector
        
        self.phishing_keywords = {
            'high_priority': [
                'verify', 'suspended', 'urgent', 'winner', 'congratulations',
                'selected', 'prize', 'reward', 'claim', 'alert'
            ],
            'urgency_tactics': [
                'immediately', 'expire', 'limited time', 'act now',
                'today only', 'final notice', 'last chance', 'within 24 hours',
                'before it\'s too late', 'don\'t miss'
            ],
            'financial': [
                'refund', 'payment', 'credit card', 'bank account',
                'wire transfer', 'paypal', 'billing', 'invoice',
                'transaction', 'money', 'cash', 'deposit'
            ],
            'action_verbs': [
                'click here', 'confirm', 'update', 'reset', 'validate',
                'download', 'open attachment', 'follow link', 'sign in',
                'log in', 'verify account'
            ]
        }
        
        self.social_engineering_patterns = [
            'verify your', 'confirm your', 'update your',
            'suspended', 'locked', 'blocked', 'compromised',
            'unusual activity', 'unauthorized access', 'security alert'
        ]
        
        self.disposable_email_domains = [
            'tempmail.com', 'guerrillamail.com', '10minutemail.com',
            'throwaway.email', 'mailinator.com', 'temp-mail.org'
        ]
    
    def analyze(self, content: str, sender_email: str = None) -> Dict:
        """
        Analyze email/text content for phishing patterns
        """
        score = 0
        threats = []
        details = []
        ml_confidence = None
        
        if not content.strip():
            return self._error_response("Empty content provided")
        
        content_lower = content.lower()
        
        # ML-Based Phishing Detection
        if self.ml_detector:
            try:
                ml_probability = self.ml_detector.predict_phishing(content)
                ml_confidence = float(ml_probability)
                ml_score = int(ml_probability * 60)  # Scale to 0-60 points
                score += ml_score
                
                if ml_probability > 0.7:
                    threats.append(f"🚨 ML DETECTION: High phishing probability ({ml_probability*100:.1f}%)")
                elif ml_probability > 0.4:
                    threats.append(f"⚠️ ML DETECTION: Moderate phishing indicators ({ml_probability*100:.1f}%)")
                else:
                    details.append(f"✓ ML ANALYSIS: Low phishing probability ({ml_probability*100:.1f}%)")
            except Exception as e:
                details.append("ℹ️ ML analysis unavailable, using pattern matching")
        
        # Keyword Analysis
        keyword_results = self._analyze_keywords(content_lower)
        score += keyword_results['score']
        threats.extend(keyword_results['threats'])
        
        # Multiple Urgency Tactics
        urgency_count = sum(1 for tactic in self.phishing_keywords['urgency_tactics']
                          if tactic in content_lower)
        if urgency_count >= 3:
            score += 25
            threats.append(f"🚨 URGENCY MANIPULATION: {urgency_count} pressure tactics detected")
        
        # Financial Requests
        financial_count = sum(1 for term in self.phishing_keywords['financial']
                            if term in content_lower)
        if financial_count >= 2:
            score += 20
            threats.append(f"🚨 FINANCIAL REQUEST: {financial_count} payment-related terms")
        
        # Social Engineering Patterns
        for pattern in self.social_engineering_patterns:
            if pattern in content_lower:
                score += 16
                threats.append(f"⚠️ SOCIAL ENGINEERING: '{pattern}' manipulation tactic")
                if len([t for t in threats if 'SOCIAL ENGINEERING' in t]) >= 3:
                    break
        
        # Excessive Punctuation
        exclamation_count = content.count('!')
        if exclamation_count > 3:
            score += 8
            threats.append(f"⚠️ EXCESSIVE PUNCTUATION: {exclamation_count} exclamation marks")
        
        # ALL CAPS Detection
        if len(content) > 20:
            caps_chars = sum(1 for c in content if c.isupper())
            caps_ratio = caps_chars / len(content)
            if caps_ratio > 0.5:
                score += 12
                threats.append(f"⚠️ ALL CAPS: {caps_ratio*100:.0f}% uppercase text")
        
        # Embedded URL Analysis
        url_results = self._analyze_embedded_urls(content)
        score += url_results['score']
        threats.extend(url_results['threats'])
        details.extend(url_results['details'])
        
        # Sender Email Validation
        if sender_email:
            sender_results = self._validate_sender(sender_email)
            score += sender_results['score']
            threats.extend(sender_results['threats'])
            details.extend(sender_results['details'])
        
        # Suspicious Attachments Keywords
        if any(word in content_lower for word in ['attachment', 'attached', 'open file', 'download']):
            attachment_score = self._check_attachment_keywords(content_lower)
            score += attachment_score['score']
            threats.extend(attachment_score['threats'])
        
        # Generic Greetings (impersonal)
        if any(greeting in content_lower[:100] for greeting in ['dear customer', 'dear user', 'dear member', 'valued customer']):
            score += 10
            threats.append("⚠️ GENERIC GREETING: Impersonal salutation")
        
        # Success indicators
        if score < 20:
            details.append("✓ Content uses normal language patterns")
            details.append("✓ No major social engineering tactics detected")
        
        return self._create_response(score, threats, details, ml_confidence)
    
    def _analyze_keywords(self, content_lower: str) -> Dict:
        """Analyze phishing keywords"""
        score = 0
        threats = []
        keyword_count = 0
        
        for category, keywords in self.phishing_keywords.items():
            for keyword in keywords:
                if keyword in content_lower:
                    keyword_count += 1
                    score += 6
                    if keyword_count <= 5:  # Limit displayed threats
                        threats.append(f"⚠️ PHISHING KEYWORD: Contains '{keyword}'")
        
        return {'score': score, 'threats': threats, 'count': keyword_count}
    
    def _analyze_embedded_urls(self, content: str) -> Dict:
        """Extract and analyze embedded URLs"""
        score = 0
        threats = []
        details = []
        
        # Extract URLs
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        urls = re.findall(url_pattern, content)
        
        if urls:
            details.append(f"ℹ️ Found {len(urls)} embedded URL(s)")
            
            # Check for suspicious URL patterns
            for url in urls[:3]:  # Analyze first 3 URLs
                url_lower = url.lower()
                
                # IP address in URL
                if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
                    score += 25
                    threats.append("🚨 MALICIOUS LINK: IP address in embedded URL")
                
                # Suspicious TLDs
                if any(tld in url_lower for tld in ['.tk', '.ml', '.ga', '.xyz', '.click']):
                    score += 20
                    threats.append("⚠️ SUSPICIOUS LINK: High-risk domain extension")
                
                # URL shortener
                if any(short in url_lower for short in ['bit.ly', 'tinyurl', 'goo.gl', 't.co']):
                    score += 15
                    threats.append("⚠️ URL SHORTENER: Hidden destination in link")
        
        return {'score': score, 'threats': threats, 'details': details}
    
    def _validate_sender(self, sender_email: str) -> Dict:
        """Validate sender email address"""
        score = 0
        threats = []
        details = []
        
        try:
            # Validate email format
            valid = validate_email(sender_email)
            email_domain = valid.domain.lower()
            
            # Check disposable email services
            if any(disposable in email_domain for disposable in self.disposable_email_domains):
                score += 30
                threats.append("🚨 DISPOSABLE EMAIL: Sender using temporary email service")
            else:
                details.append(f"✓ SENDER: Valid email format ({email_domain})")
            
            # Check for typosquatting in sender domain
            legitimate_domains = ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com']
            for legit in legitimate_domains:
                if email_domain != legit and self._is_similar(email_domain, legit, threshold=0.85):
                    score += 35
                    threats.append(f"🚨 SENDER TYPOSQUATTING: Domain mimics '{legit}'")
                    break
            
        except EmailNotValidError:
            score += 25
            threats.append("⚠️ INVALID SENDER: Malformed email address")
        
        return {'score': score, 'threats': threats, 'details': details}
    
    def _check_attachment_keywords(self, content_lower: str) -> Dict:
        """Check for suspicious attachment-related content"""
        score = 0
        threats = []
        
        suspicious_file_types = ['.exe', '.zip', '.rar', '.scr', '.bat', '.vbs', '.js']
        
        for file_type in suspicious_file_types:
            if file_type in content_lower:
                score += 20
                threats.append(f"🚨 SUSPICIOUS ATTACHMENT: Potentially dangerous file type ({file_type})")
                break
        
        return {'score': score, 'threats': threats}
    
    def _is_similar(self, str1: str, str2: str, threshold: float) -> bool:
        """Simple similarity check"""
        from app.utils.similarity import calculate_similarity
        return calculate_similarity(str1, str2) > threshold * 100
    
    def _create_response(self, score: int, threats: List[str],
                        details: List[str], ml_confidence: float) -> Dict:
        """Create standardized response"""
        score = min(score, 100)
        
        if score >= 70:
            risk_level = "HIGH RISK"
            recommendation = "🚨 Do NOT respond or click any links. Delete immediately and report."
        elif score >= 40:
            risk_level = "MEDIUM RISK"
            recommendation = "⚠️ Verify sender through official channels before responding."
        elif score >= 20:
            risk_level = "LOW RISK"
            recommendation = "ℹ️ Exercise caution. Verify sender identity if requesting action."
        else:
            risk_level = "SAFE"
            recommendation = "✅ Content appears legitimate. No major threats detected."
        
        return {
            'score': score,
            'risk_level': risk_level,
            'recommendation': recommendation,
            'threats': threats,
            'details': details,
            'ml_confidence': ml_confidence,
            'analysis_type': 'email'
        }
    
    def _error_response(self, message: str) -> Dict:
        """Create error response"""
        return {
            'score': 25,
            'risk_level': 'UNKNOWN',
            'recommendation': 'Unable to analyze content',
            'threats': [f"⚠️ {message}"],
            'details': [],
            'ml_confidence': None,
            'analysis_type': 'email'
        }
