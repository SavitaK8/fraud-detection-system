
import re
import ssl
import socket
import dns.resolver
from urllib.parse import urlparse
import tldextract
from typing import Dict, List, Tuple
import validators

# Import utilities
from app.utils.similarity import calculate_similarity
from app.utils.whitelists import LEGITIMATE_DOMAINS

class URLDetector:
    """
    Comprehensive URL analysis with 12 detection layers
    """
    
    def __init__(self):
        self.legitimate_domains = LEGITIMATE_DOMAINS
        self.suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.gq',  # Free TLDs
            '.xyz', '.click', '.link', '.top', '.work',  # Suspicious
            '.bid', '.webcam', '.party', '.trade'
        ]
        self.url_shorteners = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
            'buff.ly', 'adf.ly', 'cutt.ly', 'short.io', 'rebrand.ly'
        ]
        self.suspicious_paths = [
            'verify', 'login', 'account', 'secure', 'update',
            'confirm', 'validate', 'authentication', 'signin',
            'webscr', 'banking', 'suspended'
        ]
    
    def analyze(self, url: str) -> Dict:
        """Main analysis function"""
        score = 0
        threats = []
        details = []
        
        # Validate and parse URL
        if not url.strip():
            return self._error_response("Empty URL provided")
        
        # Add protocol if missing
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        # Validate URL format
        if not validators.url(url):
            score += 25
            threats.append("⚠️ INVALID URL: Malformed URL structure")
            return self._create_response(score, threats, details, 'invalid')
        
        try:
            parsed = urlparse(url)
            extracted = tldextract.extract(url)
            
            domain = extracted.domain + '.' + extracted.suffix
            full_domain = parsed.netloc.lower()
            
            # Layer 1: Whitelist Check
            if self._check_whitelist(domain):
                details.append('✓ VERIFIED: Domain is on trusted whitelist')
                return self._create_response(5, threats, details, domain)
            
            # Layer 2: Typosquatting Detection
            typo_result = self._detect_typosquatting(domain)
            if typo_result:
                score += 65
                threats.append(typo_result)
            
            # Layer 3: Character Substitution
            char_sub = self._detect_character_substitution(domain)
            if char_sub:
                score += 30
                threats.append(char_sub)
            
            # Layer 4: IP Address Detection
            if self._is_ip_address(full_domain):
                score += 45
                threats.append("⚠️ IP ADDRESS: Using IP instead of domain name")
            
            # Layer 5: Suspicious TLD
            tld_check = self._check_suspicious_tld(domain)
            if tld_check:
                score += 35
                threats.append(tld_check)
            
            # Layer 6: HTTPS/SSL Check
            ssl_result = self._check_ssl(parsed, full_domain)
            if ssl_result['is_https']:
                details.append('✓ HTTPS: Encrypted connection detected')
            else:
                score += 20
                threats.append("⚠️ NO ENCRYPTION: Not using HTTPS")
            
            if ssl_result.get('ssl_warning'):
                score += 25
                threats.append(ssl_result['ssl_warning'])
            
            # Layer 7: URL Shortener
            if self._is_url_shortener(full_domain):
                score += 25
                threats.append("⚠️ URL SHORTENER: Destination hidden")
            
            # Layer 8: Excessive Subdomains
            subdomain_count = len(extracted.subdomain.split('.')) if extracted.subdomain else 0
            if subdomain_count > 2:
                score += 15
                threats.append(f"⚠️ MULTIPLE SUBDOMAINS: {subdomain_count + 1} levels detected")
            
            # Layer 9: Suspicious Path Keywords
            path_threats = self._check_suspicious_paths(parsed.path)
            score += len(path_threats) * 8
            threats.extend(path_threats)
            
            # Layer 10: DNS Records Check
            dns_result = self._check_dns(domain)
            if dns_result['has_records']:
                details.append('✓ DNS: Valid domain records found')
            else:
                score += 15
                threats.append("⚠️ DNS: Suspicious or missing DNS records")
            
            # Layer 11: Pattern Anomalies
            pattern_score, pattern_threats = self._check_pattern_anomalies(url, domain)
            score += pattern_score
            threats.extend(pattern_threats)
            
            # Add general detail if no threats
            if len(threats) == 0:
                details.append('ℹ️ No major threats detected in URL structure')
            
            return self._create_response(score, threats, details, domain)
            
        except Exception as e:
            return self._error_response(f"Analysis error: {str(e)}")
    
    def _check_whitelist(self, domain: str) -> bool:
        """Check if domain is in whitelist"""
        return any(legit in domain for legit in self.legitimate_domains)
    
    def _detect_typosquatting(self, domain: str) -> str:
        """Detect domain typosquatting using Levenshtein distance"""
        for legitimate in self.legitimate_domains:
            similarity = calculate_similarity(domain, legitimate)
            if 75 < similarity < 100:
                return f"🚨 TYPOSQUATTING: Domain mimics '{legitimate}' ({similarity:.0f}% similar)"
        return None
    
    def _detect_character_substitution(self, domain: str) -> str:
        """Detect character substitutions like 0->o, 1->l"""
        substitutions = {
            '0': 'o', '1': 'l', '3': 'e', '5': 's',
            '8': 'b', '9': 'g'
        }
        
        # Check if domain contains numbers that could be substitutions
        if any(char in domain for char in substitutions.keys()):
            # Create normalized version
            normalized = domain
            for num, letter in substitutions.items():
                normalized = normalized.replace(num, letter)
            
            # Check similarity with legitimate domains
            for legitimate in self.legitimate_domains:
                similarity = calculate_similarity(normalized, legitimate)
                if similarity > 85:
                    return f"🚨 CHARACTER SUBSTITUTION: Using look-alike characters (mimics '{legitimate}')"
        
        return None
    
    def _is_ip_address(self, domain: str) -> bool:
        """Check if domain is an IP address"""
        domain = domain.split(':')[0]
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        return bool(re.match(ip_pattern, domain))
    
    def _check_suspicious_tld(self, domain: str) -> str:
        """Check for suspicious top-level domains"""
        for tld in self.suspicious_tlds:
            if domain.endswith(tld):
                return f"⚠️ SUSPICIOUS TLD: High-risk domain extension ({tld})"
        return None
    
    def _check_ssl(self, parsed, domain: str) -> Dict:
        """Check HTTPS and SSL certificate"""
        result = {'is_https': parsed.scheme == 'https'}
        
        if result['is_https']:
            try:
                hostname = domain.split(':')[0]
                context = ssl.create_default_context()
                with socket.create_connection((hostname, 443), timeout=3) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        result['ssl_valid'] = True
            except ssl.SSLError:
                result['ssl_warning'] = "⚠️ SSL ERROR: Invalid or self-signed certificate"
            except socket.timeout:
                result['ssl_warning'] = "⚠️ CONNECTION: Unable to verify SSL certificate (timeout)"
            except Exception:
                pass
        
        return result
    
    def _is_url_shortener(self, domain: str) -> bool:
        """Check if domain is a URL shortener"""
        return any(shortener in domain for shortener in self.url_shorteners)
    
    def _check_suspicious_paths(self, path: str) -> List[str]:
        """Check for suspicious keywords in URL path"""
        threats = []
        path_lower = path.lower()
        
        for keyword in self.suspicious_paths:
            if keyword in path_lower:
                threats.append(f"⚠️ SUSPICIOUS PATH: Contains '{keyword}'")
                if len(threats) >= 3:
                    break
        
        return threats
    
    def _check_dns(self, domain: str) -> Dict:
        """Check DNS A records"""
        try:
            answers = dns.resolver.resolve(domain, 'A', lifetime=2)
            return {'has_records': len(answers) > 0, 'records': len(answers)}
        except:
            return {'has_records': False, 'records': 0}
    
    def _check_pattern_anomalies(self, url: str, domain: str) -> Tuple[int, List[str]]:
        """Check for various pattern anomalies"""
        score = 0
        threats = []
        
        # Excessive length
        if len(url) > 100:
            score += 10
            threats.append("⚠️ EXCESSIVE LENGTH: Unusually long URL")
        
        # Too many hyphens
        hyphen_count = domain.count('-')
        if hyphen_count > 3:
            score += 12
            threats.append(f"⚠️ EXCESSIVE HYPHENS: {hyphen_count} hyphens in domain")
        
        # Special characters in domain
        if re.search(r'[^a-zA-Z0-9.-]', domain):
            score += 15
            threats.append("⚠️ SPECIAL CHARACTERS: Unusual characters in domain")
        
        # @ symbol (credential harvesting attempt)
        if '@' in url:
            score += 40
            threats.append("🚨 CREDENTIAL HARVESTING: @ symbol detected")
        
        return score, threats
    
    def _create_response(self, score: int, threats: List[str], 
                        details: List[str], domain: str) -> Dict:
        """Create standardized response"""
        score = min(score, 100)
        
        if score >= 70:
            risk_level = "HIGH RISK"
            recommendation = "🚨 Do NOT interact with this URL. Block and report immediately."
        elif score >= 40:
            risk_level = "MEDIUM RISK"
            recommendation = "⚠️ Verify through official channels before visiting this URL."
        elif score >= 20:
            risk_level = "LOW RISK"
            recommendation = "ℹ️ Exercise caution. Double-check the source."
        else:
            risk_level = "SAFE"
            recommendation = "✅ URL appears legitimate. No major threats detected."
        
        return {
            'score': score,
            'risk_level': risk_level,
            'recommendation': recommendation,
            'threats': threats,
            'details': details,
            'domain': domain,
            'analysis_type': 'url'
        }
    
    def _error_response(self, message: str) -> Dict:
        """Create error response"""
        return {
            'score': 25,
            'risk_level': 'UNKNOWN',
            'recommendation': 'Unable to analyze URL',
            'threats': [f"⚠️ {message}"],
            'details': [],
            'domain': 'unknown',
            'analysis_type': 'url'
        }
