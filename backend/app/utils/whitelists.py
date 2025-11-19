
LEGITIMATE_DOMAINS = {
    # Major Tech Companies
    'google.com', 'gmail.com', 'youtube.com',
    'facebook.com', 'fb.com', 'instagram.com', 'whatsapp.com',
    'microsoft.com', 'outlook.com', 'office.com', 'live.com',
    'apple.com', 'icloud.com',
    'amazon.com', 'aws.amazon.com',
    'twitter.com', 'x.com',
    'linkedin.com',
    'netflix.com',
    'zoom.us',
    'dropbox.com',
    'github.com',
    'stackoverflow.com',
    'reddit.com',
    'wikipedia.org',
    
    # Financial Services
    'paypal.com',
    'stripe.com',
    'visa.com',
    'mastercard.com',
    
    # E-commerce
    'ebay.com',
    'shopify.com',
    'walmart.com',
    'target.com',
    
    # Indian Companies
    'flipkart.com',
    'paytm.com',
    'phonepe.com',
    'bharatpe.com',
    
    # Government & Education
    'gov.in',
    'nic.in',
    'aktu.ac.in',
    
    # Other Major Sites
    'adobe.com',
    'salesforce.com',
    'oracle.com',
    'ibm.com',
    'cisco.com',
}

# Financial institution domains (extra scrutiny for similar domains)
FINANCIAL_DOMAINS = {
    'paypal.com',
    'stripe.com',
    'square.com',
    'bankofamerica.com',
    'chase.com',
    'wellsfargo.com',
    'citibank.com',
    'americanexpress.com',
    'discover.com',
    'paytm.com',
    'phonepe.com',
    'googlepay.com',
}

# Government domains (highest trust level)
GOVERNMENT_DOMAINS = {
    'gov.in',
    'gov.uk',
    'gov.au',
    'gov.ca',
    'usa.gov',
    'nic.in',
}

# Educational domains (trusted for academic content)
EDUCATIONAL_DOMAINS = {
    'aktu.ac.in',
    'iit.ac.in',
    'mit.edu',
    'stanford.edu',
    'harvard.edu',
    'ox.ac.uk',
    'cam.ac.uk',
}

def is_whitelisted(domain: str) -> bool:
    """Check if domain is in whitelist"""
    domain = domain.lower().strip()
    
    # Remove www. prefix
    if domain.startswith('www.'):
        domain = domain[4:]
    
    # Check exact match
    if domain in LEGITIMATE_DOMAINS:
        return True
    
    # Check if domain ends with any whitelisted domain (for subdomains)
    for legit_domain in LEGITIMATE_DOMAINS:
        if domain.endswith('.' + legit_domain):
            return True
    
    return False

def get_domain_category(domain: str) -> str:
    """Get category of whitelisted domain"""
    domain = domain.lower().strip()
    
    if domain.startswith('www.'):
        domain = domain[4:]
    
    if domain in GOVERNMENT_DOMAINS or any(domain.endswith('.' + d) for d in GOVERNMENT_DOMAINS):
        return 'government'
    elif domain in EDUCATIONAL_DOMAINS or any(domain.endswith('.' + d) for d in EDUCATIONAL_DOMAINS):
        return 'educational'
    elif domain in FINANCIAL_DOMAINS or any(domain.endswith('.' + d) for d in FINANCIAL_DOMAINS):
        return 'financial'
    elif domain in LEGITIMATE_DOMAINS:
        return 'trusted'
    else:
        return 'unknown'

def is_high_value_target(domain: str) -> bool:
    """Check if domain is commonly targeted for phishing"""
    domain = domain.lower().strip()
    
    # Financial and government domains are high-value targets
    return (domain in FINANCIAL_DOMAINS or 
            domain in GOVERNMENT_DOMAINS or
            any(domain.endswith('.' + d) for d in FINANCIAL_DOMAINS | GOVERNMENT_DOMAINS))
