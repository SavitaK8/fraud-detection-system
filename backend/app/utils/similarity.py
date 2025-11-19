

def levenshtein_distance(str1: str, str2: str) -> int:
    """
    Calculate Levenshtein (edit) distance between two strings
    Returns: minimum number of edits needed to transform str1 into str2
    """
    m, n = len(str1), len(str2)
    
    # Create matrix
    matrix = [[0] * (n + 1) for _ in range(m + 1)]
    
    # Initialize first column and row
    for i in range(m + 1):
        matrix[i][0] = i
    for j in range(n + 1):
        matrix[0][j] = j
    
    # Fill matrix
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if str1[i - 1] == str2[j - 1]:
                cost = 0
            else:
                cost = 1
            
            matrix[i][j] = min(
                matrix[i - 1][j] + 1,      # Deletion
                matrix[i][j - 1] + 1,      # Insertion
                matrix[i - 1][j - 1] + cost  # Substitution
            )
    
    return matrix[m][n]

def calculate_similarity(str1: str, str2: str) -> float:
    """
    Calculate similarity percentage between two strings
    Returns: similarity score 0-100 (100 = identical)
    """
    str1 = str1.lower().strip()
    str2 = str2.lower().strip()
    
    if str1 == str2:
        return 100.0
    
    if not str1 or not str2:
        return 0.0
    
    distance = levenshtein_distance(str1, str2)
    max_length = max(len(str1), len(str2))
    
    similarity = ((max_length - distance) / max_length) * 100
    
    return round(similarity, 2)

def is_typosquatting(domain: str, legitimate_domain: str, threshold: float = 75.0) -> bool:
    """
    Check if domain is typosquatting a legitimate domain
    Args:
        domain: Domain to check
        legitimate_domain: Known legitimate domain
        threshold: Similarity threshold (default 75%)
    Returns: True if similarity is above threshold but not 100%
    """
    similarity = calculate_similarity(domain, legitimate_domain)
    return threshold < similarity < 100.0

def detect_character_substitution(text: str) -> str:
    """
    Detect and normalize common character substitutions
    0->o, 1->l, 3->e, 5->s, 8->b, 9->g
    """
    substitutions = {
        '0': 'o',
        '1': 'l',
        '3': 'e',
        '5': 's',
        '8': 'b',
        '9': 'g'
    }
    
    normalized = text.lower()
    for num, letter in substitutions.items():
        normalized = normalized.replace(num, letter)
    
    return normalized

# Test functions
if __name__ == "__main__":
    # Test cases
    test_pairs = [
        ("paypal.com", "paypa1.com"),    # Character substitution
        ("google.com", "gooogle.com"),   # Extra character
        ("amazon.com", "amaz0n.com"),    # Character substitution
        ("facebook.com", "faceb00k.com"), # Multiple substitutions
        ("microsoft.com", "micr0soft.com"),
        ("apple.com", "apple.com"),      # Identical
        ("netflix.com", "netf1ix.com"),  # Substitution
    ]
    
    print("🧪 Testing Levenshtein Distance & Typosquatting Detection\n")
    
    for legit, suspicious in test_pairs:
        similarity = calculate_similarity(legit, suspicious)
        is_typo = is_typosquatting(suspicious, legit)
        
        status = "🚨 TYPOSQUATTING" if is_typo else "✅ SAFE" if similarity == 100 else "⚠️ SUSPICIOUS"
        print(f"{status} | {suspicious:20} vs {legit:20} | Similarity: {similarity:5.1f}%")
