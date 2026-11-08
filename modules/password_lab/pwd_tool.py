import hashlib
import math
import re
from typing import Dict, Any, List

HASH_REGEX_PATTERNS = [
    (re.compile(r'^[a-fA-F0-9]{32}$'), ["MD5", "NTLM"]),
    (re.compile(r'^[a-fA-F0-9]{40}$'), ["SHA-1"]),
    (re.compile(r'^[a-fA-F0-9]{64}$'), ["SHA-256"]),
    (re.compile(r'^[a-fA-F0-9]{128}$'), ["SHA-512"]),
    (re.compile(r'^\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}$'), ["bcrypt"]),
    (re.compile(r'^\$argon2(i|d|id)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$'), ["Argon2"])
]

class PasswordSecurityLab:
    def __init__(self):
        pass

    def calculate_entropy(self, text: str) -> float:
        """Calculates Shannon Entropy in bits for a given string."""
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        entropy = -sum([p * math.log2(p) for p in prob])
        return round(entropy * len(text), 2)

    def evaluate_strength(self, pwd: str) -> Dict[str, Any]:
        """Evaluates password complexity, charset, entropy, and crack resistance."""
        length = len(pwd)
        has_lower = bool(re.search(r'[a-z]', pwd))
        has_upper = bool(re.search(r'[A-Z]', pwd))
        has_digit = bool(re.search(r'\d', pwd))
        has_special = bool(re.search(r'[^a-zA-Z0-9]', pwd))

        charset_pool = 0
        if has_lower: charset_pool += 26
        if has_upper: charset_pool += 26
        if has_digit: charset_pool += 10
        if has_special: charset_pool += 33

        entropy_bits = round(length * math.log2(charset_pool), 2) if charset_pool > 0 else 0.0

        score = 0
        if length >= 8: score += 1
        if length >= 12: score += 1
        if length >= 16: score += 1
        if has_lower and has_upper: score += 1
        if has_digit: score += 1
        if has_special: score += 1

        rating = "VERY WEAK"
        if score >= 5: rating = "STRONG"
        elif score >= 4: rating = "MODERATE"
        elif score >= 2: rating = "WEAK"

        return {
            "length": length,
            "charset_pool": charset_pool,
            "entropy_bits": entropy_bits,
            "rating": rating,
            "has_lower": has_lower,
            "has_upper": has_upper,
            "has_digit": has_digit,
            "has_special": has_special
        }

    def identify_hash(self, hash_str: str) -> List[str]:
        """Identifies possible cryptographic hash algorithms for a given string."""
        hash_str = hash_str.strip()
        candidates = []
        for regex, names in HASH_REGEX_PATTERNS:
            if regex.match(hash_str):
                candidates.extend(names)
        return candidates or ["Unknown/Unrecognized Hash Format"]

    def generate_hashes(self, text: str) -> Dict[str, str]:
        """Generates standard cryptographic hashes for security research."""
        encoded = text.encode('utf-8')
        
        # NTLM calculation (MD4 of UTF-16LE)
        try:
            ntlm_hash = hashlib.new('md4', text.encode('utf-16le')).hexdigest()
        except ValueError:
            ntlm_hash = "Unsupported in current OpenSSL environment"

        return {
            "MD5": hashlib.md5(encoded).hexdigest(),
            "SHA-1": hashlib.sha1(encoded).hexdigest(),
            "SHA-256": hashlib.sha256(encoded).hexdigest(),
            "SHA-512": hashlib.sha512(encoded).hexdigest(),
            "NTLM": ntlm_hash
        }

password_lab = PasswordSecurityLab()
