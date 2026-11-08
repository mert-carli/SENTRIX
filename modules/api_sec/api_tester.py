import json
import base64
import time
from typing import Dict, Any, List

class APISecurityTester:
    def __init__(self):
        pass

    def decode_jwt(self, token_str: str) -> Dict[str, Any]:
        """Parses and audits JSON Web Tokens (JWT) for security misconfigurations."""
        parts = token_str.strip().split(".")
        if len(parts) != 3:
            return {"error": "Invalid JWT format. Must contain 3 dot-separated segments."}

        def b64_decode(s: str) -> Dict[str, Any]:
            # Add padding if required
            rem = len(s) % 4
            if rem > 0:
                s += "=" * (4 - rem)
            raw = base64.urlsafe_b64decode(s)
            return json.loads(raw.decode('utf-8'))

        try:
            header = b64_decode(parts[0])
            payload = b64_decode(parts[1])
        except Exception as e:
            return {"error": f"Failed to base64url decode token: {e}"}

        findings = []
        alg = header.get("alg", "").upper()
        if alg in ["NONE", "NONE"]:
            findings.append(("CRITICAL", "JWT Algorithm 'none' Allowed", "Token uses insecure 'none' algorithm allowing arbitrary signature bypass."))
        elif alg.startswith("HS") and "RS" in header.get("typ", ""):
            findings.append(("HIGH", "Potential Algorithm Confusion", "HMAC key confusion risk."))

        # Expiration Check
        exp = payload.get("exp")
        is_expired = False
        if exp:
            now = time.time()
            if now > exp:
                is_expired = True
                findings.append(("INFO", "Token Expired", f"Expired at {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(exp))} UTC."))
        else:
            findings.append(("MEDIUM", "Missing Expiration (exp claim)", "JWT has no expiration timestamp. Tokens remain valid indefinitely if leaked."))

        return {
            "header": header,
            "payload": payload,
            "signature_present": bool(parts[2]),
            "algorithm": alg,
            "is_expired": is_expired,
            "findings": findings
        }

api_security_tester = APISecurityTester()
