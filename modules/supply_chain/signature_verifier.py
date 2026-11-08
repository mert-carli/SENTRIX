import subprocess
import os
from typing import Dict, Any

class AuthenticodeVerifier:
    """Verifies Microsoft Authenticode digital signatures on executables and DLLs."""

    @staticmethod
    def verify_file_signature(file_path: str) -> Dict[str, Any]:
        if not os.path.isfile(file_path):
            return {"valid": False, "status": "FILE_NOT_FOUND", "signer": None}

        ps = f'(Get-AuthenticodeSignature -FilePath "{file_path}").Status.ToString()'
        signer_ps = f'(Get-AuthenticodeSignature -FilePath "{file_path}").SignerCertificate.Subject'

        try:
            res_status = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True, timeout=8, check=False)
            res_signer = subprocess.run(["powershell", "-NoProfile", "-Command", signer_ps], capture_output=True, text=True, timeout=8, check=False)

            status_str = res_status.stdout.strip()
            signer_str = res_signer.stdout.strip()

            is_valid = status_str == "Valid"
            return {
                "file_path": file_path,
                "is_signed": status_str != "NotSigned",
                "is_valid": is_valid,
                "status": status_str,
                "signer": signer_str if signer_str else "Unknown"
            }
        except Exception as e:
            return {"valid": False, "status": "ERROR", "error": str(e)}
