import os
import math
import re
from typing import Dict, Any, List

class FirmwareAnalyzer:
    """Performs static security analysis on firmware binary images."""

    MAGIC_SIGNATURES = [
        (b"hsqs", "SquashFS Little-Endian Filesystem"),
        (b"sqsh", "SquashFS Big-Endian Filesystem"),
        (b"\x27\x05\x19\x56", "U-Boot Legacy uImage Header"),
        (b"UBI#", "UBIFS Raw NAND Image"),
        (b"\x1f\x8b\x08", "GZIP Compressed Ramdisk / Kernel"),
        (b"PK\x03\x04", "ZIP Compressed Firmware Archive")
    ]

    @classmethod
    def analyze_binary(cls, file_path: str) -> Dict[str, Any]:
        if not os.path.isfile(file_path):
            return {"success": False, "error": "Firmware image file not found."}

        file_size = os.path.getsize(file_path)
        with open(file_path, "rb") as f:
            header = f.read(4096)
            f.seek(0)
            full_data = f.read(min(file_size, 5242880))  # Max 5MB for fast entropy sample

        # 1. Identify Embedded Signatures
        detected_types = []
        for sig, label in cls.MAGIC_SIGNATURES:
            if sig in header:
                detected_types.append(label)

        # 2. Shannon Entropy Calculation
        entropy = cls._calculate_entropy(full_data)

        # 3. Scan for Hardcoded Private Keys / Certs
        has_private_key = b"-----BEGIN PRIVATE KEY-----" in full_data or b"-----BEGIN RSA PRIVATE KEY-----" in full_data
        has_certificate = b"-----BEGIN CERTIFICATE-----" in full_data

        findings = []
        if entropy > 7.5:
            findings.append({
                "severity": "MEDIUM",
                "title": f"High Entropy Detected ({entropy:.2f} / 8.0)",
                "description": "Indicates encrypted payload or compressed filesystem."
            })
        if has_private_key:
            findings.append({
                "severity": "CRITICAL",
                "title": "Hardcoded Private Key Identified",
                "description": "Cryptographic private key found embedded in raw firmware image."
            })

        return {
            "success": True,
            "filename": os.path.basename(file_path),
            "file_size": file_size,
            "detected_filesystems": detected_types if detected_types else ["Raw Binary / Unknown Header"],
            "entropy": round(entropy, 2),
            "embedded_secrets": {
                "has_private_key": has_private_key,
                "has_certificate": has_certificate
            },
            "findings": findings
        }

    @staticmethod
    def _calculate_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        occ = [0] * 256
        for b in data:
            occ[b] += 1
        total = len(data)
        entropy = 0.0
        for count in occ:
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)
        return entropy
