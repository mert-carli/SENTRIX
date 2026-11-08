import os
import hashlib
from typing import Dict, Any, Optional
from datetime import datetime
from core.database import db

class MemoryManager:
    """Manages memory images (raw, dmp, vmem), integrity verification, and metadata records."""

    def register_memory_image(self, file_path: str, case_id: Optional[int] = None, notes: str = "") -> Dict[str, Any]:
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"Memory image not found at: {file_path}")

        file_size = os.path.getsize(file_path)
        sha256 = self.calculate_sha256(file_path)
        filename = os.path.basename(file_path)

        record = {
            "file_path": file_path,
            "filename": filename,
            "file_size": file_size,
            "sha256": sha256,
            "registered_at": datetime.utcnow().isoformat(),
            "notes": notes
        }

        # Store in forensic_evidence table
        try:
            with db.get_connection() as conn:
                conn.execute("""
                INSERT INTO forensic_evidence (case_id, evidence_label, evidence_type, source_path, file_size_bytes, sha256)
                VALUES (?, ?, 'MEMORY_IMAGE', ?, ?, ?)
                """, (case_id, filename, file_path, file_size, sha256))
                conn.commit()
        except Exception:
            pass

        return record

    def calculate_sha256(self, file_path: str, chunk_size: int = 1048576) -> str:
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(chunk_size):
                h.update(chunk)
        return h.hexdigest()
