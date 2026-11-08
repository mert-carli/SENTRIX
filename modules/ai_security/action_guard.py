"""
SENTRIX v5.0 — Action Guard & Human-in-the-Loop Execution Engine
Guarantees that no disruptive, destructive, or containment action is executed
without explicit operator approval. Tracks audit trail and rollback options.
"""

import os
import uuid
import subprocess
import shutil
from datetime import datetime
from typing import Dict, Any, List, Optional
from core.logger import log
from core.database import db

class ActionType:
    KILL_PROCESS = "KILL_PROCESS"
    BLOCK_FIREWALL_IP = "BLOCK_FIREWALL_IP"
    QUARANTINE_FILE = "QUARANTINE_FILE"
    STOP_SERVICE = "STOP_SERVICE"
    ISOLATE_HOST = "ISOLATE_HOST"

class ActionRisk:
    LOW = "DÜŞÜK"
    MEDIUM = "ORTA"
    HIGH = "YÜKSEK"
    CRITICAL = "KRİTİK"

class ActionStatus:
    PENDING = "BEKLEMEDE"
    APPROVED = "ONAYLANDI"
    REJECTED = "REDDEDİLDİ"
    EXECUTED = "UYGULANDI"
    FAILED = "BAŞARISIZ"
    ROLLED_BACK = "GERİ ALINDI"

class ActionGuard:
    """Manages pending security proposals, operator approval gates, and rollback states."""

    def __init__(self):
        self._proposals: Dict[str, Dict[str, Any]] = {}
        self.quarantine_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "data", "quarantine"))
        os.makedirs(self.quarantine_dir, exist_ok=True)

    def create_proposal(
        self,
        action_type: str,
        target: str,
        description: str,
        risk_level: str = ActionRisk.HIGH,
        params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Creates an unapproved action proposal requiring operator consent."""
        action_id = f"act_{uuid.uuid4().hex[:8]}"
        params = params or {}
        
        command = ""
        rollback_command = ""

        if action_type == ActionType.KILL_PROCESS:
            pid = str(target)
            command = f"taskkill /F /PID {pid}"
            rollback_command = "İşlem sonlandırıldı (otomatik yeniden başlatılamaz)"
        elif action_type == ActionType.BLOCK_FIREWALL_IP:
            ip = str(target)
            rule_name = f"SENTRIX_Block_{ip}"
            command = f"netsh advfirewall firewall add rule name=\"{rule_name}\" dir=in action=block remoteip={ip}"
            rollback_command = f"netsh advfirewall firewall delete rule name=\"{rule_name}\""
            params["rule_name"] = rule_name
        elif action_type == ActionType.STOP_SERVICE:
            svc = str(target)
            command = f"sc stop \"{svc}\""
            rollback_command = f"sc start \"{svc}\""
        elif action_type == ActionType.QUARANTINE_FILE:
            file_path = str(target)
            quarantine_target = os.path.join(self.quarantine_dir, f"{os.path.basename(file_path)}.{action_id}.quarantine")
            command = f"MOVE \"{file_path}\" \"{quarantine_target}\""
            rollback_command = f"MOVE \"{quarantine_target}\" \"{file_path}\""
            params["quarantine_path"] = quarantine_target
        elif action_type == ActionType.ISOLATE_HOST:
            ip = str(target)
            command = f"route add {ip} MASK 255.255.255.255 127.0.0.1"
            rollback_command = f"route delete {ip}"
        else:
            command = f"# Özel komut: {target}"
            rollback_command = "# Manuel geri alma gereklidir"

        proposal = {
            "action_id": action_id,
            "action_type": action_type,
            "target": target,
            "description": description,
            "risk_level": risk_level,
            "command": command,
            "rollback_command": rollback_command,
            "params": params,
            "status": ActionStatus.PENDING,
            "operator": None,
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat(),
            "output": "",
            "error": ""
        }

        self._proposals[action_id] = proposal
        log.info(f"ActionGuard: Yeni onay bekleyen işlem oluşturuldu [{action_id}]: {description} ({risk_level})")
        return proposal

    def list_proposals(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """Returns filtered proposals sorted by creation date."""
        items = list(self._proposals.values())
        if status:
            items = [p for p in items if p["status"] == status]
        return sorted(items, key=lambda x: x["created_at"], reverse=True)

    def get_proposal(self, action_id: str) -> Optional[Dict[str, Any]]:
        return self._proposals.get(action_id)

    def approve_and_execute(self, action_id: str, operator: str = "Operatör") -> Dict[str, Any]:
        """Explicitly approves and executes an action with audit logging."""
        proposal = self._proposals.get(action_id)
        if not proposal:
            return {"success": False, "message": "İşlem bulunamadı."}

        if proposal["status"] != ActionStatus.PENDING:
            return {"success": False, "message": f"Bu işlem zaten '{proposal['status']}' durumunda."}

        proposal["operator"] = operator
        proposal["updated_at"] = datetime.now().isoformat()
        
        success, out, err = self._execute_action(proposal)
        if success:
            proposal["status"] = ActionStatus.EXECUTED
            proposal["output"] = out
            msg = f"İşlem '{action_id}' ({proposal['description']}) başarıyla uygulandı."
            log.info(f"ActionGuard: {msg}")
        else:
            proposal["status"] = ActionStatus.FAILED
            proposal["error"] = err
            msg = f"İşlem '{action_id}' uygulanırken hata oluştu: {err}"
            log.warning(f"ActionGuard: {msg}")

        # Audit log in database
        try:
            db.log_security_event(
                event_type="ACTION_GUARD_EXECUTION",
                description=f"[{proposal['status']}] {proposal['description']} (Operatör: {operator})",
                severity="HIGH" if not success else "MEDIUM"
            )
        except Exception as e:
            log.debug(f"ActionGuard: Audit log yazılamadı: {e}")

        return {
            "success": success,
            "message": msg,
            "output": out,
            "error": err,
            "proposal": proposal
        }

    def reject(self, action_id: str, reason: str = "", operator: str = "Operatör") -> Dict[str, Any]:
        """Operator explicitly rejects the action."""
        proposal = self._proposals.get(action_id)
        if not proposal:
            return {"success": False, "message": "İşlem bulunamadı."}

        proposal["status"] = ActionStatus.REJECTED
        proposal["operator"] = operator
        proposal["output"] = f"Reddedildi: {reason}"
        proposal["updated_at"] = datetime.now().isoformat()
        log.info(f"ActionGuard: İşlem [{action_id}] operatör tarafından reddedildi. Neden: {reason}")
        return {"success": True, "message": "İşlem iptal edildi.", "proposal": proposal}

    def rollback(self, action_id: str) -> Dict[str, Any]:
        """Reverts an executed action if a rollback command exists."""
        proposal = self._proposals.get(action_id)
        if not proposal:
            return {"success": False, "message": "İşlem bulunamadı."}

        if proposal["status"] != ActionStatus.EXECUTED:
            return {"success": False, "message": "Yalnızca uygulanmış işlemler geri alınabilir."}

        action_type = proposal["action_type"]
        success = False
        out = ""
        err = ""

        try:
            if action_type == ActionType.QUARANTINE_FILE:
                target_orig = proposal["target"]
                quarantine_target = proposal["params"].get("quarantine_path")
                if quarantine_target and os.path.exists(quarantine_target):
                    shutil.move(quarantine_target, target_orig)
                    success = True
                    out = f"Dosya '{target_orig}' konumuna geri yüklendi."
                else:
                    err = "Karantinadaki dosya bulunamadı."
            elif action_type == ActionType.BLOCK_FIREWALL_IP:
                rule_name = proposal["params"].get("rule_name")
                if rule_name:
                    cmd = f"netsh advfirewall firewall delete rule name=\"{rule_name}\""
                    res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
                    success = (res.returncode == 0)
                    out = res.stdout
                    err = res.stderr
            elif action_type == ActionType.STOP_SERVICE:
                svc = proposal["target"]
                cmd = f"sc start \"{svc}\""
                res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
                success = (res.returncode == 0)
                out = res.stdout
                err = res.stderr
            elif action_type == ActionType.ISOLATE_HOST:
                ip = proposal["target"]
                cmd = f"route delete {ip}"
                res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
                success = (res.returncode == 0)
                out = res.stdout
                err = res.stderr
            else:
                err = "Bu işlem türü için otomatik geri alma desteklenmiyor."
        except Exception as e:
            err = str(e)

        if success:
            proposal["status"] = ActionStatus.ROLLED_BACK
            proposal["updated_at"] = datetime.now().isoformat()
            log.info(f"ActionGuard: İşlem [{action_id}] geri alındı.")
            return {"success": True, "message": "İşlem başarıyla geri alındı.", "output": out}
        else:
            log.error(f"ActionGuard: Geri alma başarısız [{action_id}]: {err}")
            return {"success": False, "message": f"Geri alma başarısız: {err}"}

    def _execute_action(self, proposal: Dict[str, Any]) -> tuple[bool, str, str]:
        """Internal execution helper for confirmed proposals."""
        action_type = proposal["action_type"]
        target = proposal["target"]

        try:
            if action_type == ActionType.KILL_PROCESS:
                try:
                    pid = int(target)
                except ValueError:
                    return False, "", "Geçersiz PID değeri."
                cmd = f"taskkill /F /PID {pid}"
                res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
                return (res.returncode == 0), res.stdout.strip(), res.stderr.strip()

            elif action_type == ActionType.BLOCK_FIREWALL_IP:
                rule_name = proposal["params"].get("rule_name", f"SENTRIX_Block_{target}")
                cmd = f"netsh advfirewall firewall add rule name=\"{rule_name}\" dir=in action=block remoteip={target}"
                res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
                return (res.returncode == 0), res.stdout.strip(), res.stderr.strip()

            elif action_type == ActionType.QUARANTINE_FILE:
                src = str(target)
                dst = proposal["params"].get("quarantine_path")
                if not os.path.exists(src):
                    return False, "", f"Hedef dosya bulunamadı: {src}"
                shutil.move(src, dst)
                return True, f"Dosya karantinaya taşındı: {dst}", ""

            elif action_type == ActionType.STOP_SERVICE:
                cmd = f"sc stop \"{target}\""
                res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
                return (res.returncode == 0), res.stdout.strip(), res.stderr.strip()

            elif action_type == ActionType.ISOLATE_HOST:
                cmd = f"route add {target} MASK 255.255.255.255 127.0.0.1"
                res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
                return (res.returncode == 0), res.stdout.strip(), res.stderr.strip()

            else:
                return False, "", f"Desteklenmeyen eylem türü: {action_type}"
        except Exception as e:
            return False, "", str(e)

action_guard = ActionGuard()
