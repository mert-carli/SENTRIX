import ipaddress
import socket
import urllib.parse
from typing import List, Tuple, Optional
from datetime import datetime
from core.database import db

class ScopeViolationError(PermissionError):
    pass

class ScopeManager:
    def __init__(self):
        self._private_networks = [
            ipaddress.ip_network("127.0.0.0/8"),
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("169.254.0.0/16"),  # Link-local / Cloud metadata (AWS/Azure 169.254.169.254)
            ipaddress.ip_network("::1/128"),
            ipaddress.ip_network("fc00::/7"),
            ipaddress.ip_network("fe80::/10")
        ]

    def normalize_target(self, target: str) -> str:
        """Strips URI schemes, paths, and port numbers to isolate host/IP."""
        cleaned = target.strip()
        if "://" in cleaned:
            parsed = urllib.parse.urlparse(cleaned)
            cleaned = parsed.hostname or cleaned
        else:
            cleaned = cleaned.split("/")[0].split(":")[0]
        return cleaned.strip().lower()

    def get_allowed_targets(self, project_id: int = 1) -> List[str]:
        """Returns the list of configured authorized targets and CIDR ranges for the project."""
        try:
            with db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT authorized_targets, allowed_ip_ranges, allowed_domains FROM projects WHERE id = ?", (project_id,))
                row = cursor.fetchone()
                if not row:
                    return ["127.0.0.1", "localhost"]
                targets = []
                for field in ["authorized_targets", "allowed_ip_ranges", "allowed_domains"]:
                    val = row[field] or ""
                    targets.extend([t.strip() for t in val.split(",") if t.strip()])
                return targets or ["127.0.0.1", "localhost"]
        except Exception:
            return ["127.0.0.1", "localhost"]

    def is_target_authorized(self, target: str, project_id: int = 1) -> Tuple[bool, str]:
        """
        Validates if target (IPv4, IPv6, or domain) is inside the authorized project scope.
        Enforces DNS rebinding checks and exclusion overrides.
        Returns (is_authorized, reason).
        """
        host = self.normalize_target(target)
        if not host:
            return False, "Target cannot be empty."

        # Always allow loopback for local offline tests
        if host in ["127.0.0.1", "localhost", "::1"]:
            return True, "Loopback target authorized for local operation."

        try:
            with db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT authorized_targets, allowed_ip_ranges, allowed_domains, excluded_targets FROM projects WHERE id = ?", (project_id,))
                row = cursor.fetchone()
        except Exception as e:
            return False, f"Database scope check failed: {e}"

        if not row:
            return False, f"Project ID {project_id} not found."

        authorized_targets = [t.strip().lower() for t in (row["authorized_targets"] or "").split(",") if t.strip()]
        allowed_ip_ranges = [r.strip() for r in (row["allowed_ip_ranges"] or "").split(",") if r.strip()]
        allowed_domains = [d.strip().lower() for d in (row["allowed_domains"] or "").split(",") if d.strip()]
        excluded_targets = [e.strip().lower() for e in (row["excluded_targets"] or "").split(",") if e.strip()]

        # 1. Exclusion override (Fail-Closed)
        if host in excluded_targets:
            return False, f"Target '{host}' is explicitly listed in EXCLUDED targets."

        # 2. Check exact authorized targets list
        if host in authorized_targets:
            return True, f"Target '{host}' is in explicit authorized targets list."

        # 3. Check IP address (IPv4 and IPv6)
        try:
            target_ip = ipaddress.ip_address(host)
            
            # Check exclusions by IP
            for exc in excluded_targets:
                try:
                    if target_ip == ipaddress.ip_address(exc):
                        return False, f"Target IP '{host}' matches excluded IP '{exc}'."
                except ValueError:
                    continue

            for cidr in allowed_ip_ranges:
                try:
                    network = ipaddress.ip_network(cidr, strict=False)
                    if target_ip in network:
                        return True, f"Target IP '{host}' falls within allowed CIDR '{cidr}'."
                except ValueError:
                    continue
            return False, f"Target IP '{host}' is outside authorized CIDR ranges for Project {project_id}."
        except ValueError:
            # Target is a domain name
            pass

        # 4. Domain Whitelist Verification
        domain_match = False
        matched_rule = ""
        for allowed in allowed_domains:
            if host == allowed or host.endswith("." + allowed):
                domain_match = True
                matched_rule = allowed
                break

        if not domain_match:
            return False, f"Domain '{host}' does not match allowed domains for Project {project_id}."

        # 5. DNS Rebinding & Cloud Metadata Protection
        try:
            resolved_ips = socket.getaddrinfo(host, None)
            for res in resolved_ips:
                res_ip_str = res[4][0]
                res_ip = ipaddress.ip_address(res_ip_str)

                # Check if resolved IP is in excluded list
                for exc in excluded_targets:
                    try:
                        if res_ip == ipaddress.ip_address(exc):
                            return False, f"[DNS REBINDING BLOCKED] Domain '{host}' resolved to excluded IP '{res_ip_str}'."
                    except ValueError:
                        continue

                # If domain resolves to link-local cloud metadata (169.254.169.254), block unless explicitly whitelisted
                if res_ip in ipaddress.ip_network("169.254.0.0/16"):
                    if res_ip_str not in authorized_targets:
                        return False, f"[SSRF / METADATA BLOCKED] Domain '{host}' resolves to link-local metadata address {res_ip_str}."

            return True, f"Domain '{host}' matches '{matched_rule}' and passes DNS resolution verification."
        except socket.gaierror as e:
            return False, f"DNS resolution failed for '{host}': {e}"
        except Exception as e:
            return False, f"Scope validation failed: {e}"

    def validate_redirect(self, original_url: str, redirect_url: str, project_id: int = 1) -> Tuple[bool, str]:
        """Ensures HTTP redirects do not escape authorized scope boundary."""
        redir_host = self.normalize_target(redirect_url)
        return self.is_target_authorized(redir_host, project_id)

    def enforce_scope(self, target: str, project_id: int = 1):
        authorized, reason = self.is_target_authorized(target, project_id)
        if not authorized:
            raise ScopeViolationError(f"[SCOPE VIOLATION] {reason}")

scope_manager = ScopeManager()
