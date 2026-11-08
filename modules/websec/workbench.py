import urllib.request
import urllib.parse
import ssl
import json
import difflib
import time
from typing import Dict, List, Any, Optional
from core.scope import scope_manager
from core.logger import audit_logger
from core.database import db

class WebSecurityWorkbench:
    def __init__(self):
        pass

    def send_custom_request(self, method: str, url: str, headers: Dict[str, str], body: Optional[str] = None, project_id: int = 1) -> Dict[str, Any]:
        """
        Executes an arbitrary HTTP request within authorized project scope.
        Returns full raw response, headers, latency, and status.
        """
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname or url
        scope_manager.enforce_scope(hostname, project_id)
        audit_logger.log_action("HTTP_WORKBENCH_REQUEST", f"Method={method}, URL={url}")

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        data_bytes = body.encode('utf-8') if body else None
        req = urllib.request.Request(url, data=data_bytes, headers=headers, method=method.upper())

        t0 = time.time()
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=8) as resp:
                elapsed_ms = (time.time() - t0) * 1000
                resp_body = resp.read().decode('latin1', errors='ignore')
                resp_headers = dict(resp.getheaders())
                return {
                    "status_code": resp.status,
                    "reason": resp.reason,
                    "elapsed_ms": round(elapsed_ms, 2),
                    "headers": resp_headers,
                    "body": resp_body[:10000],
                    "body_len": len(resp_body)
                }
        except urllib.error.HTTPError as e:
            elapsed_ms = (time.time() - t0) * 1000
            err_body = e.read().decode('latin1', errors='ignore')
            return {
                "status_code": e.code,
                "reason": e.reason,
                "elapsed_ms": round(elapsed_ms, 2),
                "headers": dict(e.headers),
                "body": err_body[:10000],
                "body_len": len(err_body)
            }
        except Exception as e:
            return {"error": str(e), "elapsed_ms": 0.0}

    def compute_response_diff(self, response_a: str, response_b: str) -> str:
        """Computes a unified text diff between two HTTP responses."""
        lines_a = response_a.splitlines(keepends=True)
        lines_b = response_b.splitlines(keepends=True)
        diff = difflib.unified_diff(lines_a, lines_b, fromfile="Response A (Baseline)", tofile="Response B (Test)")
        return "".join(diff)

    def export_to_har(self, request_data: Dict[str, Any], response_data: Dict[str, Any]) -> str:
        """Exports a single HTTP transaction into standard HTTP Archive (HAR) JSON format."""
        har = {
            "log": {
                "version": "1.2",
                "creator": {"name": "SENTRIX Cyber Operations Platform", "version": "3.0"},
                "entries": [
                    {
                        "startedDateTime": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "time": response_data.get("elapsed_ms", 0),
                        "request": {
                            "method": request_data.get("method", "GET"),
                            "url": request_data.get("url", ""),
                            "httpVersion": "HTTP/1.1",
                            "headers": [{"name": k, "value": v} for k, v in request_data.get("headers", {}).items()],
                            "bodySize": len(request_data.get("body", "") or "")
                        },
                        "response": {
                            "status": response_data.get("status_code", 0),
                            "statusText": response_data.get("reason", ""),
                            "httpVersion": "HTTP/1.1",
                            "headers": [{"name": k, "value": v} for k, v in response_data.get("headers", {}).items()],
                            "content": {
                                "size": response_data.get("body_len", 0),
                                "mimeType": response_data.get("headers", {}).get("Content-Type", "text/plain"),
                                "text": response_data.get("body", "")
                            }
                        }
                    }
                ]
            }
        }
        return json.dumps(har, indent=2)

web_workbench = WebSecurityWorkbench()
