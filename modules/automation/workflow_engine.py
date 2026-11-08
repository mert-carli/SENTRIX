import time
import json
from typing import Dict, List, Any, Callable
from core.database import db
from core.scope import scope_manager, ScopeViolationError
from modules.recon.scanner import port_scanner_engine
from modules.vuln_research.cve_engine import vulnerability_engine
from modules.reporting.report_generator import report_generator

DEFAULT_SECURITY_WORKFLOW = [
    {"step_id": 1, "name": "Validate Authorized Scope", "action": "VALIDATE_SCOPE"},
    {"step_id": 2, "name": "Scan Critical Service Ports", "action": "SCAN_PORTS"},
    {"step_id": 3, "name": "Correlate Vulnerabilities", "action": "CORRELATE_CVES"},
    {"step_id": 4, "name": "Compile Executive Assessment Report", "action": "COMPILE_REPORT"}
]

class SecurityAutomationEngine:
    def __init__(self):
        pass

    def run_automated_audit_workflow(self, target: str, project_id: int = 1, progress_cb: Callable[[str], None] = None) -> Dict[str, Any]:
        """
        Executes a chained, multi-stage automated security assessment workflow:
        Scope Enforcement -> Port Scan -> CVE Correlation -> Report Compilation.
        """
        run_logs = []
        t0 = time.time()

        def log_step(msg: str):
            run_logs.append(f"[{time.strftime('%H:%M:%S')}] {msg}")
            if progress_cb:
                progress_cb(msg)

        log_step(f"Starting Automated Security Workflow for target '{target}'...")

        # Step 1: Scope Validation
        try:
            scope_manager.enforce_scope(target, project_id)
            log_step("[OK] STEP 1: Target validated within Authorized Project Scope.")
        except ScopeViolationError as e:
            log_step(f"[FAIL] STEP 1 ABORTED: {e}")
            return {"status": "FAILED", "reason": str(e), "logs": run_logs}

        # Step 2: Critical Port Scan
        critical_ports = [21, 22, 80, 135, 443, 445, 3389, 8080]
        log_step(f"[*] STEP 2: Scanning {len(critical_ports)} critical ports on {target}...")
        try:
            scan_results = port_scanner_engine.scan_target(target, critical_ports, project_id=project_id)
            open_ports = [r for r in scan_results if r.state == "OPEN"]
            log_step(f"[OK] STEP 2: Port Scan Completed. Found {len(open_ports)} open port(s).")
        except Exception as e:
            log_step(f"[FAIL] STEP 2 FAILED: {e}")
            return {"status": "FAILED", "reason": str(e), "logs": run_logs}

        # Step 3: CVE Correlation
        log_step("[*] STEP 3: Correlating discovered services with Known Exploited Vulnerabilities...")
        correlated_cves = []
        for p in open_ports:
            cves = vulnerability_engine.evaluate_service_vulnerabilities(p.service)
            correlated_cves.extend(cves)
        log_step(f"[OK] STEP 3: Identified {len(correlated_cves)} potential CVE reference(s).")

        # Step 4: Compile Report
        log_step("[*] STEP 4: Compiling assessment report...")
        report_md = report_generator.generate_comprehensive_report(project_id=project_id, lang="EN")
        log_step("[OK] STEP 4: Executive Assessment Report successfully compiled.")

        elapsed = round(time.time() - t0, 2)
        log_step(f"[+] Workflow Completed in {elapsed} seconds.")

        return {
            "status": "COMPLETED",
            "target": target,
            "elapsed_seconds": elapsed,
            "open_ports_count": len(open_ports),
            "cves_correlated": len(correlated_cves),
            "logs": run_logs,
            "report_preview": report_md[:500]
        }

workflow_engine = SecurityAutomationEngine()
