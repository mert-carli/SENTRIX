import sqlite3
import os
import json
from datetime import datetime
from typing import List, Dict, Any, Optional

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "sentrix.db")

class Database:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()

    def get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=15.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def _init_db(self):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # 1. Projects & Scope Management
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS projects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                authorized_targets TEXT DEFAULT '',
                allowed_ip_ranges TEXT DEFAULT '',
                allowed_domains TEXT DEFAULT '',
                excluded_targets TEXT DEFAULT '',
                max_scan_rate INTEGER DEFAULT 100,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """)

            cursor.execute("""
            INSERT OR IGNORE INTO projects (id, name, authorized_targets, allowed_ip_ranges, allowed_domains, excluded_targets)
            VALUES (1, 'Default Lab Scope', '127.0.0.1, localhost', '192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12', 'localhost, local', '');
            """)

            # 2. Operations (Engagements / Assessments)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS operations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER DEFAULT 1,
                name TEXT NOT NULL,
                operation_type TEXT NOT NULL, -- PENTEST, RED_TEAM, RECON, AUDIT
                status TEXT DEFAULT 'ACTIVE', -- ACTIVE, COMPLETED, ARCHIVED
                started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ended_at TIMESTAMP,
                notes TEXT,
                FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
            );
            """)

            # 3. Assets & Hosts
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER DEFAULT 1,
                ip TEXT NOT NULL,
                mac TEXT,
                hostname TEXT,
                os_guess TEXT,
                latency TEXT,
                vendor TEXT,
                status TEXT DEFAULT 'ONLINE',
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
                UNIQUE(project_id, ip)
            );
            """)

            # 4. Domains & OSINT Assets
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS domains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER DEFAULT 1,
                domain_name TEXT NOT NULL,
                apex_domain TEXT,
                ip_addresses TEXT, -- comma-separated
                mail_servers TEXT,
                whois_registrar TEXT,
                whois_created TIMESTAMP,
                whois_expires TIMESTAMP,
                discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
                UNIQUE(project_id, domain_name)
            );
            """)

            # 5. Scan Sessions
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER DEFAULT 1,
                scan_type TEXT NOT NULL,
                target TEXT NOT NULL,
                status TEXT DEFAULT 'COMPLETED',
                started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP,
                total_found INTEGER DEFAULT 0,
                raw_output TEXT,
                FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
            );
            """)

            # 6. Open Ports & Services
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS open_ports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER NOT NULL,
                scan_session_id INTEGER,
                port INTEGER NOT NULL,
                protocol TEXT DEFAULT 'TCP',
                service TEXT DEFAULT 'UNKNOWN',
                version TEXT,
                state TEXT DEFAULT 'OPEN',
                detection_method TEXT DEFAULT 'BANNER/CONNECT',
                confidence INTEGER DEFAULT 90,
                cve_references TEXT,
                recommended_checks TEXT,
                last_scanned TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE,
                FOREIGN KEY (scan_session_id) REFERENCES scan_sessions(id) ON DELETE SET NULL,
                UNIQUE(host_id, port, protocol)
            );
            """)

            # 7. Vulnerabilities & Findings
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER,
                cve_id TEXT,
                title TEXT NOT NULL,
                severity TEXT DEFAULT 'MEDIUM',
                cvss_score REAL DEFAULT 5.0,
                epss_score REAL DEFAULT 0.0,
                is_cisa_kev BOOLEAN DEFAULT 0,
                status TEXT DEFAULT 'POTENTIALLY AFFECTED', -- CONFIRMED, POTENTIALLY AFFECTED, NOT AFFECTED, INCONCLUSIVE
                evidence TEXT,
                remediation TEXT,
                discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE SET NULL
            );
            """)

            # 8. Web Security Findings
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS web_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER DEFAULT 1,
                target_url TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                category TEXT NOT NULL,
                severity TEXT DEFAULT 'MEDIUM',
                confidence TEXT DEFAULT 'HIGH',
                title TEXT NOT NULL,
                evidence TEXT,
                remediation TEXT,
                status TEXT DEFAULT 'CONFIRMED',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
            );
            """)

            # 9. Network Flows (PCAP / Flow analysis)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS network_flows (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                src_ip TEXT NOT NULL,
                src_port INTEGER,
                dst_ip TEXT NOT NULL,
                dst_port INTEGER,
                protocol TEXT NOT NULL,
                bytes_sent INTEGER DEFAULT 0,
                bytes_recv INTEGER DEFAULT 0,
                duration_sec REAL DEFAULT 0.0,
                is_anomaly BOOLEAN DEFAULT 0,
                anomaly_reason TEXT
            );
            """)

            # 10. File Artifacts & Forensics
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS file_artifacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_name TEXT NOT NULL,
                file_path TEXT NOT NULL,
                file_size INTEGER DEFAULT 0,
                format_detected TEXT,
                md5_hash TEXT,
                sha256_hash TEXT NOT NULL,
                entropy REAL DEFAULT 0.0,
                is_packed BOOLEAN DEFAULT 0,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """)

            # 11. Security Events (Raw Ingest)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                event_type TEXT NOT NULL,
                source TEXT NOT NULL,
                severity TEXT DEFAULT 'INFO',
                title TEXT NOT NULL,
                raw_data TEXT
            );
            """)

            # 12. Central Correlated Alerts
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                severity TEXT NOT NULL, -- CRITICAL, HIGH, MEDIUM, LOW, INFO
                confidence INTEGER DEFAULT 80,
                source TEXT NOT NULL,
                title TEXT NOT NULL,
                evidence TEXT,
                mitre_technique TEXT,
                status TEXT DEFAULT 'ACTIVE', -- ACTIVE, ACKNOWLEDGED, RESOLVED, FALSE_POSITIVE
                recommended_action TEXT
            );
            """)

            # 13. Incidents (IR Workspace)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_number TEXT UNIQUE NOT NULL,
                title TEXT NOT NULL,
                severity TEXT DEFAULT 'HIGH',
                status TEXT DEFAULT 'OPEN', -- OPEN, INVESTIGATING, CONTAINED, CLOSED
                assigned_analyst TEXT DEFAULT 'SecOps Analyst',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                closed_at TIMESTAMP,
                summary TEXT,
                containment_actions TEXT
            );
            """)

            # 14. Evidence Management
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id INTEGER,
                case_id TEXT NOT NULL,
                evidence_name TEXT NOT NULL,
                file_path TEXT,
                sha256_hash TEXT NOT NULL,
                acquisition_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                chain_of_custody TEXT,
                notes TEXT,
                FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE SET NULL
            );
            """)

            # 15. Threat Intelligence IOCs
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS threat_indicators (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator TEXT UNIQUE NOT NULL,
                ioc_type TEXT NOT NULL, -- IP, DOMAIN, HASH, URL
                threat_type TEXT,
                confidence INTEGER DEFAULT 75,
                source TEXT,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP
            );
            """)

            # 16. Security Automation Workflows
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS workflows (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                description TEXT,
                steps_json TEXT NOT NULL, -- list of step definitions
                is_active BOOLEAN DEFAULT 1,
                last_run TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """)

            cursor.execute("""
            CREATE TABLE IF NOT EXISTS workflow_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                workflow_id INTEGER NOT NULL,
                status TEXT DEFAULT 'COMPLETED', -- RUNNING, COMPLETED, FAILED, CANCELLED
                started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ended_at TIMESTAMP,
                logs_json TEXT,
                FOREIGN KEY (workflow_id) REFERENCES workflows(id) ON DELETE CASCADE
            );
            """)

            # 17. Sigma & Detection Rules
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS detection_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id TEXT UNIQUE NOT NULL,
                title TEXT NOT NULL,
                status TEXT DEFAULT 'STABLE',
                severity TEXT DEFAULT 'MEDIUM',
                author TEXT DEFAULT 'SENTRIX',
                mitre_technique TEXT,
                condition_json TEXT NOT NULL,
                is_enabled BOOLEAN DEFAULT 1
            );
            """)

            # 18. Audit Logs
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                action TEXT NOT NULL,
                details TEXT,
                user TEXT DEFAULT 'SYSTEM'
            );
            """)

            # 19. User Settings & Configurations
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            """)

            # --- SENTRIX v4.0 Schema Expansion ---

            # 20. Event Sources
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS event_sources (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                source_type TEXT NOT NULL, -- ETW, SYSMON, EVENTLOG, EDR, CLOUD
                status TEXT DEFAULT 'ACTIVE',
                config_json TEXT,
                events_ingested INTEGER DEFAULT 0,
                last_event_at TIMESTAMP
            );
            """)

            # 21. Process Events Telemetry
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS process_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                host_id INTEGER DEFAULT 1,
                pid INTEGER NOT NULL,
                ppid INTEGER,
                process_name TEXT NOT NULL,
                image_path TEXT,
                command_line TEXT,
                user_account TEXT,
                integrity_level TEXT,
                sha256 TEXT,
                parent_process_name TEXT,
                is_suspicious BOOLEAN DEFAULT 0
            );
            """)

            # 22. File & Integrity Events
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS file_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                host_id INTEGER DEFAULT 1,
                file_path TEXT NOT NULL,
                action TEXT NOT NULL, -- CREATED, MODIFIED, DELETED, RENAMED
                sha256 TEXT,
                pid INTEGER,
                user_account TEXT
            );
            """)

            # 23. Registry Change Events
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS registry_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                host_id INTEGER DEFAULT 1,
                key_path TEXT NOT NULL,
                value_name TEXT,
                value_data TEXT,
                action TEXT NOT NULL, -- SET, DELETED, KEY_CREATED
                pid INTEGER
            );
            """)

            # 24. Network Flows
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS network_flows (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                host_id INTEGER DEFAULT 1,
                src_ip TEXT NOT NULL,
                src_port INTEGER,
                dst_ip TEXT NOT NULL,
                dst_port INTEGER,
                protocol TEXT DEFAULT 'TCP',
                bytes_sent INTEGER DEFAULT 0,
                bytes_recv INTEGER DEFAULT 0,
                pid INTEGER,
                process_name TEXT
            );
            """)

            # 25. Forensic Cases & Evidence
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS forensic_cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_number TEXT UNIQUE NOT NULL,
                title TEXT NOT NULL,
                investigator TEXT DEFAULT 'Analyst',
                status TEXT DEFAULT 'ACTIVE', -- ACTIVE, CLOSED, ARCHIVED
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                closed_at TIMESTAMP
            );
            """)

            cursor.execute("""
            CREATE TABLE IF NOT EXISTS forensic_evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER,
                evidence_label TEXT NOT NULL,
                evidence_type TEXT NOT NULL, -- MEMORY_IMAGE, DISK_IMAGE, PCAP, LOG, TRIAGE
                source_path TEXT,
                file_size_bytes INTEGER DEFAULT 0,
                sha256 TEXT NOT NULL,
                acquired_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                chain_of_custody TEXT,
                FOREIGN KEY (case_id) REFERENCES forensic_cases(id) ON DELETE CASCADE
            );
            """)

            # 26. Memory Artifacts
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS memory_artifacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER,
                image_name TEXT NOT NULL,
                artifact_type TEXT NOT NULL, -- PROCESS, NETWORK, INJECTED_CODE, MUTEX, DRIVER
                pid INTEGER,
                process_name TEXT,
                memory_address TEXT,
                protection TEXT,
                suspicious_indicators TEXT,
                notes TEXT,
                FOREIGN KEY (case_id) REFERENCES forensic_cases(id) ON DELETE CASCADE
            );
            """)

            # 27. Threat Hunting Workspace
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS threat_hunts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hunt_id TEXT UNIQUE NOT NULL,
                title TEXT NOT NULL,
                hypothesis TEXT NOT NULL,
                author TEXT DEFAULT 'Lead Threat Hunter',
                mitre_technique TEXT,
                status TEXT DEFAULT 'IN_PROGRESS', -- IN_PROGRESS, VALIDATED, NO_FINDINGS, CLOSED
                findings_summary TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                closed_at TIMESTAMP
            );
            """)

            cursor.execute("""
            CREATE TABLE IF NOT EXISTS hunt_queries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hunt_id INTEGER NOT NULL,
                query_type TEXT NOT NULL, -- SQL, SIGMA, PROCESS, NETWORK
                query_string TEXT NOT NULL,
                results_count INTEGER DEFAULT 0,
                executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (hunt_id) REFERENCES threat_hunts(id) ON DELETE CASCADE
            );
            """)

            # 28. Detection Rule Executions
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS rule_executions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id TEXT NOT NULL,
                execution_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                target_dataset TEXT NOT NULL,
                matched_count INTEGER DEFAULT 0,
                duration_ms REAL DEFAULT 0.0,
                status TEXT DEFAULT 'SUCCESS'
            );
            """)

            # 29. Cloud & Container Assets
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS cloud_assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                provider TEXT NOT NULL, -- AWS, AZURE, GCP
                account_id TEXT NOT NULL,
                resource_id TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                region TEXT,
                risk_level TEXT DEFAULT 'LOW', -- CRITICAL, HIGH, MEDIUM, LOW
                findings_json TEXT,
                last_scanned TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(provider, account_id, resource_id)
            );
            """)

            cursor.execute("""
            CREATE TABLE IF NOT EXISTS container_assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_type TEXT NOT NULL, -- DOCKER_CONTAINER, DOCKER_IMAGE, K8S_POD, K8S_SERVICE
                asset_id TEXT NOT NULL,
                name TEXT NOT NULL,
                namespace TEXT DEFAULT 'default',
                is_privileged BOOLEAN DEFAULT 0,
                exposed_ports TEXT,
                vulnerabilities_json TEXT,
                last_scanned TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(asset_type, asset_id)
            );
            """)

            # 30. Software Supply Chain & SBOM
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS software_components (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_name TEXT NOT NULL,
                component_name TEXT NOT NULL,
                version TEXT NOT NULL,
                package_type TEXT NOT NULL, -- PYTHON, NPM, GO, NATIVE
                license TEXT,
                cve_count INTEGER DEFAULT 0,
                osv_findings TEXT,
                last_scanned TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(project_name, component_name, version)
            );
            """)

            # 31. Attack Surface Risk Assessments
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS risk_assessments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_id INTEGER NOT NULL,
                asset_name TEXT NOT NULL,
                overall_score REAL NOT NULL, -- 0.0 to 100.0
                likelihood_score REAL NOT NULL,
                impact_score REAL NOT NULL,
                critical_findings_count INTEGER DEFAULT 0,
                remediation_plan TEXT,
                evaluated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """)

            # 32. Incident Actions & SOAR Playbooks
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS incident_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id INTEGER NOT NULL,
                action_type TEXT NOT NULL, -- PROCESS_KILL, FIREWALL_BLOCK, QUARANTINE, NOTIFY
                description TEXT NOT NULL,
                status TEXT DEFAULT 'PENDING_APPROVAL', -- PENDING_APPROVAL, EXECUTED, CANCELLED, ROLLED_BACK
                approved_by TEXT,
                executed_at TIMESTAMP,
                result_output TEXT,
                FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
            );
            """)

            cursor.execute("""
            CREATE TABLE IF NOT EXISTS automation_playbooks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                description TEXT,
                trigger_type TEXT NOT NULL, -- ON_ALERT, ON_SCHEDULE, ON_SCAN_COMPLETE, MANUAL
                playbook_json TEXT NOT NULL,
                is_active BOOLEAN DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """)

            cursor.execute("""
            CREATE TABLE IF NOT EXISTS playbook_executions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                playbook_id INTEGER NOT NULL,
                trigger_event TEXT,
                status TEXT DEFAULT 'COMPLETED', -- RUNNING, COMPLETED, FAILED, WAITING_APPROVAL
                steps_completed INTEGER DEFAULT 0,
                execution_log TEXT,
                started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP,
                FOREIGN KEY (playbook_id) REFERENCES automation_playbooks(id) ON DELETE CASCADE
            );
            """)

            # Indexes for v4.0 Performance
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_proc_pid ON process_events(pid);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_proc_name ON process_events(process_name);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_hunt_id ON threat_hunts(hunt_id);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_cloud_res ON cloud_assets(provider, resource_id);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_cont_id ON container_assets(asset_id);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_comp_name ON software_components(component_name);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_risk_asset ON risk_assessments(asset_id);")

            # Indexes for Performance Optimization
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts(ip);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_ports_host ON open_ports(host_id);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_sev ON alerts(severity);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_flows_ip ON network_flows(src_ip, dst_ip);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_ti_indicator ON threat_indicators(indicator);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_vuln_cve ON vulnerabilities(cve_id);")

            # Automated Schema Migrations
            cursor.execute("PRAGMA table_info(open_ports);")
            port_cols = [row["name"] for row in cursor.fetchall()]
            if "scan_session_id" not in port_cols:
                cursor.execute("ALTER TABLE open_ports ADD COLUMN scan_session_id INTEGER;")
            if "detection_method" not in port_cols:
                cursor.execute("ALTER TABLE open_ports ADD COLUMN detection_method TEXT DEFAULT 'BANNER/CONNECT';")

            cursor.execute("PRAGMA table_info(scan_sessions);")
            session_cols = [row["name"] for row in cursor.fetchall()]
            if "raw_output" not in session_cols:
                cursor.execute("ALTER TABLE scan_sessions ADD COLUMN raw_output TEXT;")

            cursor.execute("PRAGMA table_info(vulnerabilities);")
            vuln_cols = [row["name"] for row in cursor.fetchall()]
            if "epss_score" not in vuln_cols:
                cursor.execute("ALTER TABLE vulnerabilities ADD COLUMN epss_score REAL DEFAULT 0.0;")
            if "is_cisa_kev" not in vuln_cols:
                cursor.execute("ALTER TABLE vulnerabilities ADD COLUMN is_cisa_kev BOOLEAN DEFAULT 0;")

            conn.commit()

    # --- CRUD Helpers ---
    def add_audit_log(self, action: str, details: str = "", user: str = "SYSTEM"):
        try:
            with self.get_connection() as conn:
                conn.execute(
                    "INSERT INTO audit_logs (action, details, user) VALUES (?, ?, ?)",
                    (action, details, user)
                )
                conn.commit()
        except Exception:
            pass

    def upsert_host(self, ip: str, mac: str = "", hostname: str = "", os_guess: str = "", latency: str = "", vendor: str = "", project_id: int = 1) -> int:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO hosts (project_id, ip, mac, hostname, os_guess, latency, vendor, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(project_id, ip) DO UPDATE SET
                mac = COALESCE(NULLIF(excluded.mac, ''), hosts.mac),
                hostname = COALESCE(NULLIF(excluded.hostname, ''), hosts.hostname),
                os_guess = COALESCE(NULLIF(excluded.os_guess, ''), hosts.os_guess),
                latency = COALESCE(NULLIF(excluded.latency, ''), hosts.latency),
                vendor = COALESCE(NULLIF(excluded.vendor, ''), hosts.vendor),
                last_seen = CURRENT_TIMESTAMP;
            """, (project_id, ip, mac, hostname, os_guess, latency, vendor))
            conn.commit()
            
            cursor.execute("SELECT id FROM hosts WHERE project_id = ? AND ip = ?", (project_id, ip))
            row = cursor.fetchone()
            return row["id"] if row else 0

    def upsert_port(self, host_id: int, port: int, protocol: str = "TCP", service: str = "UNKNOWN", version: str = "", state: str = "OPEN", confidence: int = 90, cve_references: str = "", recommended_checks: str = "", scan_session_id: Optional[int] = None, detection_method: str = "BANNER/CONNECT"):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO open_ports (host_id, scan_session_id, port, protocol, service, version, state, confidence, cve_references, recommended_checks, detection_method, last_scanned)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(host_id, port, protocol) DO UPDATE SET
                scan_session_id = COALESCE(excluded.scan_session_id, open_ports.scan_session_id),
                service = excluded.service,
                version = excluded.version,
                state = excluded.state,
                confidence = excluded.confidence,
                cve_references = excluded.cve_references,
                recommended_checks = excluded.recommended_checks,
                detection_method = excluded.detection_method,
                last_scanned = CURRENT_TIMESTAMP;
            """, (host_id, scan_session_id, port, protocol, service, version, state, confidence, cve_references, recommended_checks, detection_method))
            conn.commit()

    def record_scan_session(self, scan_type: str, target: str, total_found: int, raw_output: str = "", project_id: int = 1) -> int:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO scan_sessions (project_id, scan_type, target, total_found, raw_output, completed_at)
            VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """, (project_id, scan_type, target, total_found, raw_output))
            conn.commit()
            return cursor.lastrowid

    def add_alert(self, severity: str, source: str, title: str, evidence: str = "", mitre_technique: str = "", recommended_action: str = "", confidence: int = 85) -> int:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO alerts (severity, confidence, source, title, evidence, mitre_technique, recommended_action)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (severity, confidence, source, title, evidence, mitre_technique, recommended_action))
            conn.commit()
            return cursor.lastrowid

    def create_incident(self, title: str, severity: str = "HIGH", summary: str = "") -> int:
        incident_num = f"INC-{datetime.now().strftime('%Y%m%d')}-{os.urandom(2).hex().upper()}"
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO incidents (incident_number, title, severity, summary)
            VALUES (?, ?, ?, ?)
            """, (incident_num, title, severity, summary))
            conn.commit()
            return cursor.lastrowid

    def get_recent_alerts(self, limit: int = 20) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def get_all_hosts(self, project_id: int = 1) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM hosts WHERE project_id = ? ORDER BY ip ASC", (project_id,))
            return [dict(row) for row in cursor.fetchall()]

    def get_open_ports_for_host(self, host_id: int) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM open_ports WHERE host_id = ? ORDER BY port ASC", (host_id,))
            return [dict(row) for row in cursor.fetchall()]

    def get_all_open_ports(self) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            SELECT p.*, h.ip, h.hostname 
            FROM open_ports p
            LEFT JOIN hosts h ON p.host_id = h.id
            ORDER BY p.port ASC
            """)
            return [dict(row) for row in cursor.fetchall()]

    def get_all_vulnerabilities(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM vulnerabilities ORDER BY cvss_score DESC, id DESC LIMIT ?", (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def log_security_event(self, event_type: str, description: str, severity: str = "INFO", source: str = "SENTRIX", title: str = "") -> int:
        if not title:
            title = description[:50]
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO security_events (event_type, source, severity, title, raw_data)
            VALUES (?, ?, ?, ?, ?)
            """, (event_type, source, severity, title, description))
            conn.commit()
            return cursor.lastrowid

    def get_recent_security_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM security_events ORDER BY id DESC LIMIT ?", (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def set_setting(self, key: str, value: str):
        with self.get_connection() as conn:
            conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))
            conn.commit()

    def get_setting(self, key: str, default: str = "") -> str:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT value FROM settings WHERE key = ?", (key,))
            row = cursor.fetchone()
            return row["value"] if row else default

db = Database()
