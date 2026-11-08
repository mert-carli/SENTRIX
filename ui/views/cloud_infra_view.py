import customtkinter as ctk
import threading
from ui.views.common import (
    COLOR_BG_MAIN, COLOR_BG_SECONDARY, COLOR_BORDER, COLOR_TEXT_PRIMARY,
    COLOR_TEXT_SECONDARY, COLOR_ACCENT_TERMINAL, COLOR_STATE_CRITICAL,
    COLOR_STATE_WARNING, COLOR_HOVER, FONT_TITLE, FONT_SUBTITLE, FONT_BTN,
    FONT_TEXT, FONT_CODE, BaseWorkspaceView
)
from modules.cloud_security.aws.aws_auditor import AWSSecurityAuditor
from modules.cloud_security.azure.azure_auditor import AzureSecurityAuditor
from modules.cloud_security.gcp.gcp_auditor import GCPSecurityAuditor
from modules.container_security.docker_auditor import DockerAuditor
from modules.container_security.kubernetes_auditor import KubernetesAuditor
from modules.supply_chain.dependency_scanner import DependencyScanner
from modules.supply_chain.sbom_engine import SBOMEngine
from modules.crypto_lab.tls_inspector import TLSInspector
from modules.crypto_lab.local_store import LocalCertificateStoreAuditor

class CloudInfrastructureView(BaseWorkspaceView):
    def __init__(self, parent, controller):
        super().__init__(parent, controller)
        self.aws = AWSSecurityAuditor()
        self.docker = DockerAuditor()
        self.k8s = KubernetesAuditor()
        self._init_ui()

    def _init_ui(self):
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=20, pady=(15, 10))
        lbl_title = ctk.CTkLabel(header, text="CLOUD & INFRASTRUCTURE SECURITY", font=FONT_TITLE, text_color=COLOR_TEXT_PRIMARY)
        lbl_title.pack(side="left")
        lbl_desc = ctk.CTkLabel(header, text=" // Cloud Posture, Containers, Supply Chain SBOM & Cryptography", font=FONT_SUBTITLE, text_color=COLOR_TEXT_SECONDARY)
        lbl_desc.pack(side="left", padx=(10, 0))

        self.tabview = ctk.CTkTabview(
            self, fg_color=COLOR_BG_SECONDARY,
            segmented_button_fg_color=COLOR_BG_MAIN,
            segmented_button_selected_color=COLOR_HOVER,
            segmented_button_selected_hover_color=COLOR_HOVER,
            text_color=COLOR_TEXT_PRIMARY
        )
        self.tabview.pack(fill="both", expand=True, padx=20, pady=(0, 15))

        self.tab_cloud = self.tabview.add("Cloud Posture (AWS/Azure/GCP)")
        self.tab_containers = self.tabview.add("Containers & K8s")
        self.tab_supply = self.tabview.add("Supply Chain & SBOM")
        self.tab_crypto = self.tabview.add("Cryptography & TLS Lab")

        self._setup_cloud_tab()
        self._setup_containers_tab()
        self._setup_supply_tab()
        self._setup_crypto_tab()

    def _setup_cloud_tab(self):
        bar = ctk.CTkFrame(self.tab_cloud, fg_color="transparent")
        bar.pack(fill="x", padx=10, pady=10)

        btn_aws = ctk.CTkButton(
            bar, text="Audit AWS Baseline Rules", font=FONT_BTN,
            fg_color=COLOR_HOVER, hover_color=COLOR_BORDER,
            text_color=COLOR_ACCENT_TERMINAL, width=200,
            command=self._audit_aws_demo
        )
        btn_aws.pack(side="left", padx=(0, 10))

        self.txt_cloud = ctk.CTkTextbox(self.tab_cloud, font=FONT_CODE, fg_color=COLOR_BG_MAIN, text_color=COLOR_TEXT_PRIMARY)
        self.txt_cloud.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    def _setup_containers_tab(self):
        bar = ctk.CTkFrame(self.tab_containers, fg_color="transparent")
        bar.pack(fill="x", padx=10, pady=10)

        btn_doc = ctk.CTkButton(
            bar, text="Audit Docker Containers", font=FONT_BTN,
            fg_color=COLOR_HOVER, hover_color=COLOR_BORDER,
            text_color=COLOR_ACCENT_TERMINAL, width=190,
            command=self._audit_docker
        )
        btn_doc.pack(side="left", padx=(0, 10))

        btn_k8s = ctk.CTkButton(
            bar, text="Check Kubernetes Cluster", font=FONT_BTN,
            fg_color=COLOR_HOVER, hover_color=COLOR_BORDER,
            text_color=COLOR_TEXT_PRIMARY, width=190,
            command=self._audit_k8s
        )
        btn_k8s.pack(side="left")

        self.txt_containers = ctk.CTkTextbox(self.tab_containers, font=FONT_CODE, fg_color=COLOR_BG_MAIN, text_color=COLOR_TEXT_PRIMARY)
        self.txt_containers.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    def _setup_supply_tab(self):
        bar = ctk.CTkFrame(self.tab_supply, fg_color="transparent")
        bar.pack(fill="x", padx=10, pady=10)

        btn_sbom = ctk.CTkButton(
            bar, text="Generate CycloneDX SBOM", font=FONT_BTN,
            fg_color=COLOR_HOVER, hover_color=COLOR_BORDER,
            text_color=COLOR_ACCENT_TERMINAL, width=210,
            command=self._generate_sbom
        )
        btn_sbom.pack(side="left")

        self.txt_supply = ctk.CTkTextbox(self.tab_supply, font=FONT_CODE, fg_color=COLOR_BG_MAIN, text_color=COLOR_TEXT_PRIMARY)
        self.txt_supply.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    def _setup_crypto_tab(self):
        bar = ctk.CTkFrame(self.tab_crypto, fg_color="transparent")
        bar.pack(fill="x", padx=10, pady=10)

        lbl_h = ctk.CTkLabel(bar, text="Host:", font=FONT_TEXT, text_color=COLOR_TEXT_PRIMARY)
        lbl_h.pack(side="left", padx=(0, 5))
        self.entry_tls = ctk.CTkEntry(bar, width=180, font=FONT_CODE, fg_color=COLOR_BG_MAIN, border_color=COLOR_BORDER, text_color=COLOR_TEXT_PRIMARY)
        self.entry_tls.insert(0, "google.com")
        self.entry_tls.pack(side="left", padx=(0, 10))

        btn_tls = ctk.CTkButton(
            bar, text="Probe TLS Endpoint", font=FONT_BTN,
            fg_color=COLOR_HOVER, hover_color=COLOR_BORDER,
            text_color=COLOR_ACCENT_TERMINAL, width=160,
            command=self._probe_tls
        )
        btn_tls.pack(side="left", padx=(0, 10))

        btn_ca = ctk.CTkButton(
            bar, text="Audit Windows Root CA Store", font=FONT_BTN,
            fg_color=COLOR_HOVER, hover_color=COLOR_BORDER,
            text_color=COLOR_TEXT_PRIMARY, width=220,
            command=self._audit_root_cas
        )
        btn_ca.pack(side="left")

        self.txt_crypto = ctk.CTkTextbox(self.tab_crypto, font=FONT_CODE, fg_color=COLOR_BG_MAIN, text_color=COLOR_TEXT_PRIMARY)
        self.txt_crypto.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    def _audit_aws_demo(self):
        self.txt_cloud.delete("1.0", "end")
        self.txt_cloud.insert("end", "[*] Auditing AWS Security Group & S3 rules...\n")
        sample_sgs = [{
            "GroupId": "sg-01a2b3c4d5",
            "OwnerId": "123456789012",
            "IpPermissions": [{
                "FromPort": 22, "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            }]
        }]
        findings = self.aws.audit_security_group_rules(sample_sgs)
        findings += self.aws.audit_s3_bucket("sentrix-corp-backup", is_public=True, encryption_enabled=False)
        for f in findings:
            self.txt_cloud.insert("end", f"[{f.severity}] {f.title}\n")
            self.txt_cloud.insert("end", f"    Resource: {f.resource_type} ({f.resource_id})\n")
            self.txt_cloud.insert("end", f"    Evidence: {f.evidence}\n")
            self.txt_cloud.insert("end", f"    Remedy:   {f.remediation}\n")
            self.txt_cloud.insert("end", "-" * 60 + "\n")

    def _audit_docker(self):
        self.txt_containers.delete("1.0", "end")
        stat = self.docker.check_docker_available()
        self.txt_containers.insert("end", f"Docker Status: {stat.get('status')} - {stat.get('message')}\n\n")
        containers = self.docker.audit_running_containers()
        if containers:
            for c in containers:
                self.txt_containers.insert("end", f"Container: {c['names']} ({c['image']}) | Privileged: {c['is_privileged']}\n")
        else:
            self.txt_containers.insert("end", "[i] No active Docker containers found or Docker daemon offline.\n")

    def _audit_k8s(self):
        self.txt_containers.delete("1.0", "end")
        stat = self.k8s.check_kubectl_status()
        self.txt_containers.insert("end", f"Kubernetes Status: {stat.get('status')} - {stat.get('message')}\n")

    def _generate_sbom(self):
        self.txt_supply.delete("1.0", "end")
        packages = DependencyScanner.parse_requirements_txt("requirements.txt")
        sbom = SBOMEngine.generate_cyclonedx_json(packages, project_name="SENTRIX")
        self.txt_supply.insert("end", f"[+] CycloneDX SBOM Generated ({len(packages)} components):\n\n")
        import json
        self.txt_supply.insert("end", json.dumps(sbom, indent=2))

    def _probe_tls(self):
        host = self.entry_tls.get().strip()
        self.txt_crypto.delete("1.0", "end")
        self.txt_crypto.insert("end", f"[*] Probing TLS endpoint: {host}:443...\n")
        def run():
            res = TLSInspector.inspect_endpoint(host)
            self.after(0, lambda: self._render_tls(res))
        threading.Thread(target=run, daemon=True).start()

    def _render_tls(self, res):
        self.txt_crypto.delete("1.0", "end")
        self.txt_crypto.insert("end", f"Host:         {res.get('host')}\n")
        self.txt_crypto.insert("end", f"TLS Version:  {res.get('tls_version')}\n")
        self.txt_crypto.insert("end", f"Cipher Suite: {res.get('cipher_suite')} ({res.get('bits')} bits)\n")
        self.txt_crypto.insert("end", f"Security:     {res.get('status')}\n")

    def _audit_root_cas(self):
        self.txt_crypto.delete("1.0", "end")
        self.txt_crypto.insert("end", "[*] Auditing Windows Root CA Certificate Store...\n")
        def run():
            cas = LocalCertificateStoreAuditor.audit_root_store(limit=25)
            self.after(0, lambda: self._render_cas(cas))
        threading.Thread(target=run, daemon=True).start()

    def _render_cas(self, cas):
        self.txt_crypto.delete("1.0", "end")
        self.txt_crypto.insert("end", f"[+] Retrieved {len(cas)} Trusted Root Authorities from Cert:\\LocalMachine\\Root:\n\n")
        for ca in cas:
            self.txt_crypto.insert("end", f"Subject: {ca.get('Subject')}\n")
            self.txt_crypto.insert("end", f"Expires: {ca.get('NotAfter')} | Thumbprint: {ca.get('Thumbprint')}\n")
            self.txt_crypto.insert("end", "-" * 60 + "\n")
