from typing import List, Dict, Any

class AndroidManifestAuditor:
    """Audits Android application manifest configuration for security misconfigurations."""

    @staticmethod
    def audit_manifest_flags(
        debuggable: bool = False,
        allow_backup: bool = True,
        uses_cleartext: bool = False,
        exported_components_count: int = 0
    ) -> List[Dict[str, Any]]:
        findings = []

        if debuggable:
            findings.append({
                "severity": "CRITICAL",
                "category": "MASVS-PLATFORM",
                "title": "Application is configured as debuggable (android:debuggable=true)",
                "description": "Enables runtime debugging, memory dumping, and arbitrary code injection via ADB.",
                "remediation": "Set android:debuggable='false' in production release manifests."
            })

        if allow_backup:
            findings.append({
                "severity": "MEDIUM",
                "category": "MASVS-STORAGE",
                "title": "Application backup enabled (android:allowBackup=true)",
                "description": "Allows extracting app data and private storage via 'adb backup'.",
                "remediation": "Set android:allowBackup='false' if sensitive credentials or tokens are stored locally."
            })

        if uses_cleartext:
            findings.append({
                "severity": "HIGH",
                "category": "MASVS-NETWORK",
                "title": "Cleartext HTTP traffic allowed (android:usesCleartextTraffic=true)",
                "description": "Permits unencrypted HTTP communications susceptible to network eavesdropping and MITM.",
                "remediation": "Enforce HTTPS by setting android:usesCleartextTraffic='false' and configuring Network Security Config."
            })

        if exported_components_count > 0:
            findings.append({
                "severity": "MEDIUM",
                "category": "MASVS-PLATFORM",
                "title": f"{exported_components_count} components exported without permission checks",
                "description": "Exported activities, services, or broadcast receivers can be triggered by rogue apps on the device.",
                "remediation": "Set android:exported='false' for internal components or require custom permissions."
            })

        return findings
