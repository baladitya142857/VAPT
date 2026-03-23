"""
Session state shared across all VAPT modules
"""
import json
import os
from datetime import datetime


class Session:
    """Global session state for the VAPT engagement"""

    def __init__(self):
        self.reset()

    def reset(self):
        self.target         = ""
        self.scope          = []
        self.recon_results  = {}
        self.scan_results   = {}
        self.vuln_results   = []
        self.exploit_log    = []
        self.post_ex_log    = []
        self.findings       = []        # unified finding list for reporting
        self.started_at     = datetime.now()
        self.engagement_name = "VAPT Engagement"
        self.tester_name     = "Security Tester"
        self.org_name        = "Target Organization"

    # ── helpers ──────────────────────────────────────────────────────────────

    def add_finding(self, title, severity, description,
                    impact="", remediation="", module=""):
        self.findings.append({
            "id":          len(self.findings) + 1,
            "title":       title,
            "severity":    severity,
            "description": description,
            "impact":      impact,
            "remediation": remediation,
            "module":      module,
            "timestamp":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        })

    def to_dict(self):
        return {
            "target":          self.target,
            "engagement_name": self.engagement_name,
            "tester_name":     self.tester_name,
            "org_name":        self.org_name,
            "started_at":      self.started_at.isoformat(),
            "recon_results":   self.recon_results,
            "scan_results":    self.scan_results,
            "vuln_results":    self.vuln_results,
            "exploit_log":     self.exploit_log,
            "post_ex_log":     self.post_ex_log,
            "findings":        self.findings,
        }

    def save(self, path):
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2, default=str)

    def load(self, path):
        with open(path) as f:
            data = json.load(f)
        self.target          = data.get("target", "")
        self.engagement_name = data.get("engagement_name", "VAPT Engagement")
        self.tester_name     = data.get("tester_name", "Security Tester")
        self.org_name        = data.get("org_name", "Target Organization")
        self.recon_results   = data.get("recon_results", {})
        self.scan_results    = data.get("scan_results", {})
        self.vuln_results    = data.get("vuln_results", [])
        self.exploit_log     = data.get("exploit_log", [])
        self.post_ex_log     = data.get("post_ex_log", [])
        self.findings        = data.get("findings", [])


# Singleton
session = Session()
