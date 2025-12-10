# CAPEv2 Reporting Module for Box.js
import logging
from lib.cuckoo.common.abstracts import Report
import os

log = logging.getLogger(__name__)


class PowerShellAnalysis(Report):
    """Generate report section for PowerShell deobfuscation results."""

    def run(self, results):
        # CAPE merges processing results under their key directly

        powershell_analysis_data = results.get("powershell_analysis", {})
        if "powershell_analysis" in powershell_analysis_data:
            powershell_analysis_data = powershell_analysis_data["powershell_analysis"]
        #powershell_analysis_data = results.get("powershell_analysis")
        log.info(f"powershell_analysis_data: {powershell_analysis_data}")
        if not powershell_analysis_data:
            log.info("No Box.js data found.")
            return

        # Inject into final report
        results.setdefault("static_analysis", {})
        results["static_analysis"]["powershell_analysis"] = powershell_analysis_data
        #log.info(f"results: {results}")

        # Log correct summary
        iocs = powershell_analysis_data.get("iocs")
        log.info(f"PS IOCs: {iocs}")

