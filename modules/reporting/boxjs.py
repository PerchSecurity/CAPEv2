# CAPEv2 Reporting Module for Box.js
import logging
from lib.cuckoo.common.abstracts import Report

log = logging.getLogger(__name__)


class BoxJSReport(Report):
    def run(self, results):
        # CAPE merges processing results under their key directly

        boxjs_data = results.get("boxjs", {})
        if "boxjs" in boxjs_data:
            boxjs_data = boxjs_data["boxjs"]
        #boxjs_data = results.get("boxjs")
        log.info(f"boxjs_data: {boxjs_data}")
        if not boxjs_data:
            log.info("No Box.js data found.")
            return

        # Inject into final report
        results.setdefault("static_analysis", {})
        results["static_analysis"]["boxjs"] = boxjs_data
        #log.info(f"results: {results}")

        # Log correct summary
        summary = boxjs_data.get("ioc_summary")
        log.info(f"summary: {summary}")
        log.info(f"Box.js report added: {summary}")

