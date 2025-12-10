# CAPEv2 Processing Module for Box.js (Docker-based)
import os
import subprocess
import json
import logging

from lib.cuckoo.common.abstracts import Processing

log = logging.getLogger(__name__)

class BoxJSProcessing(Processing):
    """Run Box.js inside Docker for static JavaScript analysis."""

    def run(self):
        self.key = "boxjs"
        sample_path = self.file_path
        analysis_path = self.analysis_path

        # Only process JavaScript files
        #if not sample_path.endswith(".js"):
        #    log.info("Box.js skipped: not a JavaScript file.")
        #    return {}

        # Create output directory for Box.js results
        boxjs_output = os.path.join(analysis_path, "boxjs_results")
        os.makedirs(boxjs_output, exist_ok=True)

        # Configurable options
        docker_image = self.options.get("docker_image", "capacitorset/box-js")
        timeout = int(self.options.get("timeout", 300))  # default 5 min
        extra_flags = self.options.get("extra_flags", "--download")

        try:
            cmd = [
                "docker", "run", "--rm",
                "-v", f"{sample_path}:/samples/sample.js:ro",
                "-v", f"{boxjs_output}:/output",
                docker_image,
                "box-js", "/samples/sample.js", "--output-dir=/output", extra_flags
            ]
            log.info(f"Running Box.js in Docker: {' '.join(cmd)}")

            subprocess.run(cmd, check=True, timeout=timeout)

            # Parse Box.js output files
            results_dir = os.path.join(boxjs_output, "sample.js.results")
            results = {
                "urls": [],
                "ioc": [],
                "snippets": [],
                "ioc_summary": {}
            }

            log.info(f"Building BoxJS Results: {results}")

            urls_file = os.path.join(results_dir, "urls.json")
            if os.path.exists(urls_file):
                with open(urls_file) as f:
                    results["urls"] = json.load(f)
            log.info(f"Building BoxJS Results: {results}")

            ioc_file = os.path.join(results_dir, "IOC.json")
            if os.path.exists(ioc_file):
                with open(ioc_file) as f:
                    results["ioc"] = json.load(f)
            log.info(f"Building BoxJS Results: {results}")

            snippets_file = os.path.join(results_dir, "snippets.json")
            if os.path.exists(snippets_file):
                with open(snippets_file) as f:
                    results["snippets"] = json.load(f)
            log.info(f"Building BoxJS Results: {results}")


            # Build summary
            results["ioc_summary"] = {
                "total_urls": len(results["urls"]),
                "total_iocs": len(results["ioc"]),
                "total_snippets": len(results["snippets"])
            }
            log.info(f"Building BoxJS Results: {results}")

            return {"boxjs": results}

        except subprocess.TimeoutExpired:
            log.error(f"Box.js analysis timed out after {timeout} seconds.")
        except subprocess.CalledProcessError as e:
            log.error(f"Box.js execution failed: {e}")
        except Exception as e:
            log.exception(f"Unexpected error running Box.js: {e}")

        return {}

