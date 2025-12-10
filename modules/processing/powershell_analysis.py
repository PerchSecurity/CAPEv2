# CAPEv2 Processing Module: PowerShell Deobfuscator
# Place this in: modules/processing/powershell_deobfuscator.py

import re
import base64
import binascii
import subprocess
import os
import logging
from lib.cuckoo.common.abstracts import Processing

log = logging.getLogger(__name__)

class PowerShellAnalysis(Processing):
    """Deobfuscate PowerShell scripts and extract IOCs for static analysis."""

    def decode_base64(self, data):
        try:
            return base64.b64decode(data).decode("utf-8", errors="ignore")
        except (binascii.Error, UnicodeDecodeError):
            return None

    
    def extract_iocs(self, text):
        # Regex patterns
        url_pattern = r"https?://[^\s\"']+"  # Full URLs
        domain_from_url_pattern = r"https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"  # Capture domain after http(s)
        download_cmd_pattern = r"\b(?:Invoke-WebRequest|iwr|curl|wget)\s+'\""
    
        # Extract all URLs
        urls = re.findall(url_pattern, text)
    
        # Extract domains from URLs
        domains_from_urls = re.findall(domain_from_url_pattern, " ".join(urls))
    
        # Extract URLs after download commands
        cmd_urls = re.findall(download_cmd_pattern, text)
        domains_from_cmds = re.findall(domain_from_url_pattern, " ".join(cmd_urls))
    
        # Combine and deduplicate domains
        all_domains = set(domains_from_urls + domains_from_cmds)

        # Deduplicate URLs and IPs
        unique_urls = list(set(urls + cmd_urls))
        unique_ips = list(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)))
    
        return {
            "urls": unique_urls,
            "domains": list(all_domains),
            "ips": unique_ips
        }

    def run(self):
        log.info("Starting PowerShell analysis")
        self.key = "powershell_analysis"
        results = {"deobfuscated_script": "", "iocs": {}}

        # Locate PowerShell script from static analysis
        target = self.task.get("target")
        if not target or not target.endswith(".ps1"):
            log.info("No PowerShell script detected for analysis.")
            return results

        ps_script = open(target, 'r').read()

        # Step 1: Replace 'iex' with 'Write-Output'
        #edited_script = ps_script.replace("iex", "Write-Output")
        #with open(target, 'w') as f:
        #    f.write(edited_script)
        #log.info(f"Running script {target} - Contents: {edited_script}")
        #cmd = ["pwsh", target]
        #deobfuscated = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
        deob_pass=1
        deobfuscated = ""
        while True:
            # Read current script
            with open(target, 'r') as f:
                script_content = f.read()
        
            # Check if 'iex' exists
            if "iex" not in script_content:
                break  # No more iex, stop looping
        
            # Replace 'iex' with 'Write-Output'
            script_content = script_content.replace("iex", "Write-Output")
        
            # Write modified script back
            with open(target, 'w') as f:
                f.write(script_content)
        
            # Run the script and capture output
            try:
                #cmd = ["firejail", "--net=none", "pwsh", target]
                cmd = ["pwsh", target]
                output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
            except subprocess.CalledProcessError as e:
                output = e.output  # Capture error output if script fails
        
            # Append output to deobfuscated content
            deobfuscated += "Deobfuscation pass" + str(deob_pass) + "\n" + output
        
            # Overwrite script with output for next iteration
            with open(target, 'w') as f:
                f.write(output)

            deob_pass += 1
        
        log.info(f"Deobfuscated script: {deobfuscated}")

        # Step 2: Detect and decode Base64 strings
        base64_candidates = re.findall(r"[A-Za-z0-9+/=]{20,}", deobfuscated)
        for candidate in base64_candidates:
            decoded = self.decode_base64(candidate)
            if decoded:
                deobfuscated += "\n" + decoded

        # Step 3: Extract IOCs
        iocs = self.extract_iocs(deobfuscated)
        log.info(f"IOCs: {iocs}")

        # Populate results
        results["deobfuscated_script"] = deobfuscated
        results["iocs"] = iocs

        return results
    
