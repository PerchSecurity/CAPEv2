# CAPEv2 Reporting Module: OpenCTI Integration with STIX Relationships
import logging
import re
from lib.cuckoo.common.abstracts import Report
from datetime import datetime
from pycti import OpenCTIApiClient

log = logging.getLogger(__name__)

class OpenCTIReporting(Report):
    """Send CAPEv2 analysis results to OpenCTI as Malware Analysis entity with STIX relationships."""
    def to_iso8601(self, dt_string):
        try:
            # CAPEv2 format: "YYYY-MM-DD HH:MM:SS"
            dt = datetime.strptime(dt_string, "%Y-%m-%d %H:%M:%S")
            return dt.isoformat() + "Z"  # Append Z for UTC
        except Exception:
            return None
    
    def add_malware(self, client, malware_name, artifact_id, analysis_id):
        log.info(f"Finding and adding malware and relationships: {malware_name}")
        mal = client.malware.create(name=malware_name)
        malware_id = mal["id"]

        # Link Malware Analysis to Malware
        client.stix_core_relationship.create(
            fromId=analysis_id,
            toId=malware_id,
            relationship_type="related-to"
        )

        client.stix_core_relationship.create(
            fromId=artifact_id,
            toId=malware_id,
            relationship_type="related-to"
        )


    def run(self, results):
        log.info("Begin processing data for OpenCTI")
        api_url = self.options.get("api_url")
        api_token = self.options.get("api_token")
        log.info(f"Attempting to connect to {api_url}")
        client = OpenCTIApiClient(api_url, api_token)

        # Extract sample info
        target = results.get("target", {}).get("file", {})
        sample_name = target.get("name")
        sample_md5 = target.get("md5")
        sample_sha256 = target.get("sha256")
        started = self.to_iso8601(results.get("info", {}).get("started"))
        ended = self.to_iso8601(results.get("info", {}).get("ended"))

        # Create Malware Analysis entity
        analysis = client.malware_analysis.create(
            product="CAPEv2",
            result_name=f"{sample_name} analyzed on {started}",
            analysis_started=started,
            analysis_ended=ended,
            sample_md5=sample_md5,
            sample_sha256=sample_sha256,
        )
        analysis_id = analysis["id"]
        log.info(f"Created Malware Analysis: {analysis_id}")

        # Create Artifact for the sample
        filters = {
                "mode": "and",
                "filters": [{
                    "key":"hashes.SHA-256",
                    "operator":"eq",
                    "values":[sample_sha256],
                    "mode":"or"
                    }],
                "filterGroups": [],
                }
        log.info(f"Searching for Artifact with filters {filters}")
        artifact = client.stix_cyber_observable.read(filters=filters)
        log.info(f"Found Artifact - {artifact}")
        artifact_id = artifact["id"]

        # Link Malware Analysis to Artifact
        client.stix_core_relationship.create(
            fromId=analysis_id,
            toId=artifact_id,
            relationship_type="related-to"
        )

        # Optionally create Malware entity (if family name known)
        log.info(f"Results: {results}")
        if 'detections' in results:
            log.info(f"Found detections")
            for malware in results['detections']:
                malware_name = malware['family']
                self.add_malware(client, malware_name, artifact_id, analysis_id)

        if "clamav" in results['target']['file']:
            log.info(f"Found clamav")
            for malware in results['target']['file']['clamav']:
                pattern="(?<=\\.)(\\w+)(?=\\-)"
                malware_name = re.findall(pattern, malware)[0]
                self.add_malware(client, malware_name, artifact_id, analysis_id)

        for signature in results['signatures']:
            abstract = signature['description']
            content = str(signature['data'][0])
            sig_note = client.note.create(abstract=abstract, content=content)
            note_id=sig_note['id']
            note_rel = client.note.add_stix_object_or_stix_relationship(id=note_id,stixObjectOrStixRelationshipId=analysis_id)

        # Collect observables from BoxJS and PowerShell
        observables = []
        boxjs = results.get("boxjs", {})
        log.info(f"BOX.js data - {boxjs}")
        if "boxjs" in boxjs.keys():
            for url in boxjs['boxjs']['urls']:
                observables.append({'type': 'URL.value', 'value': url})
            for note in boxjs['boxjs']['ioc']:
                abstract = note['type']
                content = str(note['value'])
                if abstract == 'Sample Name':
                    pass
                else:
                    sig_note = client.note.create(abstract=abstract, content=content)
                    note_id=sig_note['id']
                    note_rel = client.note.add_stix_object_or_stix_relationship(id=note_id,stixObjectOrStixRelationshipId=analysis_id)


        ps = results.get("powershell_analysis", {})
        iocs = ps.get("iocs", {})
        if "urls" in iocs.keys():
            for url in iocs['urls']:
                observables.append({'type': 'URL.value', 'value': url})
            for domain in iocs['domains']:
                observables.append({'type': 'Domain-Name.value', 'value': domain})
            for ip in iocs['ips']:
                observables.append({'type': 'IPv4-Addr.value', 'value': ip})

        #observables.update(iocs.get("urls", []))
        #observables.update(iocs.get("domains", []))
        #observables.update(iocs.get("ips", []))

        # Create observables and link them
        log.info(f"Observables - {observables}")
        for obs in observables:
            try:
                obs_type = obs['type']
                obs_value = obs['value']
                log.info(f"Attempting to create {obs_type} - {obs_value}")
                observable = client.stix_cyber_observable.create(
                    simple_observable_value=obs_value,
                    simple_observable_key=obs_type,
                    simple_observable_description=f"Extracted from CAPEv2 analysis of {sample_name}"
                )
                client.stix_core_relationship.create(
                    fromId=artifact_id,
                    toId=observable["id"],
                    relationship_type="related-to"
                )
                client.stix_core_relationship.create(
                    fromId=analysis_id,
                    toId=observable["id"],
                    relationship_type="related-to"
                )
            except Exception as e:
                log.error(f"Failed to create observable {obs_value}: {e}")


