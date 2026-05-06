import os
import httpx
import logging
from typing import List, Dict
import asyncio
from packaging import version as pypa_version

logger = logging.getLogger(__name__)

class OSVScanner:
    def __init__(self):
        self.osv_url = "https://api.osv.dev/v1/query"

    async def check_vulnerabilities(self, component: dict, client: httpx.AsyncClient) -> List[Dict]:
        name = component.get("name")
        version = component.get("version")
        purl = component.get("purl")
        vulns = []
        
        if not purl:
            return vulns
            
        ecosystem = "npm" if "pkg:npm" in purl else "PyPI" if "pkg:pypi" in purl else None
        if not ecosystem:
            return vulns

        payload = {
            "package": {"name": name, "ecosystem": ecosystem},
            "version": version
        }
        
        try:
            response = await client.post(self.osv_url, json=payload)
            if response.status_code == 200:
                data = response.json()
                if "vulns" in data:
                    for vuln in data["vulns"]:
                        aliases = vuln.get("aliases", [])
                        cve = next((a for a in aliases if a.startswith("CVE-")), vuln.get("id"))
                        ghsa_id = vuln.get("id", "")
                        is_malicious = ghsa_id.startswith("MAL-")
                        
                        # Extract the CVSS severity if available
                        severity_raw = "high"
                        for sev_obj in vuln.get("severity", []):
                            score_str = sev_obj.get("score", "")
                            # CVSS:3.1/AV:N/.../7.5 - extract base score
                            if "/AV:" in score_str:
                                try:
                                    base_score = float(score_str.split("/")[-1])
                                    if base_score >= 9.0: severity_raw = "critical"
                                    elif base_score >= 7.0: severity_raw = "high"
                                    elif base_score >= 4.0: severity_raw = "medium"
                                    else: severity_raw = "low"
                                except Exception:
                                    pass
                        severity = "critical" if is_malicious else severity_raw

                        # Extract fix version from OSV affected.ranges
                        fixed_version = None
                        for affected in vuln.get("affected", []):
                            for rng in affected.get("ranges", []):
                                for event in rng.get("events", []):
                                    if "fixed" in event:
                                        fixed_version = event["fixed"]
                                        break
                                if fixed_version:
                                    break
                            if fixed_version:
                                break

                        # Build specific remediation message
                        if is_malicious:
                            remediation = f"CRITICAL: Remove {name} immediately — it is a malicious package. Reference: {ghsa_id}"
                        elif fixed_version:
                            remediation = (
                                f"Upgrade {name} from {version} → {fixed_version} (or later) to patch this vulnerability.\n"
                                f"  In requirements.txt: change '{name}=={version}' to '{name}>={fixed_version}'\n"
                                f"  Run: pip install --upgrade {name}\n"
                                f"  Advisory: {ghsa_id}"
                                + (f" | CVE: {cve}" if cve != ghsa_id else "")
                            )
                        else:
                            remediation = (
                                f"Upgrade {name} to the latest stable version to patch this vulnerability.\n"
                                f"  Run: pip install --upgrade {name} (or npm update {name})\n"
                                f"  Advisory: {ghsa_id}"
                                + (f" | CVE: {cve}" if cve != ghsa_id else "")
                            )

                        title = (
                            f"Malicious Dependency: {name}@{version}" if is_malicious
                            else f"Supply Chain Vulnerability in {name}@{version}"
                            + (f" ({cve})" if cve and cve != ghsa_id else f" ({ghsa_id})")
                        )

                        vulns.append({
                            "file": "requirements.txt" if "pypi" in purl else "package.json",
                            "line": None,
                            "severity": severity,
                            "title": title,
                            "description": vuln.get("details", vuln.get("summary", "Known vulnerability in third-party dependency.")),
                            "cve_reference": cve,
                            "remediation_patch": remediation,
                        })
        except Exception as e:
            logger.error(f"Error querying OSV for {name}@{version}: {e}")
            
        return vulns

class NVDScanner:
    def __init__(self):
        self.nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.api_key = os.environ.get("NVD_API_KEY")

    async def check_vulnerabilities(self, component: dict, client: httpx.AsyncClient) -> List[Dict]:
        cpe = component.get("cpe")
        vulns = []
        if not cpe:
            return vulns

        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        try:
            response = await client.get(f"{self.nvd_url}?cpeName={cpe}", headers=headers, timeout=10.0)
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])
                for item in vulnerabilities:
                    cve_item = item.get("cve", {})
                    cve_id = cve_item.get("id")
                    descriptions = cve_item.get("descriptions", [])
                    desc_text = next((d.get("value") for d in descriptions if d.get("lang") == "en"), "NVD Vulnerability")
                    
                    metrics = cve_item.get("metrics", {})
                    cvss_data = []
                    for k in metrics.keys():
                        cvss_data.extend(metrics[k])
                    
                    severity = "medium"
                    if cvss_data:
                        first_cvss = cvss_data[0].get("cvssData", {})
                        severity = first_cvss.get("baseSeverity", "medium").lower()

                    vulns.append({
                        "file": "SBOM",
                        "line": None,
                        "severity": severity,
                        "title": f"NVD Vulnerability in {component.get('name')} ({cve_id})",
                        "description": desc_text,
                        "cve_reference": cve_id,
                        "remediation": f"Upgrade {component.get('name')} to a patched version."
                    })
        except Exception as e:
            logger.error(f"Error querying NVD for cpe {cpe}: {e}")

        return vulns

class GitHubAdvisoryScanner:
    def __init__(self):
        self.graphql_url = "https://api.github.com/graphql"
        self.token = os.environ.get("GITHUB_TOKEN")

    async def check_vulnerabilities(self, component: dict, client: httpx.AsyncClient) -> List[Dict]:
        vulns = []
        if not self.token:
            return vulns

        name = component.get("name")
        purl = component.get("purl", "")
        
        ecosystem = "NPM" if "pkg:npm" in purl else "PIP" if "pkg:pypi" in purl else None
        if not ecosystem:
            return vulns

        query = """
        query($ecosystem: SecurityAdvisoryEcosystem!, $package: String!) {
          securityVulnerabilities(ecosystem: $ecosystem, package: $package, first: 5) {
            nodes {
              severity
              advisory {
                id
                summary
                description
                identifiers { type value }
              }
            }
          }
        }
        """

        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
        
        variables = {"ecosystem": ecosystem, "package": name}
        
        try:
            response = await client.post(self.graphql_url, json={"query": query, "variables": variables}, headers=headers, timeout=10.0)
            if response.status_code == 200:
                data = response.json()
                nodes = data.get("data", {}).get("securityVulnerabilities", {}).get("nodes", [])
                for node in nodes:
                    advisory = node.get("advisory", {})
                    severity = node.get("severity", "MODERATE").lower()
                    if severity == "moderate": severity = "medium"
                    
                    identifiers = advisory.get("identifiers", [])
                    cve = next((i["value"] for i in identifiers if i["type"] == "CVE"), advisory.get("id"))

                    vulns.append({
                        "file": "SBOM",
                        "line": None,
                        "severity": severity,
                        "title": f"GHSA: {advisory.get('summary', 'Vulnerability in ' + name)}",
                        "description": advisory.get("description", ""),
                        "cve_reference": cve,
                        "remediation": f"Upgrade {name} according to GitHub Advisory."
                    })
        except Exception as e:
            logger.error(f"Error querying GHSA for {name}: {e}")
            
        return vulns

class DependencyHealthScanner:
    async def check_outdated(self, component: dict, client: httpx.AsyncClient) -> List[Dict]:
        name = component.get("name")
        version = component.get("version")
        purl = component.get("purl", "")
        vulns = []

        if not version:
            return vulns

        try:
            latest_version = None
            if "pkg:pypi" in purl:
                resp = await client.get(f"https://pypi.org/pypi/{name}/json", timeout=5.0)
                if resp.status_code == 200:
                    latest_version = resp.json().get("info", {}).get("version")
            elif "pkg:npm" in purl:
                resp = await client.get(f"https://registry.npmjs.org/{name}", timeout=5.0)
                if resp.status_code == 200:
                    latest_version = resp.json().get("dist-tags", {}).get("latest")

            if latest_version:
                if self._is_outdated(version, latest_version):
                    vulns.append({
                        "file": "SBOM",
                        "line": None,
                        "severity": "low",
                        "title": f"Outdated Dependency: {name}@{version}",
                        "description": f"The version {version} of {name} is outdated. The latest version is {latest_version}.",
                        "cve_reference": None,
                        "remediation": f"Upgrade {name} to version {latest_version} to receive recent security patches and bug fixes."
                    })
        except Exception as e:
            logger.debug(f"Failed to check health for {name}: {e}")

        return vulns
        
    def _is_outdated(self, current: str, latest: str) -> bool:
        try:
            return pypa_version.parse(current) < pypa_version.parse(latest)
        except:
            return False

class SupplyChainAnalyzer:
    def __init__(self):
        self.osv = OSVScanner()
        self.nvd = NVDScanner()
        self.ghsa = GitHubAdvisoryScanner()
        self.health = DependencyHealthScanner()

    async def check_vulnerabilities(self, sbom: dict) -> List[Dict]:
        all_vulns = []
        components = sbom.get("components", [])
        
        async with httpx.AsyncClient() as client:
            tasks = []
            for component in components:
                tasks.append(self.osv.check_vulnerabilities(component, client))
                tasks.append(self.nvd.check_vulnerabilities(component, client))
                tasks.append(self.ghsa.check_vulnerabilities(component, client))
                tasks.append(self.health.check_outdated(component, client))
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for index, res in enumerate(results):
                if isinstance(res, Exception):
                    logger.error(f"Error in a scanner task: {res}")
                elif isinstance(res, list):
                    all_vulns.extend(res)
                    
        seen = set()
        deduped = []
        for v in all_vulns:
            identifier = v.get("cve_reference") or v.get("title")
            if identifier not in seen:
                seen.add(identifier)
                deduped.append(v)
                
        return deduped
