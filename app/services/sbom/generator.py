import os
import json
import logging
import asyncio
import httpx
from datetime import datetime
try:
    from dicttoxml import dicttoxml
except ImportError:
    dicttoxml = None

logger = logging.getLogger(__name__)

class SBOMGenerator:
    def __init__(self):
        # We define simple registries here
        self.npm_registry = "https://registry.npmjs.org"
        self.pypi_registry = "https://pypi.org/pypi"

    async def _fetch_npm_license(self, client: httpx.AsyncClient, name: str) -> list:
        try:
            resp = await client.get(f"{self.npm_registry}/{name}", timeout=3.0)
            if resp.status_code == 200:
                data = resp.json()
                lic = data.get("license", "UNKNOWN")
                if isinstance(lic, dict): # some old npm formats
                    lic = lic.get("type", "UNKNOWN")
                return [{"license": {"id": lic}}]
        except Exception:
            pass
        return []

    async def _fetch_pypi_license(self, client: httpx.AsyncClient, name: str) -> list:
        try:
            resp = await client.get(f"{self.pypi_registry}/{name}/json", timeout=3.0)
            if resp.status_code == 200:
                info = resp.json().get("info", {})
                lic = info.get("license") or "UNKNOWN"
                return [{"license": {"name": lic}}]
        except Exception:
            pass
        return []

    async def build_sbom(self, workspace_path: str, repo_name: str) -> dict:
        """
        Parses package manifests and lock files to reconstruct transitive dependencies.
        Fetches license metadata asynchronously.
        Outputs a CycloneDX compliant JSON dictionary.
        """
        logger.info(f"Generating SBOM for {repo_name} at {workspace_path}")
        components = []
        
        # Determine dependencies (including transitives via lockfile)
        npm_deps = self._parse_npm_tree(workspace_path)
        pypi_deps = self._parse_pypi_tree(workspace_path)
        
        # Combine
        raw_components = npm_deps + pypi_deps

        # Fetch licenses concurrently
        async with httpx.AsyncClient() as client:
            tasks = []
            for comp in raw_components:
                if "pkg:npm" in comp["purl"]:
                    tasks.append(self._fetch_npm_license(client, comp["name"]))
                else:
                    tasks.append(self._fetch_pypi_license(client, comp["name"]))
            
            licenses_list = await asyncio.gather(*tasks)
            
            for i, comp in enumerate(raw_components):
                comp["licenses"] = licenses_list[i]
                components.append(comp)

        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "metadata": {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "component": {
                    "type": "application",
                    "name": repo_name
                }
            },
            "components": components
        }
        return sbom

    def _parse_npm_tree(self, workspace_path: str) -> list:
        components = []
        lock_path = os.path.join(workspace_path, "package-lock.json")
        pkg_path = os.path.join(workspace_path, "package.json")
        
        if os.path.exists(lock_path):
            # lock file handles transitive well
            try:
                with open(lock_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    
                    # package-lock v2/v3 puts deps in "packages"
                    packages = data.get("packages", {})
                    # default fallback to v1 format dependencies
                    deps = data.get("dependencies", {})
                    
                    if packages:
                        for key, val in packages.items():
                            if not key: continue # root project itself
                            name = key.split("node_modules/")[-1]
                            ver = val.get("version", "")
                            if name and ver:
                                components.append(self._make_comp(name, ver, "npm"))
                    elif deps:
                        for name, val in deps.items():
                            ver = val.get("version", "")
                            if name and ver:
                                components.append(self._make_comp(name, ver, "npm"))
            except Exception as e:
                logger.error(f"Failed to parse package-lock.json: {e}")
        elif os.path.exists(pkg_path):
            # direct dependency fallback
            try:
                with open(pkg_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    all_deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
                    for name, ver in all_deps.items():
                        clean_ver = ver.lstrip("^~<>=")
                        components.append(self._make_comp(name, clean_ver, "npm"))
            except Exception as e:
                logger.error(f"Failed to parse package.json: {e}")
                
        return components

    def _parse_pypi_tree(self, workspace_path: str) -> list:
        components = []
        req_txt_path = os.path.join(workspace_path, "requirements.txt")
        # In a real environment we'd parse poetry.lock or pipfile.lock for transitivity.
        # But here we do best-effort requirements logic.
        if os.path.exists(req_txt_path):
            with open(req_txt_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split("==")
                    if len(parts) == 2:
                        name, ver = parts[0].strip(), parts[1].strip()
                        components.append(self._make_comp(name, ver, "pypi"))
        return components

    def _make_comp(self, name: str, version: str, eco: str) -> dict:
        return {
            "type": "library",
            "name": name,
            "version": version,
            "purl": f"pkg:{eco}/{name}@{version}"
        }

    def export_json(self, sbom: dict, output_path: str):
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(sbom, f, indent=2)
            
    def export_xml(self, sbom: dict, output_path: str):
        if dicttoxml is None:
            logger.error("dicttoxml is not installed; cannot export XML")
            return
        # Basic CycloneDX XML wrap
        xml_bytes = dicttoxml(sbom, custom_root="bom", attr_type=False)
        with open(output_path, "wb") as f:
            f.write(xml_bytes)
