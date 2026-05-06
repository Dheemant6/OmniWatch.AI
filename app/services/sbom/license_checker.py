import logging

logger = logging.getLogger(__name__)

# Very basic example of restricted licenses to flag in commercial/closed enterprise apps
BANNED_LICENSES = {
    "GPL-3.0",
    "GPL-3.0-only", 
    "GPL-3.0-or-later",
    "AGPL-3.0",
    "AGPL-3.0-only",
    "SSPL"
}

def check_compliance(sbom: dict) -> list[dict]:
    """
    Scans a standard CycloneDX SBOM dict for banned licenses.
    Returns a list of violation dicts describing components causing infractions.
    """
    violations = []
    
    components = sbom.get("components", [])
    
    for comp in components:
        licenses = comp.get("licenses", [])
        
        for lic_data in licenses:
            lic = lic_data.get("license", {})
            spdx_id = lic.get("id", lic.get("name", "")).upper()
            
            # Simple check if any of the banned licenses are a substring match or exact match
            for banned in BANNED_LICENSES:
                if banned.upper() in spdx_id:
                    v = {
                        "component": comp.get("name"),
                        "version": comp.get("version"),
                        "license": spdx_id,
                        "purl": comp.get("purl"),
                        "policy_violation": f"Banned license found: {banned}"
                    }
                    violations.append(v)
                    logger.warning(f"License Policy Violation: {comp.get('name')} uses {spdx_id}")

    return violations
