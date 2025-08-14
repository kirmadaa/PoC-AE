import json
import subprocess
import tempfile
from typing import List, Dict

def run_trivy_image(image: str) -> dict:
    """
    Runs: trivy image --no-progress -f json -o <tempfile> <image>
    Returns parsed JSON dict.
    """
    tmp = tempfile.NamedTemporaryFile(prefix="trivy_report_", suffix=".json", delete=False)
    tmp.close()
    outpath = tmp.name
    cmd = ["trivy", "image", "--no-progress", "-f", "json", "-o", outpath, image]
    print("Running:", " ".join(cmd))
    subprocess.run(cmd, check=True)
    with open(outpath, "r") as fh:
        data = json.load(fh)
    return data

def parse_trivy_json(trivy_json: dict) -> List[Dict]:
    """
    Parse Trivy JSON into a normalized list of vulnerabilities.

    Each item: {
      'vuln_id', 'pkg_name', 'installed_version', 'fixed_version' (may be ''),
      'severity', 'primary_url', 'target' (image or package target)
    }
    """
    results = []
    # Trivy's structure: top-level "Results": [ { "Target": "alpine:3.12", "Class": ..., "Type": "os", "Vulnerabilities": [...] } ...]
    for res in trivy_json.get("Results", []):
        target = res.get("Target", "")
        vulns = res.get("Vulnerabilities") or []
        for v in vulns:
            item = {
                "vuln_id": v.get("VulnerabilityID"),
                "pkg_name": v.get("PkgName"),
                "installed_version": v.get("InstalledVersion"),
                "fixed_version": v.get("FixedVersion") or "",
                "severity": v.get("Severity"),
                "primary_url": (v.get("References") or [None])[0],
                "target": target,
                "title": v.get("Title") or "",
            }
            results.append(item)
    return results
