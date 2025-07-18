import json
import os
import logging
import argparse
from collections import defaultdict
import subprocess

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(message)s')


def load_report(file_path):
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        logging.error(f"Failed to load {file_path}: {e}")
        # Ensure we always have a Results key
        return {"Results": []}


def get_component_root(target):
    """
    Derive a component directory from the Trivy target string.
    If it’s a path, take the top-level folder; otherwise default to '.'.
    """
    # Normalize path separators
    norm = os.path.normpath(target)
    # If it looks like a file path under a subfolder, use that folder
    parts = norm.split(os.sep)
    if len(parts) >= 2 and parts[0] not in ("", "."):
        return parts[0]
    # For image scans (e.g. alpine:3.19), treat as root
    return "."


def group_vulnerabilities_by_component(report):
    grouped = defaultdict(list)
    results = report.get("Results", [])
    if not isinstance(results, list):
        return grouped

    for result in results:
        target = result.get("Target", "")
        comp = get_component_root(target)
        for vuln in result.get("Vulnerabilities", []) + result.get("Misconfigurations", []):
            grouped[comp].append(vuln)
    return grouped


def remediate_go_mod(component_root, vulns):
    logging.info(f"\n[Go Module Remediation] Component: {component_root}")
    go_mod_path = os.path.join(component_root, 'go.mod')
    if not os.path.exists(go_mod_path):
        logging.warning(f"go.mod not found in {component_root}")
        return

    fixed_any = False
    for vuln in vulns:
        if vuln.get('Type', '').lower() != 'gomod':
            continue
        module_name = vuln.get('PkgName')
        fixed_version = vuln.get('FixedVersion')
        if module_name and fixed_version:
            logging.info(f"Upgrading {module_name} to version {fixed_version}…")
            try:
                subprocess.run(['go', 'get', f'{module_name}@{fixed_version}'],
                               cwd=component_root, check=True)
                fixed_any = True
            except subprocess.CalledProcessError as e:
                logging.error(f"Failed to update {module_name}: {e}")

    if fixed_any:
        subprocess.run(['go', 'mod', 'tidy'], cwd=component_root, check=False)


def remediate_dockerfile(component_root, vulns):
    logging.info(f"\n[Dockerfile Remediation] Component: {component_root}")
    dockerfile_path = os.path.join(component_root, 'Dockerfile')
    if not os.path.exists(dockerfile_path):
        logging.warning(f"Dockerfile not found in {component_root}")
        return

    with open(dockerfile_path, 'r') as f:
        lines = f.readlines()

    modified = False
    # If Trivy flagged DS001 (running as root), insert a non-root user
    if any(v.get('ID') == 'DS001' for v in vulns):
        if not any('adduser' in l or 'useradd' in l for l in lines):
            # insert before any CMD/ENTRYPOINT or at end if not found
            insert_at = next((i for i,l in enumerate(lines) if l.strip().upper().startswith(('CMD ', 'ENTRYPOINT '))), len(lines)-1)
            lines.insert(insert_at, 'RUN adduser -D appuser\n')
        if not any(l.strip().upper().startswith('USER ') for l in lines):
            lines.append('USER appuser\n')
        modified = True

    if modified:
        with open(dockerfile_path, 'w') as f:
            f.writelines(lines)
        logging.info("Dockerfile updated with non-root user.")


def main(go_report, dockerfile_report, image_report):
    all_reports = [
        load_report(go_report),
        load_report(dockerfile_report),
        load_report(image_report),
    ]

    # Merge vulnerabilities per component directory
    prioritized = defaultdict(list)
    for report in all_reports:
        for comp, vulns in group_vulnerabilities_by_component(report).items():
            prioritized[comp].extend(vulns)

    if not prioritized:
        logging.info("No vulnerabilities found to remediate.")
        return

    for comp, vulns in prioritized.items():
        logging.info(f"\nProcessing component: {comp} with {len(vulns)} issues")
        remediate_go_mod(comp, vulns)
        remediate_dockerfile(comp, vulns)

    logging.info("\n--- PoC Remediation Complete ---")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Trivy Remediation Script")
    parser.add_argument('--go-report',        required=True, help="Path to Trivy go.mod scan report")
    parser.add_argument('--dockerfile-report',required=True, help="Path to Trivy Dockerfile scan report")
    parser.add_argument('--image-report',     required=True, help="Path to Trivy image scan report")
    args = parser.parse_args()

    main(args.go_report, args.dockerfile_report, args.image_report)
