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
        return {}

def get_component_root(file_path):
    if file_path.endswith("go.mod") or file_path.endswith("Dockerfile"):
        return os.path.dirname(file_path) or "."
    elif file_path.endswith(".apk") or ":" in file_path:
        # Likely an image scan target like "alpine:3.19"
        return "."
    return "."

def group_vulnerabilities_by_component(report):
    grouped = defaultdict(list)
    results = report.get("Results", [])
    if not isinstance(results, list):
        return grouped

    for result in results:
        target = result.get("Target", "")
        component_root = get_component_root(target)
        vulns = result.get("Vulnerabilities", [])
        misconfigs = result.get("Misconfigurations", [])

        for vuln in vulns + misconfigs:
            grouped[component_root].append(vuln)
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
            logging.info(f"Upgrading {module_name} to version {fixed_version}...")
            try:
                subprocess.run(['go', 'get', f'{module_name}@{fixed_version}'], cwd=component_root, check=True)
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
    if any(v.get('ID') == 'DS001' for v in vulns):  # Checks if container runs as root
        if not any('useradd -u' in line or 'adduser' in line for line in lines):
            lines.insert(-1, 'RUN adduser -D appuser\n')
        if not any(line.startswith('USER ') for line in lines):
            lines.append('USER appuser\n')
        modified = True

    if modified:
        with open(dockerfile_path, 'w') as f:
            f.writelines(lines)
        logging.info("Dockerfile updated with non-root user.")

def main(go_report, dockerfile_report, image_report):
    all_reports = [load_report(go_report), load_report(dockerfile_report), load_report(image_report)]

    prioritized_vulns_by_component = defaultdict(list)
    for report in all_reports:
        grouped = group_vulnerabilities_by_component(report)
        for comp, vulns in grouped.items():
            prioritized_vulns_by_component[comp].extend(vulns)

    if not prioritized_vulns_by_component:
        logging.info("No vulnerabilities found to remediate.")
        return

    for component_root, vulns in prioritized_vulns_by_component.items():
        logging.info(f"\nProcessing component: {component_root} with {len(vulns)} issues")
        remediate_go_mod(component_root, vulns)
        remediate_dockerfile(component_root, vulns)

    logging.info("\n--- PoC Remediation Complete ---")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Trivy Remediation Script")
    parser.add_argument('--go-report', required=True, help="Path to Trivy go.mod scan report")
    parser.add_argument('--dockerfile-report', required=True, help="Path to Trivy Dockerfile scan report")
    parser.add_argument('--image-report', required=True, help="Path to Trivy image scan report")
    args = parser.parse_args()

    main(args.go_report, args.dockerfile_report, args.image_report)
