import json
import os
import subprocess
import sys
import re
import argparse
import logging
from collections import defaultdict

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def send_slack_notification(message):
    """Sends a notification to Slack."""
    slack_webhook_url = os.environ.get('SLACK_WEBHOOK_URL')
    if not slack_webhook_url:
        logging.warning("SLACK_WEBHOOK_URL environment variable not set. Skipping Slack notification.")
        return

    try:
        # Assuming 'requests' is installed by the workflow
        import requests
        response = requests.post(
            slack_webhook_url,
            json={'text': message},
            headers={'Content-Type': 'application/json'}
        )
        response.raise_for_status()
        logging.info("Slack notification sent successfully.")
    except ImportError:
        logging.error("Requests library not found. Cannot send Slack notification.")
    except requests.exceptions.RequestException as e:
        logging.error(f"Error sending Slack notification: {e}")

def load_trivy_report(file_path):
    """Loads and returns Trivy JSON report results."""
    if not os.path.exists(file_path):
        logging.warning(f"Trivy report file not found: {file_path}")
        return []
    try:
        with open(file_path, 'r') as f:
            report = json.load(f)
        return report.get('Results', [])
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON from {file_path}: {e}")
        return []

def get_component_root(file_path):
    """
    Determines the root directory of a component based on a file path.
    This helps group vulnerabilities to a single application/module.
    For image scans, target might be the image name.
    """
    if "go.mod" in file_path or "Dockerfile" in file_path:
        return os.path.dirname(file_path)
    # For image scan results, the 'Target' will be the image name (e.g., "golang:1.22.0-alpine")
    # For this PoC, we'll map image scan results to the Dockerfile's directory, assuming one-to-one
    return "." # Default to current directory if unsure, assuming single app in repo for PoC

def prioritize_vulnerabilities(results, severity_threshold='HIGH'):
    """
    Filters and prioritizes vulnerabilities based on severity and fix availability.
    Returns a dict mapping component_root -> list of prioritized vulns.
    """
    prioritized = defaultdict(list)
    severity_order = {'CRITICAL': 5, 'HIGH': 4, 'MEDIUM': 3, 'LOW': 2, 'UNKNOWN': 1}

    for result in results:
        # For image scans, result['Target'] is the image name, which we map to the app directory
        target_path = result.get('Target', '.')
        component_root = get_component_root(target_path)
        
        # Process vulnerabilities (OS packages, language libraries)
        for vuln in result.get('Vulnerabilities', []):
            severity = vuln.get('Severity', 'UNKNOWN').upper()
            if severity_order.get(severity, 0) >= severity_order.get(severity_threshold.upper(), 0):
                if vuln.get('FixedVersion'): # Only consider if a fix is available
                    vuln['component_root'] = component_root # Add for easier grouping later
                    prioritized[component_root].append(vuln)
        
        # Process misconfigurations (e.g., from Dockerfile, IaC)
        for misconfig in result.get('Misconfigurations', []):
            severity = misconfig.get('Severity', 'UNKNOWN').upper()
            if severity_order.get(severity, 0) >= severity_order.get(severity_threshold.upper(), 0):
                # Misconfigurations might not have 'FixedVersion' but indicate a policy violation
                misconfig['component_root'] = component_root
                misconfig['type'] = 'Misconfiguration' # Distinguish from vulns
                prioritized[component_root].append(misconfig)

    # Sort vulnerabilities/misconfigs for consistent processing
    for root in prioritized:
        prioritized[root].sort(key=lambda v: severity_order.get(v.get('Severity', 'UNKNOWN').upper(), 0), reverse=True)
    return prioritized

# --- Remediation Functions (similar to previous, but now accepting 'component_root') ---

def remediate_go_mod(component_root, vulnerabilities, summary_list):
    """Remediates Go module vulnerabilities."""
    go_mod_path = os.path.join(component_root, "go.mod")
    if not os.path.exists(go_mod_path):
        logging.info(f"Skipping Go module remediation for {component_root}: go.mod not found.")
        return

    logging.info(f"Attempting to fix Go vulnerabilities in {go_mod_path}...")
    changes_made = False
    
    for vuln in vulnerabilities:
        pkg_name = vuln.get('PkgName')
        fixed_version = vuln.get('FixedVersion')
        vuln_id = vuln.get('VulnerabilityID')
        if pkg_name and fixed_version:
            logging.info(f"  - Upgrading Go module: {pkg_name} to {fixed_version} (CVE: {vuln_id})")
            try:
                subprocess.run(['go', 'get', f'{pkg_name}@{fixed_version}'], 
                               cwd=component_root, check=True, capture_output=True, text=True)
                summary_list.append(f"- Go module `{pkg_name}` upgraded to `{fixed_version}` (CVE: {vuln_id})")
                changes_made = True
            except subprocess.CalledProcessError as e:
                logging.error(f"  Error upgrading Go module {pkg_name}: {e.stderr.strip()}")
                summary_list.append(f"- Failed to upgrade Go module `{pkg_name}` (CVE: {vuln_id}): {e.stderr.strip()}")
            except Exception as e:
                logging.error(f"  Unexpected error during Go module remediation: {e}")
                summary_list.append(f"- Unexpected error for Go module `{pkg_name}` (CVE: {vuln_id}): {e}")
    
    if changes_made:
        logging.info("  - Running go mod tidy to clean up dependencies...")
        try:
            subprocess.run(['go', 'mod', 'tidy'], 
                           cwd=component_root, check=True, capture_output=True, text=True)
            summary_list.append("- `go.mod` and `go.sum` tidied.")
        except subprocess.CalledProcessError as e:
            logging.error(f"  Error running go mod tidy: {e.stderr.strip()}")
            summary_list.append(f"- Failed to run `go mod tidy`: {e.stderr.strip()}")

def remediate_dockerfile(component_root, vulnerabilities, summary_list):
    """Remediates Dockerfile misconfigurations and base image vulnerabilities."""
    dockerfile_path = os.path.join(component_root, "Dockerfile")
    if not os.path.exists(dockerfile_path):
        logging.info(f"Skipping Dockerfile remediation for {component_root}: Dockerfile not found.")
        return

    logging.info(f"Attempting to fix Dockerfile issues in {dockerfile_path}...")
    
    try:
        with open(dockerfile_path, 'r') as f:
            lines = f.readlines()

        new_lines = []
        changes_made = False
        has_user_instruction = False
        has_user_creation_run = False
        from_line_index = -1

        for i, line in enumerate(lines):
            # Check for USER instruction
            if re.match(r'^\s*USER\s+\S+\s*$', line, re.IGNORECASE):
                has_user_instruction = True
            
            # Check for user creation RUN instruction
            if re.match(r'^\s*RUN\s+.*(?:useradd|adduser|groupadd).*$', line, re.IGNORECASE):
                has_user_creation_run = True

            # Find FROM instruction index for potential base image update
            if re.match(r'^\s*FROM\s+([^:]+):(.+)\s*$', line, re.IGNORECASE) and from_line_index == -1:
                from_line_index = i
            
            new_lines.append(line)

        # 1. Add non-root user if not present (simple heuristic)
        if not has_user_instruction and not has_user_creation_run:
            logging.info("  - Adding non-root user and setting USER instruction...")
            insert_idx = len(new_lines)
            for i, line in enumerate(reversed(new_lines)):
                if line.strip().upper().startswith(('EXPOSE', 'CMD', 'ENTRYPOINT')):
                    insert_idx = len(new_lines) - 1 - i
                    break
            
            user_creation_script = (
                "RUN addgroup --system appuser && adduser --system --ingroup appuser appuser\n"
                "USER appuser\n"
            )
            new_lines.insert(insert_idx, user_creation_script)
            summary_list.append("- Added non-root user (`appuser`) and set `USER` instruction in Dockerfile.")
            changes_made = True
        
        # 2. Address base image vulnerabilities (more robust detection, still suggests manual fix)
        # This iterates over vulnerabilities that affect OS packages, implying a vulnerable base image.
        for vuln in vulnerabilities:
            if vuln.get('Type') == 'OS' and from_line_index != -1:
                base_image_line = new_lines[from_line_index]
                match = re.match(r'^\s*FROM\s+([^:]+):(.+)\s*$', base_image_line, re.IGNORECASE)
                if match:
                    base_image_name = match.group(1)
                    base_image_tag = match.group(2)
                    # This remediation is still advisory for a PoC
                    summary_list.append(f"- Detected OS vulnerability in base image `{base_image_name}:{base_image_tag}` (CVE: {vuln.get('VulnerabilityID')}). Consider updating to a newer, patched tag.")
                    # A more advanced fix might involve looking up the latest stable tag of the base image.
        
        # 3. Address other misconfigurations reported by trivy config on Dockerfile
        for vuln in vulnerabilities: # This is a simple loop, in reality, filter by misconfig type
            if vuln.get('type') == 'Misconfiguration' and vuln.get('AVDID'):
                if vuln.get('AVDID') == 'AVD-DS-0002': # Example: Exposed sensitive port
                    summary_list.append(f"- Dockerfile misconfiguration: Exposed sensitive port (ID: {vuln.get('AVDID')}). Manual review recommended.")
                    # Direct fix: remove/modify EXPOSE line, but this is destructive and complex without YAML parsing.

        if changes_made:
            with open(dockerfile_path, 'w') as f:
                f.writelines(new_lines)
            logging.info(f"  - Dockerfile in {dockerfile_path} updated.")
        else:
            logging.info("  No Dockerfile changes applied by this script.")

    except Exception as e:
        logging.error(f"  Error remediating Dockerfile: {e}")
        summary_list.append(f"- Dockerfile remediation failed: {e}")

# --- Main Orchestration ---

def main():
    parser = argparse.ArgumentParser(description="Automated Vulnerability Remediation PoC Script.")
    parser.add_argument('--go-report', type=str, help='Path to Trivy Go module scan JSON report.')
    parser.add_argument('--dockerfile-report', type=str, help='Path to Trivy Dockerfile config scan JSON report.')
    parser.add_argument('--image-report', type=str, help='Path to Trivy image scan JSON report.')
    args = parser.parse_args()

    # Load reports
    go_results = load_trivy_report(args.go_report)
    dockerfile_results = load_trivy_report(args.dockerfile_report)
    image_results = load_trivy_report(args.image_report)

    # Combine all results for prioritization. Image results contain OS and language vulns.
    # Go and Dockerfile reports also have overlaps with image report, but also specific config/file findings.
    all_results = go_results + dockerfile_results + image_results

    # Prioritize vulnerabilities
    prioritized_vulns_by_component = prioritize_vulnerabilities(all_results, severity_threshold='MEDIUM')

    remediation_summary = []

    # Assuming all components are in the 'go-app-vulnerable' directory for this PoC
    # In a real pipeline, 'component_root' would be determined dynamically for each identified app.
    component_root = "go-app-vulnerable" # Fixed for this PoC's directory structure

    if component_root in prioritized_vulns_by_component:
        vulns_for_this_component = prioritized_vulns_by_component[component_root]
        
        # Filter for Go module vulnerabilities
        go_module_vulns = [v for v in vulns_for_this_component if v.get('Type') == 'Go-Module']
        if go_module_vulns:
            remediate_go_mod(component_root, go_module_vulns, remediation_summary)

        # Filter for Dockerfile misconfigurations AND OS/package vulns that hint at base image issues
        dockerfile_related_findings = [
            v for v in vulns_for_this_component 
            if v.get('Target', '').endswith('Dockerfile') or v.get('Type') == 'OS' or v.get('type') == 'Misconfiguration'
        ]
        if dockerfile_related_findings:
            remediate_dockerfile(component_root, dockerfile_related_findings, remediation_summary)

        # Add more remediation functions here as needed (e.g., Python, Ruby, IaC)

    # Write remediation summary for PR description
    summary_filepath = os.path.join(component_root, os.pardir, ".github", "autofix_summary_poc.txt")
    # Resolve the path relative to the current working directory of the script execution
    summary_filepath = os.path.abspath(summary_filepath)

    if remediation_summary:
        summary_content = "### Automated Fixes Applied:\n\n" + "\n".join(remediation_summary)
        logging.info(f"\n--- PoC Remediation Summary ---\n{summary_content}")
        with open(summary_filepath, 'w') as f:
            f.write(summary_content)
        send_slack_notification(f"PoC Vulnerability remediation attempt completed. Changes applied. See PR for details.\n\nSummary:\n{summary_content}")
    else:
        summary_content = "No automated remediation actions were taken for detected vulnerabilities."
        logging.info(f"\n--- PoC Remediation Summary ---\n{summary_content}")
        with open(summary_filepath, 'w') as f:
            f.write(summary_content)
        send_slack_notification("PoC Vulnerability remediation attempt completed. No automated fixes were applied.")

if __name__ == "__main__":
    main()