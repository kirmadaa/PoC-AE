import json
import os
import subprocess
import sys
import re
import requests # For Slack notification, if enabled

def send_slack_notification(message):
    """Sends a notification to Slack."""
    slack_webhook_url = os.environ.get('SLACK_WEBHOOK_URL')
    if not slack_webhook_url:
        # print("SLACK_WEBHOOK_URL environment variable not set. Skipping Slack notification.", file=sys.stderr)
        return # Do not fail the script if Slack is not configured

    try:
        response = requests.post(
            slack_webhook_url,
            json={'text': message},
            headers={'Content-Type': 'application/json'}
        )
        response.raise_for_status()
        print("Slack notification sent successfully.")
    except requests.exceptions.RequestException as e:
        print(f"Error sending Slack notification: {e}", file=sys.stderr)

def parse_trivy_report(report_path):
    """Parses Trivy JSON report."""
    try:
        with open(report_path, 'r') as f:
            report = json.load(f)
        return report.get('Results', [])
    except FileNotFoundError:
        print(f"Warning: Trivy report not found at {report_path}", file=sys.stderr)
        return []
    except json.JSONDecodeError:
        print(f"Error: Could not decode JSON from {report_path}", file=sys.stderr)
        return []

def remediate_go_mod(report_results, summary_list):
    """Attempts to remediate Go module vulnerabilities."""
    go_mod_path = "go-app-vulnerable/go.mod"
    if not os.path.exists(go_mod_path):
        print(f"Skipping Go module remediation: {go_mod_path} not found.")
        return

    print(f"Attempting to fix Go vulnerabilities in {go_mod_path}...")
    
    found_vulnerabilities = False
    for result in report_results:
        if result.get('Type') == 'Go-Module':
            for vuln in result.get('Vulnerabilities', []):
                if vuln.get('FixedVersion'):
                    pkg_name = vuln.get('PkgName')
                    fixed_version = vuln.get('FixedVersion')
                    vuln_id = vuln.get('VulnerabilityID')
                    
                    # For POC, we'll target 'gin' if it's found as vulnerable, and try to upgrade
                    # In a real scenario, you'd iterate and upgrade each specific vulnerable package
                    if pkg_name == "github.com/gin-gonic/gin":
                        print(f"  - Detected vulnerable Go module: {pkg_name} (CVE: {vuln_id}). Attempting to upgrade to {fixed_version}...")
                        try:
                            # Use `go get -u` for simple upgrade or specific version
                            # For fixed_version, `go get <pkg>@<version>`
                            subprocess.run(['go', 'get', f'{pkg_name}@{fixed_version}'], 
                                           cwd=os.path.dirname(go_mod_path), check=True)
                            subprocess.run(['go', 'mod', 'tidy'], 
                                           cwd=os.path.dirname(go_mod_path), check=True)
                            summary_list.append(f"- Go module `{pkg_name}` upgraded to `{fixed_version}` (CVE: {vuln_id})")
                            found_vulnerabilities = True
                        except subprocess.CalledProcessError as e:
                            print(f"  Error upgrading Go module {pkg_name}: {e}", file=sys.stderr)
                            summary_list.append(f"- Failed to upgrade Go module `{pkg_name}` (CVE: {vuln_id}): {e}")
                        except Exception as e:
                            print(f"  Unexpected error during Go module remediation: {e}", file=sys.stderr)
                            summary_list.append(f"- Unexpected error for Go module `{pkg_name}` (CVE: {vuln_id}): {e}")
    
    if not found_vulnerabilities:
        print("  No upgradeable Go vulnerabilities found in the report for specified modules.")

def remediate_dockerfile(report_results, summary_list):
    """Attempts to remediate Dockerfile misconfigurations/base image vulns."""
    dockerfile_path = "go-app-vulnerable/Dockerfile"
    if not os.path.exists(dockerfile_path):
        print(f"Skipping Dockerfile remediation: {dockerfile_path} not found.")
        return

    print(f"Attempting to fix Dockerfile issues in {dockerfile_path}...")
    
    made_changes = False
    new_lines = []
    
    try:
        with open(dockerfile_path, 'r') as f:
            lines = f.readlines()

        has_user_instruction = False
        has_user_creation = False

        for line in lines:
            # Check for existing USER instruction
            if re.match(r'^\s*USER\s+\S+\s*$', line, re.IGNORECASE):
                has_user_instruction = True

            # Simple heuristic for user creation (can be more robust)
            if re.match(r'^\s*RUN\s+.*useradd', line, re.IGNORECASE):
                has_user_creation = True
            
            new_lines.append(line)

        # POC: Add non-root user if not explicitly set
        if not has_user_instruction and not has_user_creation:
            # Insert before CMD or EXPOSE for best practice, or just at the end for POC
            insert_index = -1
            for i, line in enumerate(reversed(new_lines)):
                if line.strip().startswith('EXPOSE') or line.strip().startswith('CMD'):
                    insert_index = len(new_lines) - 1 - i
                    break
            if insert_index == -1: # If no EXPOSE/CMD, add at end
                insert_index = len(new_lines)

            print("  - Adding non-root user and setting USER instruction...")
            user_creation_lines = [
                "# Add non-root user for security\n",
                "RUN groupadd -r appuser && useradd --no-log-init -r -g appuser appuser\n",
                "USER appuser\n"
            ]
            new_lines[insert_index:insert_index] = user_creation_lines
            summary_list.append("- Added non-root user (`appuser`) and set `USER` instruction in Dockerfile.")
            made_changes = True
        
        # Example: Check for `FROM` instruction for base image vulnerability
        for result in report_results:
            if result.get('Type') == 'alpine' or result.get('Type') == 'debian': # Example OS types
                for vuln in result.get('Vulnerabilities', []):
                    if vuln.get('VulnerabilityID'):
                        print(f"  - Detected OS vulnerability (e.g., {vuln.get('VulnerabilityID')}) in base image. "
                              "Consider updating `FROM` line to a newer base image version if available.")
                        summary_list.append(f"- Detected potential OS vulnerability (e.g., {vuln.get('VulnerabilityID')}) in Dockerfile's base image. Manual review recommended for a newer base image.")
                        # This part doesn't modify the Dockerfile as it's complex to auto-select new base images
                        # but alerts the user.

        if made_changes:
            with open(dockerfile_path, 'w') as f:
                f.writelines(new_lines)
            print(f"  - Dockerfile in {dockerfile_path} updated.")
        else:
            print("  No Dockerfile changes needed for this PoC.")

    except Exception as e:
        print(f"  Error remediating Dockerfile: {e}", file=sys.stderr)
        summary_list.append(f"- Dockerfile remediation failed: {e}")


def main():
    if len(sys.argv) < 3:
        print("Usage: python remediate_vulnerabilities_poc.py <trivy_go_report.json> <trivy_dockerfile_report.json>", file=sys.stderr)
        sys.exit(1)

    go_report_path = sys.argv[1]
    dockerfile_report_path = sys.argv[2]

    go_vulns_results = parse_trivy_report(go_report_path)
    dockerfile_vulns_results = parse_trivy_report(dockerfile_report_path)

    remediation_actions_taken = []
    
    # Prioritize and remediate
    remediate_go_mod(go_vulns_results, remediation_actions_taken)
    remediate_dockerfile(dockerfile_vulns_results, remediation_actions_taken)

    if remediation_actions_taken:
        print("\n--- PoC Remediation Summary ---")
        summary_text = "Automated Fixes Applied:\n" + "\n".join(remediation_actions_taken)
        print(summary_text)
        with open('.github/autofix_summary_poc.txt', 'w') as f:
            f.write(summary_text)
        send_slack_notification(f"PoC Vulnerability remediation attempt completed. Changes applied. See PR for details.\n\nSummary:\n{summary_text}")
    else:
        print("\nNo automated remediation actions were taken for this PoC.")
        with open('.github/autofix_summary_poc.txt', 'w') as f:
            f.write("No automated remediation actions were taken for this PoC.")
        send_slack_notification("PoC Vulnerability remediation attempt completed. No automated fixes were applied.")

if __name__ == "__main__":
    main()