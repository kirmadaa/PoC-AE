import json
import argparse
import os
import re
import subprocess
from collections import defaultdict

def parse_args():
    parser = argparse.ArgumentParser(description='Automated Vulnerability Remediation')
    parser.add_argument('--go-report', help='Trivy filesystem scan report')
    parser.add_argument('--docker-report', help='Trivy Dockerfile scan report')
    parser.add_argument('--image-report', help='Trivy container image scan report')
    return parser.parse_args()

def update_go_mod(vulns):
    """Update go.mod with fixed package versions"""
    if not os.path.exists('go.mod') or not vulns:
        return False

    updated = False
    with open('go.mod', 'r') as f:
        lines = f.readlines()

    # Group fixes by package (keep highest fixed version)
    fix_map = {}
    for vuln in vulns:
        pkg = vuln['PkgName']
        fixed_ver = vuln.get('FixedVersion', '')
        if fixed_ver and (pkg not in fix_map or fixed_ver > fix_map[pkg]):
            fix_map[pkg] = fixed_ver

    # Update require lines
    for i, line in enumerate(lines):
        if line.startswith('require'):
            for pkg, fixed_ver in fix_map.items():
                if pkg in line:
                    # Preserve comment if exists
                    if '//' in line:
                        comment = line.split('//')[1]
                        lines[i] = f"require {pkg} {fixed_ver} //{comment}"
                    else:
                        lines[i] = f"require {pkg} {fixed_ver}\n"
                    updated = True

    if updated:
        with open('go.mod', 'w') as f:
            f.writelines(lines)
    return updated

def update_dockerfile(vulns):
    """Update Dockerfile base image based on recommendations"""
    if not os.path.exists('Dockerfile') or not vulns:
        return False

    # Find base image update recommendations
    base_image_updates = []
    for vuln in vulns:
        if vuln.get('ID') == 'DS002' and 'update to' in vuln.get('Resolution', ''):
            base_image_updates.append(vuln)

    if not base_image_updates:
        return False

    # Get highest recommended version
    best_update = max(base_image_updates, 
                     key=lambda x: x['CauseMetadata']['StartLine'])
    new_image = best_update['Resolution'].split()[-1]

    with open('Dockerfile', 'r') as f:
        lines = f.readlines()

    # Update base image in Dockerfile
    updated = False
    for i, line in enumerate(lines):
        if line.strip().startswith('FROM'):
            parts = line.split()
            if len(parts) > 1:
                lines[i] = f"FROM {new_image}\n"
                updated = True
                break

    if updated:
        with open('Dockerfile', 'w') as f:
            f.writelines(lines)
    return updated

def generate_report(go_fixes, docker_fix, unfixed):
    """Generate markdown remediation report"""
    report = "# Vulnerability Remediation Report\n\n"
    
    if go_fixes or docker_fix:
        report += "## ✅ Fixed Vulnerabilities\n\n"
        if docker_fix:
            report += f"### Docker Base Image Updated\n- **New Image**: {docker_fix}\n\n"
        if go_fixes:
            report += "### Go Package Updates\n| Package | Fixed Version |\n| ------- | ------------- |\n"
            for pkg, ver in go_fixes.items():
                report += f"| {pkg} | {ver} |\n"
            report += "\n"
    
    if unfixed:
        report += "## ⚠️ Unfixed Vulnerabilities (Require Manual Review)\n"
        report += "| Vulnerability ID | Package | Severity |\n"
        report += "| ----------------- | ------- | -------- |\n"
        for vuln in unfixed:
            report += f"| {vuln['VulnerabilityID']} | {vuln['PkgName']} | {vuln['Severity']} |\n"
    else:
        report += "\nAll vulnerabilities with available fixes were remediated!\n"
    
    with open('remediation-report.md', 'w') as f:
        f.write(report)

def main():
    args = parse_args()
    go_vulns = []
    docker_vulns = []
    unfixed = []
    docker_fix = None
    go_fixes = {}

    # Process Go vulnerabilities
    if args.go_report and os.path.exists(args.go_report):
        with open(args.go_report) as f:
            data = json.load(f)
        for result in data.get('Results', []):
            if result.get('Target') == 'go.mod':
                for vuln in result.get('Vulnerabilities', []):
                    if vuln.get('FixedVersion'):
                        go_vulns.append(vuln)
                    else:
                        unfixed.append(vuln)

    # Process Docker vulnerabilities
    if args.docker_report and os.path.exists(args.docker_report):
        with open(args.docker_report) as f:
            data = json.load(f)
        for result in data.get('Results', []):
            if result.get('Target') == 'Dockerfile':
                docker_vulns = result.get('Misconfigurations', [])

    # Process Image vulnerabilities
    if args.image_report and os.path.exists(args.image_report):
        with open(args.image_report) as f:
            data = json.load(f)
        for result in data.get('Results', []):
            if result.get('Class') == 'os-pkgs':
                for vuln in result.get('Vulnerabilities', []):
                    if not vuln.get('FixedVersion'):
                        unfixed.append(vuln)

    # Apply remediations
    go_updated = update_go_mod(go_vulns)
    docker_updated = update_dockerfile(docker_vulns)

    # Capture fixes for report
    if docker_updated:
        with open('Dockerfile') as f:
            for line in f:
                if line.startswith('FROM'):
                    docker_fix = line.split()[1]
                    break
    
    if go_updated:
        for vuln in go_vulns:
            go_fixes[vuln['PkgName']] = vuln['FixedVersion']

    # Generate report
    generate_report(go_fixes, docker_fix, unfixed)

    # Exit code for commit action
    if go_updated or docker_updated:
        print("Changes made. Triggering commit...")
    else:
        print("No vulnerabilities required automated fixes")

if __name__ == '__main__':
    main()