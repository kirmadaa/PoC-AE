#!/usr/bin/env python3
import os
import json
import subprocess
from pathlib import Path

def scan_dependencies(project_path: Path) -> dict:
    """
    Scans the given JavaScript project for vulnerabilities using npm audit.
    """
    if not (project_path / "package.json").exists():
        print(f"[!] package.json not found in: {project_path}")
        return {}

    cmd = ["npm", "audit", "--json"]
    print(f"[*] Running command: {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=project_path, capture_output=True, text=True)

    if result.returncode != 0:
        # npm audit returns a non-zero exit code if vulnerabilities are found
        pass

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        print(f"[!] Failed to parse npm audit output as JSON.")
        print(f"[*] STDOUT: {result.stdout}")
        print(f"[*] STDERR: {result.stderr}")
        return {}

def apply_fixes(project_path: Path, fixes: dict):
    """
    Applies the given fixes to the JavaScript project by running npm install.
    """
    for pkg_name, version in fixes.items():
        cmd = ["npm", "install", f"{pkg_name}@{version}"]
        print(f"[*] Running command: {' '.join(cmd)}")
        result = subprocess.run(cmd, cwd=project_path, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"[+] Fixed {pkg_name} to version {version}")
        else:
            print(f"[!] Failed to fix {pkg_name} to version {version}")
            print(f"[*] STDOUT: {result.stdout}")
            print(f"[*] STDERR: {result.stderr}")

def generate_fixes(vulnerabilities: dict) -> dict:
    """
    Generates a dictionary of fixes from a dictionary of vulnerabilities.
    """
    fixes = {}
    for name, vuln in vulnerabilities.items():
        if vuln.get("fixAvailable"):
            if isinstance(vuln["fixAvailable"], dict):
                fixes[name] = vuln["fixAvailable"]["version"]
            else:
                # If fixAvailable is just `true`, we'd need to find the version ourselves.
                # For now, we'll skip these.
                print(f"[!] Fix is available for {name}, but version is not specified. Skipping.")
    return fixes

def main():
    # Get inputs from environment variables
    project_path = Path(os.environ.get("PROJECT_PATH", "js_example"))

    print(f"[*] Starting JavaScript dependency fix for: {project_path}")

    # 1. Scan dependencies
    print("[*] Scanning dependencies for vulnerabilities...")
    vulnerabilities = scan_dependencies(project_path)

    if not vulnerabilities or not vulnerabilities.get("vulnerabilities"):
        print("[+] No vulnerabilities found.")
        return

    print(f"[+] Found {len(vulnerabilities.get('vulnerabilities', {}))} vulnerabilities.")

    # 2. Generate fixes
    print("[*] Generating fixes for vulnerabilities...")
    fixes = generate_fixes(vulnerabilities.get("vulnerabilities", {}))

    if not fixes:
        print("[+] No fixes could be generated.")
        return

    print(f"[+] Generated {len(fixes)} fixes.")

    # 3. Apply fixes
    print("[*] Applying fixes to project...")
    apply_fixes(project_path, fixes)

    print("[+] JavaScript dependency fix process completed.")

if __name__ == "__main__":
    main()
