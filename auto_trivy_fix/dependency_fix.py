#!/usr/bin/env python3
import os
import json
import subprocess
from pathlib import Path
import re
from packaging.version import parse as vparse
from . import tools

def scan_dependencies(requirements_path: Path) -> list:
    """
    Scans the given requirements.txt file for vulnerabilities using pip-audit.
    """
    if not requirements_path.exists():
        print(f"[!] Requirements file not found: {requirements_path}")
        return []

    cmd = ["pip-audit", "-r", str(requirements_path), "--format", "json"]
    print(f"[*] Running command: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        # pip-audit returns a non-zero exit code if vulnerabilities are found
        pass

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        print(f"[!] Failed to parse pip-audit output as JSON.")
        print(f"[*] STDOUT: {result.stdout}")
        print(f"[*] STDERR: {result.stderr}")
        return []

def apply_fixes(requirements_path: Path, fixes: dict):
    """
    Applies the given fixes to the requirements.txt file.
    """
    lines = requirements_path.read_text().splitlines()
    new_lines = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            new_lines.append(line)
            continue

        pkg_name = line.split("==")[0].strip()
        if pkg_name in fixes:
            new_version = fixes[pkg_name]
            new_lines.append(f"{pkg_name}=={new_version}")
            print(f"[+] Fixed {pkg_name} to version {new_version}")
        else:
            new_lines.append(line)

    requirements_path.write_text("\n".join(new_lines) + "\n")

def generate_fixes(vulnerabilities: list) -> dict:
    """
    Generates a dictionary of the latest required versions to fix vulnerabilities.
    """
    potential_fixes = {}
    for vuln in vulnerabilities:
        pkg_name = vuln.get("name")
        fixed_versions = vuln.get("fixed_versions")

        if not pkg_name:
            continue

        # Initialize a list for the package if it's not already there
        potential_fixes.setdefault(pkg_name, [])

        if fixed_versions:
            # Sort versions to find the latest fix for *this* specific vulnerability
            latest_fix_for_vuln = sorted(fixed_versions, key=vparse, reverse=True)[0]
            potential_fixes[pkg_name].append(latest_fix_for_vuln)
        else:
            # If no fixed version is provided, search online
            print(f"[!] No fixed version found for {pkg_name}. Searching online...")
            query = f'"{vuln.get("id")}" {pkg_name} fix version'
            try:
                search_results = tools.google_search(query)
                if search_results:
                    first_url = search_results.split('\\n')[0] # Assumes newline-separated URLs
                    print(f"[*] Visiting: {first_url}")
                    website_content = tools.view_text_website(first_url)

                    # More robust regex to find versions like X.Y.Z
                    match = re.search(r'(?:fixed in|patched in|upgrade to|version)\s+v?(\d+\.\d+\.\d+)', website_content, re.IGNORECASE)
                    if match:
                        found_version = match.group(1)
                        print(f"[+] Found a potential fixed version: {found_version}")
                        potential_fixes[pkg_name].append(found_version)
                    else:
                        print("[-] Could not find a fixed version in the website content.")
            except Exception as e:
                print(f"[!] Error searching online for a fix for {pkg_name}: {e}")

    # Now, determine the absolute latest version required for each package
    final_fixes = {}
    for pkg_name, versions in potential_fixes.items():
        if versions:
            # Sort all collected versions for the package and pick the highest one
            latest_version = sorted(versions, key=vparse, reverse=True)[0]
            final_fixes[pkg_name] = latest_version

    return final_fixes

def main():
    # Get inputs from environment variables
    requirements_path = Path(os.environ.get("REQUIREMENTS_PATH", "auto_trivy_fix/example/app/requirements.txt"))

    print(f"[*] Starting dependency fix for: {requirements_path}")

    # 1. Scan dependencies
    print("[*] Scanning dependencies for vulnerabilities...")
    vulnerabilities = scan_dependencies(requirements_path)

    if not vulnerabilities:
        print("[+] No vulnerabilities found.")
        return

    print(f"[+] Found {len(vulnerabilities)} vulnerabilities.")

    # 2. Generate fixes
    print("[*] Generating fixes for vulnerabilities...")
    fixes = generate_fixes(vulnerabilities)

    if not fixes:
        print("[+] No fixes could be generated.")
        return

    print(f"[+] Generated {len(fixes)} fixes.")

    # 3. Apply fixes
    print("[*] Applying fixes to requirements.txt...")
    apply_fixes(requirements_path, fixes)

    print("[+] Dependency fix process completed.")

if __name__ == "__main__":
    main()
