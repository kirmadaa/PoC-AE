#!/usr/bin/env python3
import os
import json
from pathlib import Path
import subprocess
import tempfile
import re
from . import tools

from .trivy_helper import run_trivy_image, parse_trivy_json
from .dockerfile_patch import DockerfilePatcher
from .report_generator import generate_final_report

def find_fixes_online(vulns):
    """
    Tries to find fixes for vulnerabilities that don't have a `fixed_version`.
    """
    print("[*] Searching for fixes online for vulnerabilities without a fixed version...")
    for vuln in vulns:
        if not vuln.get("fixed_version"):
            pkg_name = vuln.get("pkg_name")
            installed_version = vuln.get("installed_version")
            vuln_id = vuln.get("vuln_id")

            query = f'"{vuln_id}" {pkg_name} {installed_version} fix'
            print(f"[*] Searching for: {query}")

            try:
                search_results = tools.google_search(query)

                if search_results:
                    # For simplicity, let's just check the first result
                    first_url = search_results.split('\\n')[0]
                    print(f"[*] Visiting: {first_url}")
                    website_content = tools.view_text_website(first_url)

                    # Look for a fixed version in the website content
                    # This is a very basic implementation and can be improved
                    match = re.search(r'(?:fixed in|patched in|upgrade to)\s+([\d\.]+)', website_content, re.IGNORECASE)
                    if match:
                        fixed_version = match.group(1)
                        print(f"[+] Found a potential fixed version: {fixed_version}")
                        vuln["fixed_version"] = fixed_version
                    else:
                        print("[-] Could not find a fixed version in the website content.")

            except Exception as e:
                print(f"[!] Error searching online for a fix for {vuln_id}: {e}")

    return vulns

def main():
    # Get inputs from environment variables
    image_name = os.environ.get("IMAGE_NAME", "python:3.9-slim")
    dockerfile_path = Path(os.environ.get("DOCKERFILE_PATH", "auto_trivy_fix/example/Dockerfile"))
    build_context = os.environ.get("BUILD_CONTEXT", str(dockerfile_path.parent))

    print(f"[*] Starting autofix for image: {image_name}")
    print(f"[*] Dockerfile: {dockerfile_path}")
    print(f"[*] Build context: {build_context}")

    # 1. Initial scan
    print("[*] Running initial Trivy scan...")
    initial_report_json = run_trivy_image(image_name)
    initial_vulns = parse_trivy_json(initial_report_json)
    print(f"[+] Found {len(initial_vulns)} initial vulnerabilities.")

    if not initial_vulns:
        print("[+] No vulnerabilities found. Exiting.")
        return

    # 2. Find fixes online for vulnerabilities without a fixed version
    initial_vulns = find_fixes_online(initial_vulns)

    # 3. Attempt to patch Dockerfile
    print("[*] Attempting to patch Dockerfile...")
    patcher = DockerfilePatcher(dockerfile_path, Path(tempfile.gettempdir()))
    patch_result = patcher.attempt_patch(initial_vulns)

    if not patch_result.get("patched_dockerfile"):
        print("[+] No patches could be applied. Exiting.")
        # TODO: Generate a report even if no patches are applied
        return

    patched_dockerfile_path = Path(patch_result["patched_dockerfile"])
    print(f"[+] Dockerfile patched successfully: {patched_dockerfile_path}")

    # 3. Rebuild the image with the patched Dockerfile
    rebuilt_image_name = f"{image_name}-autofixed"
    print(f"[*] Rebuilding image as: {rebuilt_image_name}")
    try:
        subprocess.run(
            [
                "docker", "build",
                "-t", rebuilt_image_name,
                "-f", str(patched_dockerfile_path),
                build_context
            ],
            check=True,
            capture_output=True,
            text=True
        )
    except subprocess.CalledProcessError as e:
        print(f"[!] Docker build failed:\n{e.stderr}")
        return

    print("[+] Image rebuilt successfully.")

    # 4. Scan the rebuilt image
    print("[*] Running Trivy scan on the rebuilt image...")
    post_fix_report_json = run_trivy_image(rebuilt_image_name)
    post_fix_vulns = parse_trivy_json(post_fix_report_json)
    print(f"[+] Found {len(post_fix_vulns)} vulnerabilities in the rebuilt image.")

    # 5. Generate the final report
    print("[*] Generating final report...")
    final_report = generate_final_report(
        original_image=image_name,
        rebuilt_image=rebuilt_image_name,
        initial_vulns=initial_vulns,
        post_vulns=post_fix_vulns,
        actions=patch_result.get("actions", [])
    )

    report_path = Path("final_report.json")
    with open(report_path, "w") as f:
        json.dump(final_report, f, indent=2)

    print(f"[+] Final report saved to: {report_path}")

if __name__ == "__main__":
    main()
