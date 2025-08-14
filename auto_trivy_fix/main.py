#!/usr/bin/env python3
import json
import os
import re
import subprocess
import tempfile
import requests
import shutil
from pathlib import Path

# ===============================
# Utility functions
# ===============================
def run_cmd(cmd, check=True):
    print(f"[CMD] {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if check and result.returncode != 0:
        raise RuntimeError(result.stderr.strip())
    return result.stdout.strip()

def trivy_scan(image):
    with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
        tmp_path = tmpfile.name
    run_cmd(["trivy", "image", "--no-progress", "-f", "json", "-o", tmp_path, image])
    with open(tmp_path) as f:
        data = json.load(f)
    os.unlink(tmp_path)
    return data

def parse_base_image(dockerfile_path):
    with open(dockerfile_path) as f:
        for line in f:
            if line.strip().startswith("FROM"):
                parts = line.strip().split()
                if len(parts) > 1:
                    return parts[1]
    return None

# ===============================
# Docker Hub lookup
# ===============================
def get_latest_dockerhub_tag(image_name):
    """
    Fetch latest numeric tag for an official image from Docker Hub,
    picking highest semver without hanging on large tag lists.
    """
    namespace = "library"
    if "/" in image_name:
        namespace, image_name = image_name.split("/", 1)

    url = f"https://registry.hub.docker.com/v2/repositories/{namespace}/{image_name}/tags?page_size=100"
    numeric_tags = []
    seen_pages = 0

    while url and seen_pages < 5:  # Limit pagination to avoid hangs
        resp = requests.get(url, timeout=10).json()
        for t in resp.get("results", []):
            tag = t["name"]
            if re.match(r"^\d+(\.\d+)*$", tag):
                numeric_tags.append(tag)
        url = resp.get("next")
        seen_pages += 1

    if not numeric_tags:
        return None

    # Pick highest version numerically
    return sorted(
        numeric_tags, key=lambda s: list(map(int, s.split(".")))
    )[-1]

# ===============================
# Vulnerability check
# ===============================
def has_high_or_critical_vulns(report):
    for result in report.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            if vuln.get("Severity") in ("HIGH", "CRITICAL"):
                return True
    return False

# ===============================
# Main process
# ===============================
def main():
    image = os.environ.get("IMAGE", "nginx:latest")
    dockerfile = os.environ.get("DOCKERFILE", "Dockerfile")
    context = os.environ.get("BUILD_CONTEXT", ".")

    print(f"==> Scanning original image: {image}")
    initial_report = trivy_scan(image)

    if not has_high_or_critical_vulns(initial_report):
        print("✅ No HIGH/CRITICAL vulnerabilities found. No base image change needed.")
        return

    print("⚠️  HIGH/CRITICAL vulnerabilities detected in base image.")
    base_image = parse_base_image(dockerfile)
    if not base_image:
        print("❌ Could not detect base image from Dockerfile.")
        return

    base_name, _, base_tag = base_image.partition(":")
    base_tag = base_tag or "latest"

    print(f"Detected base image: {base_name}:{base_tag}")
    new_tag = get_latest_dockerhub_tag(base_name)

    if not new_tag:
        print("❌ Could not find a newer numeric tag on Docker Hub.")
        return

    print(f"🔄 Suggesting base image update to: {base_name}:{new_tag}")

    # Update Dockerfile
    patched_dockerfile = tempfile.mktemp(prefix="Dockerfile.auto_fix_")
    with open(dockerfile) as fin, open(patched_dockerfile, "w") as fout:
        for line in fin:
            if line.strip().startswith("FROM"):
                fout.write(f"FROM {base_name}:{new_tag}\n")
            else:
                fout.write(line)

    # Build new image
    new_image = f"{image}-auto-fixed"
    run_cmd(["docker", "build", "-f", patched_dockerfile, "-t", new_image, context])

    # Scan new image
    print(f"==> Scanning rebuilt image: {new_image}")
    new_report = trivy_scan(new_image)

    # Compare results
    initial_count = sum(len(r.get("Vulnerabilities", [])) for r in initial_report.get("Results", []))
    new_count = sum(len(r.get("Vulnerabilities", [])) for r in new_report.get("Results", []))

    print(f"📊 Initial vulnerabilities: {initial_count}")
    print(f"📊 After fix vulnerabilities: {new_count}")

    if not has_high_or_critical_vulns(new_report):
        print("✅ New base image has no HIGH/CRITICAL vulnerabilities.")
    else:
        print("⚠️  HIGH/CRITICAL vulnerabilities still remain after base image update.")

    # Save report
    final_report = {
        "original_image": image,
        "rebuilt_image": new_image,
        "initial_vuln_count": initial_count,
        "post_vuln_count": new_count,
    }
    with open("final_report.json", "w") as f:
        json.dump(final_report, f, indent=2)
    print("📝 Report saved to final_report.json")

if __name__ == "__main__":
    main()
