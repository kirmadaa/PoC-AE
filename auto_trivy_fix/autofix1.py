#!/usr/bin/env python3

import argparse
import json
import os
import re
import subprocess
import tempfile
import requests
from packaging import version

DOCKER_HUB_URL = "https://registry.hub.docker.com/v2/repositories/library/{image}/tags?page_size=100"

def run_cmd(cmd, show_output=False):
    print(f"Running command: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        print(f"Command failed with return code {result.returncode}")
        print(f"STDOUT: {result.stdout}")
        print(f"STDERR: {result.stderr}")
        result.check_returncode()  # This will raise the exception
    
    if show_output and result.stdout:
        print(result.stdout)
    
    return result.stdout.strip()

def scan_image(image):
    with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
        tmp_path = tmpfile.name
    run_cmd(["trivy", "image", "--no-progress", "-f", "json", "-o", tmp_path, image])
    with open(tmp_path) as f:
        report = json.load(f)
    os.remove(tmp_path)
    vulns = []
    for result in report.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            vulns.append(vuln)
    return vulns

def get_base_image_from_dockerfile(dockerfile_path):
    with open(dockerfile_path) as f:
        for line in f:
            if line.strip().startswith("FROM"):
                return line.strip().split()[1]
    return None

def fetch_newer_tags(image_name, current_tag):
    base_name = image_name.split(":")[0]
    
    # Handle case where current_tag might not be valid semver
    try:
        current_version = version.parse(current_tag)
    except version.InvalidVersion:
        print(f"Warning: Current tag '{current_tag}' is not a valid version, skipping version comparison")
        return []
    
    try:
        resp = requests.get(DOCKER_HUB_URL.format(image=base_name))
        resp.raise_for_status()
        tags_data = resp.json()
    except requests.RequestException as e:
        print(f"Error fetching tags from Docker Hub: {e}")
        return []
    
    # Filter for version-like tags
    tags = []
    for t in tags_data["results"]:
        tag_name = t["name"]
        if re.match(r"^\d+(\.\d+){1,2}$", tag_name):
            try:
                version.parse(tag_name)  # Validate it's parseable
                tags.append(tag_name)
            except version.InvalidVersion:
                continue
    
    if not tags:
        print("No valid version tags found")
        return []
    
    tags_sorted = sorted(tags, key=version.parse)
    newer_tags = [t for t in tags_sorted if version.parse(t) > current_version]
    return newer_tags[-10:]  # last 10 newest versions

def count_high_critical(vulns):
    return sum(1 for v in vulns if v["Severity"] in ("HIGH", "CRITICAL"))

def update_dockerfile_base_image(dockerfile_path, new_tag):
    with open(dockerfile_path, "r") as f:
        lines = f.readlines()
    
    # Create backup
    backup_path = dockerfile_path + ".backup"
    with open(backup_path, "w") as f:
        f.writelines(lines)
    print(f"Created backup: {backup_path}")
    
    with open(dockerfile_path, "w") as f:
        for line in lines:
            if line.strip().startswith("FROM"):
                parts = line.strip().split(":")
                if len(parts) >= 2:
                    f.write(f"{parts[0]}:{new_tag}\n")
                else:
                    # Handle case where there might not be a tag
                    f.write(f"{parts[0]}:{new_tag}\n")
            else:
                f.write(line)

def generate_report_json_md(report_data, json_path, md_path):
    with open(json_path, "w") as jf:
        json.dump(report_data, jf, indent=2)
    with open(md_path, "w") as mf:
        mf.write("# AutoFix Vulnerability Report\n\n")
        mf.write(f"**Base Image Before:** {report_data['base_image_before']}\n\n")
        mf.write(f"**Base Image After:** {report_data['base_image_after']}\n\n")
        mf.write(f"**Vulnerabilities Fixed:** {report_data['fixed_count']}\n\n")
        mf.write(f"**Remaining Vulnerabilities:** {report_data['remaining_count']}\n\n")
        mf.write("## Details\n")
        mf.write("### Fixed:\n")
        for f in report_data["fixed_vulns"]:
            mf.write(f"- {f}\n")
        mf.write("\n### Remaining:\n")
        for r in report_data["remaining_vulns"]:
            mf.write(f"- {r}\n")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--dockerfile", required=True)
    parser.add_argument("--build-context", required=True)
    parser.add_argument("--output-json", required=True)
    parser.add_argument("--output-md", required=True)
    args = parser.parse_args()

    # Verify files exist
    if not os.path.exists(args.dockerfile):
        print(f"Error: Dockerfile not found at {args.dockerfile}")
        return 1
    
    if not os.path.exists(args.build_context):
        print(f"Error: Build context not found at {args.build_context}")
        return 1

    print(f"==> Starting vulnerability scan for image: {args.image}")
    initial_vulns = scan_image(args.image)
    initial_count = count_high_critical(initial_vulns)
    print(f"Initial HIGH/CRITICAL vulnerabilities: {initial_count}")

    base_image = get_base_image_from_dockerfile(args.dockerfile)
    if not base_image or ":" not in base_image:
        print(f"Error: Could not parse base image from Dockerfile: {base_image}")
        return 1
    
    base_name, current_tag = base_image.split(":", 1)
    print(f"Base image detected: {base_image}")

    newer_tags = fetch_newer_tags(base_name, current_tag)
    print(f"Found newer tags: {newer_tags}")

    best_tag = current_tag
    best_vulns = initial_count
    best_vuln_list = initial_vulns

    for tag in newer_tags:
        test_image = f"{base_name}:{tag}"
        print(f"Testing tag: {tag}")
        try:
            vulns = scan_image(test_image)
            count = count_high_critical(vulns)
            print(f"Tag {tag} HIGH/CRITICAL: {count}")
            if count < best_vulns:
                best_tag = tag
                best_vulns = count
                best_vuln_list = vulns
                if count == 0:
                    print(f"Perfect tag found: {tag}")
                    break
        except subprocess.CalledProcessError:
            print(f"Failed to scan {test_image}, skipping...")
            continue

    if best_tag != current_tag:
        print(f"Updating Dockerfile base image {current_tag} -> {best_tag}")
        update_dockerfile_base_image(args.dockerfile, best_tag)
    else:
        print("No better tag found, keeping original base image")

    # Build the updated image
    print(f"Building updated image...")
    try:
        run_cmd(["docker", "build", "-f", args.dockerfile, "-t", f"{args.image}-auto-fixed", args.build_context], show_output=True)
    except subprocess.CalledProcessError as e:
        print(f"Docker build failed. Please check your Dockerfile and build context.")
        # Restore backup if we made changes
        if best_tag != current_tag:
            backup_path = args.dockerfile + ".backup"
            if os.path.exists(backup_path):
                print(f"Restoring original Dockerfile from backup")
                with open(backup_path, "r") as f:
                    content = f.read()
                with open(args.dockerfile, "w") as f:
                    f.write(content)
        return 1

    final_vulns = scan_image(f"{args.image}-auto-fixed")
    final_count = count_high_critical(final_vulns)

    fixed = set(v["VulnerabilityID"] for v in initial_vulns) - set(v["VulnerabilityID"] for v in final_vulns)
    remaining = set(v["VulnerabilityID"] for v in final_vulns)

    report_data = {
        "base_image_before": base_image,
        "base_image_after": f"{base_name}:{best_tag}",
        "fixed_count": len(fixed),
        "remaining_count": len(remaining),
        "fixed_vulns": list(fixed),
        "remaining_vulns": list(remaining)
    }

    generate_report_json_md(report_data, args.output_json, args.output_md)
    print("Reports generated.")
    print(f"Summary: Fixed {len(fixed)} vulnerabilities, {len(remaining)} remaining")
    
    return 0

if __name__ == "__main__":
    exit(main())