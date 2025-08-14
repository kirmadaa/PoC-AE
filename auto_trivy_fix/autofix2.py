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

def analyze_vulnerabilities(vulns):
    """Get detailed vulnerability breakdown"""
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for v in vulns:
        severity = v.get("Severity", "UNKNOWN")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    return severity_counts

def print_vulnerability_summary(tag, vulns):
    """Print detailed vulnerability summary for a tag"""
    counts = analyze_vulnerabilities(vulns)
    total = len(vulns)
    high_critical = counts["CRITICAL"] + counts["HIGH"]
    print(f"Tag {tag}:")
    print(f"  Total: {total} | HIGH/CRITICAL: {high_critical} | "
          f"Critical: {counts['CRITICAL']} | High: {counts['HIGH']} | "
          f"Medium: {counts['MEDIUM']} | Low: {counts['LOW']}")
    return high_critical, total

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

def create_clean_dockerfile(original_dockerfile, base_image):
    """Create a simplified Dockerfile with just the base image and essential commands"""
    with open(original_dockerfile, 'r') as f:
        lines = f.readlines()
    
    clean_lines = []
    for line in lines:
        line_stripped = line.strip()
        # Keep FROM, COPY, ADD, CMD, ENTRYPOINT, EXPOSE, WORKDIR, USER, VOLUME, LABEL
        if (line_stripped.startswith(('FROM', 'COPY', 'ADD', 'CMD', 'ENTRYPOINT', 
                                     'EXPOSE', 'WORKDIR', 'USER', 'VOLUME', 'LABEL')) or
            line_stripped == '' or line_stripped.startswith('#')):
            if line_stripped.startswith('FROM'):
                clean_lines.append(f"FROM {base_image}\n")
            else:
                clean_lines.append(line)
        # Skip RUN commands with package installations that might have version conflicts
        elif line_stripped.startswith('RUN') and ('apt-get install' in line_stripped or 'apk add' in line_stripped):
            print(f"Skipping potentially problematic package installation: {line_stripped[:80]}...")
            continue
        else:
            clean_lines.append(line)
    
    return clean_lines

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--dockerfile", required=True)
    parser.add_argument("--build-context", required=True)
    parser.add_argument("--output-json", required=True)
    parser.add_argument("--output-md", required=True)
    parser.add_argument("--clean-dockerfile", action="store_true", 
                       help="Remove problematic package installations from Dockerfile")
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
    print(f"Current image vulnerability summary:")
    print_vulnerability_summary("current", initial_vulns)

    base_image = get_base_image_from_dockerfile(args.dockerfile)
    if not base_image or ":" not in base_image:
        print(f"Error: Could not parse base image from Dockerfile: {base_image}")
        return 1
    
    base_name, current_tag = base_image.split(":", 1)
    print(f"Base image detected: {base_image}")

    # Check if the current tag exists by trying to scan it
    print(f"Verifying base image exists...")
    try:
        test_vulns = scan_image(base_image)
        print(f"Base image verified: {base_image}")
    except subprocess.CalledProcessError:
        print(f"Warning: Base image {base_image} not found. Trying 'latest' tag...")
        base_image = f"{base_name}:latest"
        current_tag = "latest"
        try:
            test_vulns = scan_image(base_image)
            print(f"Using fallback image: {base_image}")
        except subprocess.CalledProcessError:
            print(f"Error: Neither {base_name}:{current_tag} nor {base_name}:latest exist")
            return 1

    newer_tags = fetch_newer_tags(base_name, current_tag)
    print(f"Found newer tags: {newer_tags}")

    best_tag = current_tag
    best_vulns = initial_count
    best_vuln_list = initial_vulns
    best_total_vulns = len(initial_vulns)
    
    # Store results for all tags to make informed decision
    tag_results = []

    for tag in newer_tags:
        test_image = f"{base_name}:{tag}"
        print(f"Testing tag: {tag}")
        try:
            vulns = scan_image(test_image)
            high_critical_count, total_vulns = print_vulnerability_summary(tag, vulns)
            
            tag_results.append({
                'tag': tag,
                'high_critical': high_critical_count,
                'total_vulns': total_vulns,
                'vulns': vulns
            })
            
        except subprocess.CalledProcessError:
            print(f"Failed to scan {test_image}, skipping...")
            continue

    # Now analyze all results to pick the best tag
    if tag_results:
        print("\n==> Analyzing all tag results...")
        print(f"Current tag {current_tag} - HIGH/CRITICAL: {initial_count}, Total: {len(initial_vulns)}")
        
        # Sort by HIGH/CRITICAL first (ascending), then by total vulnerabilities (ascending)
        tag_results.sort(key=lambda x: (x['high_critical'], x['total_vulns']))
        
        print("\nRanked results (best to worst):")
        for i, result in enumerate(tag_results, 1):
            print(f"{i}. {result['tag']} - HIGH/CRITICAL: {result['high_critical']}, Total: {result['total_vulns']}")
        
        # Pick the best tag (first in sorted list)
        best_result = tag_results[0]
        if (best_result['high_critical'] < best_vulns or 
            (best_result['high_critical'] == best_vulns and best_result['total_vulns'] < best_total_vulns)):
            best_tag = best_result['tag']
            best_vulns = best_result['high_critical']
            best_vuln_list = best_result['vulns']
            best_total_vulns = best_result['total_vulns']
            print(f"\nSelected best tag: {best_tag}")
        else:
            print(f"\nCurrent tag {current_tag} is already optimal")
    else:
        print("No newer tags could be tested successfully")

    # Update the base image
    final_base_image = f"{base_name}:{best_tag}"
    if best_tag != current_tag:
        print(f"Updating Dockerfile base image {current_tag} -> {best_tag}")
    else:
        print("No better tag found, keeping original base image")

    # Create backup and potentially clean dockerfile
    backup_path = args.dockerfile + ".backup"
    with open(args.dockerfile, "r") as f:
        original_content = f.readlines()
    with open(backup_path, "w") as f:
        f.writelines(original_content)
    print(f"Created backup: {backup_path}")

    # Try building with the updated base image first
    update_dockerfile_base_image(args.dockerfile, best_tag)
    
    build_success = False
    dockerfile_attempts = []
    
    # Attempt 1: Try with just base image update
    print(f"Attempt 1: Building with updated base image...")
    try:
        run_cmd(["docker", "build", "-f", args.dockerfile, "-t", f"{args.image}-auto-fixed", args.build_context])
        build_success = True
        dockerfile_attempts.append("base_update")
    except subprocess.CalledProcessError:
        print("Build failed with updated base image. Trying clean dockerfile...")
        
        # Attempt 2: Try with cleaned dockerfile
        if args.clean_dockerfile:
            print(f"Attempt 2: Building with cleaned Dockerfile...")
            clean_lines = create_clean_dockerfile(args.dockerfile, final_base_image)
            with open(args.dockerfile, "w") as f:
                f.writelines(clean_lines)
            
            try:
                run_cmd(["docker", "build", "-f", args.dockerfile, "-t", f"{args.image}-auto-fixed", args.build_context])
                build_success = True
                dockerfile_attempts.append("cleaned")
            except subprocess.CalledProcessError:
                print("Build failed even with cleaned Dockerfile")

    if not build_success:
        print("All build attempts failed. Restoring original Dockerfile.")
        with open(backup_path, "r") as f:
            content = f.read()
        with open(args.dockerfile, "w") as f:
            f.write(content)
        
        print("\nSUGGESTIONS:")
        print("1. Your Dockerfile has hardcoded package versions that don't exist in the target base image")
        print("2. Try running with --clean-dockerfile to remove problematic package installations")
        print("3. Consider manually updating your Dockerfile to use compatible package versions")
        print("4. Check if your base image version (nginx:1.29.1) actually exists")
        return 1

    final_vulns = scan_image(f"{args.image}-auto-fixed")
    final_count = count_high_critical(final_vulns)

    fixed = set(v["VulnerabilityID"] for v in initial_vulns) - set(v["VulnerabilityID"] for v in final_vulns)
    remaining = set(v["VulnerabilityID"] for v in final_vulns)

    report_data = {
        "base_image_before": base_image,
        "base_image_after": final_base_image,
        "fixed_count": len(fixed),
        "remaining_count": len(remaining),
        "fixed_vulns": list(fixed),
        "remaining_vulns": list(remaining),
        "dockerfile_method": dockerfile_attempts
    }

    generate_report_json_md(report_data, args.output_json, args.output_md)
    print("Reports generated.")
    print(f"Summary: Fixed {len(fixed)} vulnerabilities, {len(remaining)} remaining")
    
    return 0

if __name__ == "__main__":
    exit(main())
