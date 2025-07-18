import json
import os
import logging
import argparse
from collections import defaultdict
import subprocess

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(message)s')

def load_report(path):
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except Exception as e:
        logging.error(f"Failed to load {path}: {e}")
        return {"Results": []}

def group_vulnerabilities_by_component(report):
    """
    - If this report has any Results whose Target endswith go.mod,
      collect *all* vulns/misconfigs into the go-mod directory.
    - Else if any Target endswith Dockerfile, collect *all* into that
      Dockerfile directory.
    - Otherwise (image scan), lump into '.'.
    """
    results = report.get("Results", [])
    all_items = []
    for r in results:
        all_items.extend(r.get("Vulnerabilities", []) + r.get("Misconfigurations", []))

    # 1) Go-mod scan?
    for r in results:
        tgt = r.get("Target", "")
        if tgt.endswith("go.mod"):
            comp = os.path.dirname(tgt) or "."
            comp = os.path.relpath(comp, os.getcwd())
            return { comp: all_items }

    # 2) Dockerfile scan?
    for r in results:
        tgt = r.get("Target", "")
        if tgt.endswith("Dockerfile"):
            comp = os.path.dirname(tgt) or "."
            comp = os.path.relpath(comp, os.getcwd())
            return { comp: all_items }

    # 3) Everything else → image scan
    return { ".": all_items }


def remediate_go_mod(component_root, vulns):
    logging.info(f"\n[Go Module Remediation] Component: {component_root}")
    go_mod = os.path.join(component_root, "go.mod")
    if not os.path.exists(go_mod):
        logging.warning(f"go.mod not found in {component_root}")
        return

    did_fix = False
    for v in vulns:
        if v.get("Type", "").lower() != "gomod":
            continue
        pkg = v.get("PkgName")
        fixed = v.get("FixedVersion")
        if pkg and fixed:
            logging.info(f"→ Upgrading {pkg} to {fixed}")
            try:
                subprocess.run(["go", "get", f"{pkg}@{fixed}"],
                               cwd=component_root, check=True)
                did_fix = True
            except subprocess.CalledProcessError as e:
                logging.error(f"Failed to go get {pkg}@{fixed}: {e}")

    if did_fix:
        subprocess.run(["go", "mod", "tidy"], cwd=component_root, check=False)


def remediate_dockerfile(component_root, vulns):
    logging.info(f"\n[Dockerfile Remediation] Component: {component_root}")
    df = os.path.join(component_root, "Dockerfile")
    if not os.path.exists(df):
        logging.warning(f"Dockerfile not found in {component_root}")
        return

    with open(df, "r") as f:
        lines = f.readlines()

    modified = False
    # Trivy’s DS001 = “container runs as root”
    if any(v.get("ID") == "DS001" for v in vulns):
        # ensure we add a non-root user
        if not any("adduser" in l or "useradd" in l for l in lines):
            # insert before any CMD/ENTRYPOINT or at end
            idx = next((i for i,l in enumerate(lines)
                        if l.strip().upper().startswith(("CMD ", "ENTRYPOINT "))),
                       len(lines)-1)
            lines.insert(idx, "RUN adduser -D appuser\n")
        if not any(l.strip().upper().startswith("USER ") for l in lines):
            lines.append("USER appuser\n")
        modified = True

    if modified:
        with open(df, "w") as f:
            f.writelines(lines)
        logging.info("→ Dockerfile updated with a non‑root user.")


def main(go_report, dockerfile_report, image_report):
    reports = [
        (load_report(go_report)),
        (load_report(dockerfile_report)),
        (load_report(image_report)),
    ]

    # Merge them all into a single map: { component_root: [vuln, ...] }
    merged = defaultdict(list)
    for rep in reports:
        for comp, vs in group_vulnerabilities_by_component(rep).items():
            merged[comp].extend(vs)

    if not merged:
        logging.info("No vulnerabilities found to remediate.")
        return

    for comp, vs in merged.items():
        logging.info(f"\nProcessing component: {comp} ({len(vs)} issues)")
        remediate_go_mod(comp, vs)
        remediate_dockerfile(comp, vs)

    logging.info("\n--- PoC Remediation Complete ---")


if __name__ == "__main__":
    p = argparse.ArgumentParser("Trivy Remediation Script")
    p.add_argument("--go-report",        required=True)
    p.add_argument("--dockerfile-report",required=True)
    p.add_argument("--image-report",     required=True)
    args = p.parse_args()
    main(args.go_report, args.dockerfile_report, args.image_report)
