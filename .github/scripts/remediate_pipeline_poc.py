import json
import os
import logging
import argparse
import subprocess

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(message)s")

COMPONENT_DIR = "go-app-vulnerable"


def load_report(path):
    try:
        return json.load(open(path, "r"))
    except Exception as e:
        logging.error(f"Failed to load {path}: {e}")
        return {"Results": []}


def collect_vulns(report):
    vs = []
    for r in report.get("Results", []):
        vs.extend(r.get("Vulnerabilities", []))
        vs.extend(r.get("Misconfigurations", []))
    return vs


def remediate_go_mod(vulns):
    root = COMPONENT_DIR
    go_mod = os.path.join(root, "go.mod")
    logging.info(f"\n[Go Module Remediation] Component: {root}")

    if not os.path.exists(go_mod):
        logging.warning(f"go.mod not found at {go_mod}")
        return

    did_fix = False
    for v in vulns:
        if v.get("Type", "").lower() != "gomod":
            continue
        pkg = v.get("PkgName")
        ver = v.get("FixedVersion")
        if pkg and ver:
            logging.info(f"→ go get {pkg}@{ver}")
            try:
                subprocess.run(["go", "get", f"{pkg}@{ver}"],
                               cwd=root, check=True)
                did_fix = True
            except subprocess.CalledProcessError as e:
                logging.error(f"Failed to update {pkg}: {e}")

    if did_fix:
        subprocess.run(["go", "mod", "tidy"], cwd=root)


def remediate_dockerfile(vulns):
    root = COMPONENT_DIR
    df = os.path.join(root, "Dockerfile")
    logging.info(f"\n[Dockerfile Remediation] Component: {root}")

    if not os.path.exists(df):
        logging.warning(f"Dockerfile not found at {df}")
        return

    lines = open(df, "r").readlines()
    modified = False

    # If any DS001 findings, insert non-root user
    if any(v.get("ID") == "DS001" for v in vulns):
        if not any("adduser" in l or "useradd" in l for l in lines):
            idx = next(
                (i for i,l in enumerate(lines)
                 if l.strip().upper().startswith(("CMD ", "ENTRYPOINT "))),
                len(lines)-1
            )
            lines.insert(idx, "RUN adduser -D appuser\n")
        if not any(l.strip().upper().startswith("USER ") for l in lines):
            lines.append("USER appuser\n")
        modified = True

    if modified:
        open(df, "w").writelines(lines)
        logging.info("→ Dockerfile updated with non‑root user.")


def main(go_report, dockerfile_report, image_report):
    go_data = load_report(go_report)
    df_data = load_report(dockerfile_report)

    go_vulns = collect_vulns(go_data)
    df_vulns = collect_vulns(df_data)

    logging.info(f"\nProcessing component: {COMPONENT_DIR}")
    logging.info(f"  Go‑mod issues:     {len(go_vulns)}")
    logging.info(f"  Dockerfile issues: {len(df_vulns)}")

    remediate_go_mod(go_vulns)
    remediate_dockerfile(df_vulns)

    logging.info("\n--- PoC Remediation Complete ---")


if __name__ == "__main__":
    parser = argparse.ArgumentParser("Trivy Remediation (hard‑coded path)")
    parser.add_argument("--go-report",        required=True)
    parser.add_argument("--dockerfile-report",required=True)
    parser.add_argument("--image-report",     required=True)
    args = parser.parse_args()
    main(args.go_report, args.dockerfile_report, args.image_report)
