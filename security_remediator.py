#!/usr/bin/env python3
import os
import sys
from src.detection import detect_project_languages
from src.strategies.javascript import JavaScriptStrategy
# Import other strategies here as they are created
# from src.strategies.java import JavaStrategy

STRATEGY_MAP = {
    'javascript': JavaScriptStrategy,
    # 'java': JavaStrategy,
}

def main():
    """
    Main entry point for the Autonomous Security Remediator.
    """
    print("Autonomous Security Remediator initialized.")

    if len(sys.argv) > 1:
        target_directory = sys.argv[1]
    else:
        print("Usage: python3 security_remediator.py <path_to_project>")
        sys.exit(1)

    if not os.path.isdir(target_directory):
        print(f"Error: Directory not found at '{target_directory}'")
        sys.exit(1)

    # Resolve to an absolute path for clarity
    target_directory = os.path.abspath(target_directory)
    print(f"Scanning project in: {target_directory}")

    languages = detect_project_languages(target_directory)

    if not languages:
        print("Could not detect a supported project type in the directory.")
        sys.exit(1)

    print(f"Detected project languages: {', '.join(languages)}")

    for lang in languages:
        if lang in STRATEGY_MAP:
            print(f"\\n----- Running {lang.capitalize()} Strategy -----")
            strategy = STRATEGY_MAP[lang]()

            # 1. Install tools (if necessary)
            strategy.install_tools()

            # 2. Run SCA scan
            sca_vulnerabilities = strategy.run_sca_scan(target_directory)
            if sca_vulnerabilities:
                print("\\n[SCA] Found vulnerabilities:")
                for vuln in sca_vulnerabilities:
                    print(f"  - Name: {vuln['name']}, Severity: {vuln['severity']}, Fix available: {vuln['fix_available']}")
            else:
                print("\\n[SCA] No dependency vulnerabilities found.")

            # 3. Run SAST scan (in the future)
            # sast_vulnerabilities = strategy.run_sast_scan(target_directory)
            # ...

        else:
            print(f"\\n----- No strategy found for {lang.capitalize()} -----")


if __name__ == "__main__":
    main()
