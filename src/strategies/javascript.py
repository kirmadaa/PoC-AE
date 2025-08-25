import subprocess
import json
from typing import List, Dict, Any

from .base import LanguageStrategy

class JavaScriptStrategy(LanguageStrategy):
    """
    Concrete strategy for handling JavaScript projects.
    """

    def install_tools(self):
        """
        Checks for npm and installs it if not present.
        For now, we assume npm is installed.
        """
        print("Checking for JavaScript tools (npm)...")
        # In a real implementation, we might run `npm --version` and
        # guide the user to install it if it fails.
        # Per user request, we can also try to install it.
        # This will be implemented more robustly later.
        pass

    def run_sca_scan(self, project_dir: str) -> List[Dict[str, Any]]:
        """
        Runs `npm audit` to find vulnerabilities in dependencies.
        """
        print(f"Running SCA scan for JavaScript project at: {project_dir}")
        command = ["npm", "audit", "--json"]
        try:
            # `npm audit` requires a package-lock.json, so we need to run `npm install` first
            # to ensure the project is in a scannable state.
            print("Ensuring dependencies are installed by running 'npm install'...")
            install_process = subprocess.run(
                ["npm", "install"],
                cwd=project_dir,
                capture_output=True,
                text=True,
                check=False  # Don't throw exception on non-zero exit
            )
            if install_process.returncode != 0:
                print(f"Warning: 'npm install' failed. SCA scan may be inaccurate.")
                print(install_process.stderr)

            # Now run the audit
            process = subprocess.run(
                command,
                cwd=project_dir,
                capture_output=True,
                text=True,
                check=True
            )

            # The output of `npm audit --json` can sometimes contain non-JSON lines
            # at the beginning. We need to find the start of the JSON object.
            json_output_start = process.stdout.find('{')
            if json_output_start == -1:
                print("Error: Could not find JSON output from npm audit.")
                return []

            report = json.loads(process.stdout[json_output_start:])
            vulnerabilities = report.get("vulnerabilities", {})

            findings = []
            for name, vuln_info in vulnerabilities.items():
                findings.append({
                    "name": name,
                    "severity": vuln_info.get("severity"),
                    "via": [item.get("name") if isinstance(item, dict) else item for item in vuln_info.get("via", [])],
                    "fix_available": vuln_info.get("fixAvailable"),
                })

            print(f"Found {len(findings)} vulnerabilities.")
            return findings

        except FileNotFoundError:
            print("Error: 'npm' command not found. Please install Node.js and npm.")
            return []
        except subprocess.CalledProcessError as e:
            # npm audit exits with a non-zero status code if vulnerabilities are found.
            # We need to parse the output even in this case.
            json_output_start = e.stdout.find('{')
            if json_output_start == -1:
                print(f"Error running npm audit: {e.stderr}")
                return []

            report = json.loads(e.stdout[json_output_start:])
            vulnerabilities = report.get("vulnerabilities", {})

            findings = []
            for name, vuln_info in vulnerabilities.items():
                findings.append({
                    "name": name,
                    "severity": vuln_info.get("severity"),
                    "via": [item.get("name") if isinstance(item, dict) else item for item in vuln_info.get("via", [])],
                    "fix_available": vuln_info.get("fixAvailable"),
                })

            print(f"Found {len(findings)} vulnerabilities.")
            return findings
        except json.JSONDecodeError:
            print("Error: Failed to decode JSON from npm audit output.")
            return []

    def run_sast_scan(self, project_dir: str):
        """
        Placeholder for running a SAST scan on JavaScript code.
        """
        print("SAST scanning for JavaScript is not yet implemented.")
        return []

    def run_tests(self, project_dir: str) -> tuple[bool, str]:
        """
        Placeholder for running the test suite of a JavaScript project.
        """
        print("Test execution for JavaScript is not yet implemented.")
        return (True, "Not implemented")

    def apply_patch(self, vulnerability_info: dict, project_dir: str):
        """
        Placeholder for applying a patch to a JavaScript project.
        """
        print("Patch application for JavaScript is not yet implemented.")
        return False
