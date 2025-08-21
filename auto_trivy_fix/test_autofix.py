import unittest
from unittest.mock import patch, MagicMock
import json
import os
from pathlib import Path
import subprocess

from . import autofix

class TestAutofix(unittest.TestCase):

    @patch("auto_trivy_fix.tools.google_search")
    @patch("auto_trivy_fix.tools.view_text_website")
    @patch("auto_trivy_fix.autofix.run_trivy_image")
    @patch("auto_trivy_fix.autofix.DockerfilePatcher")
    @patch("subprocess.run")
    @patch("auto_trivy_fix.autofix.generate_final_report")
    def test_main_workflow_success(self, mock_generate_report, mock_subprocess_run, mock_dockerfile_patcher, mock_run_trivy_image, mock_view_text_website, mock_google_search):
        # --- Mocks Setup ---

        # Mock initial Trivy scan
        mock_run_trivy_image.side_effect = [
            # Initial scan result
            {"Results": [{"Vulnerabilities": [{"PkgName": "test-pkg", "InstalledVersion": "1.0", "FixedVersion": "1.1"}]}]},
            # Post-fix scan result
            {"Results": []}
        ]

        # Mock DockerfilePatcher
        mock_patcher_instance = MagicMock()
        mock_patcher_instance.attempt_patch.return_value = {
            "patched_dockerfile": "/tmp/Dockerfile.autofix",
            "actions": [{"type": "os-fixes-applied", "count": 1}]
        }
        mock_dockerfile_patcher.return_value = mock_patcher_instance

        # Mock subprocess.run for docker build
        mock_subprocess_run.return_value = MagicMock(returncode=0)

        # Mock generate_final_report to return a serializable dict
        mock_generate_report.return_value = {"summary": "mock_report"}

        # --- Run the main function ---
        with patch.dict(os.environ, {"IMAGE_NAME": "test-image", "DOCKERFILE_PATH": "auto_trivy_fix/example/Dockerfile"}):
            autofix.main()

        # --- Assertions ---

        # Check that Trivy was called twice
        self.assertEqual(mock_run_trivy_image.call_count, 2)

        # Check that DockerfilePatcher was called
        mock_dockerfile_patcher.assert_called_once()
        mock_patcher_instance.attempt_patch.assert_called_once()

        # Check that docker build was called
        mock_subprocess_run.assert_called_once()

        # Check that the final report is generated
        mock_generate_report.assert_called_once()


if __name__ == '__main__':
    unittest.main()
