import unittest
from unittest.mock import patch, MagicMock, mock_open
import json
import os
from pathlib import Path

from auto_trivy_fix import dependency_fix

class TestDependencyFix(unittest.TestCase):

    @patch("subprocess.run")
    @patch("pathlib.Path.exists")
    @patch("pathlib.Path.read_text")
    @patch("pathlib.Path.write_text")
    def test_main_workflow_success(self, mock_write_text, mock_read_text, mock_exists, mock_subprocess_run):
        # --- Mocks Setup ---

        # Mock pip-audit scan result
        mock_subprocess_run.return_value = MagicMock(
            returncode=1,
            stdout=json.dumps([
                {"name": "requests", "version": "2.25.1", "vulns": [], "fixed_versions": ["2.26.0"]},
            ])
        )

        # Mock path exists
        mock_exists.return_value = True

        # Mock requirements.txt content
        mock_read_text.return_value = "requests==2.25.1\nnumpy==1.20.3"

        # --- Run the main function ---
        with patch.dict(os.environ, {"REQUIREMENTS_PATH": "dummy/requirements.txt"}):
            dependency_fix.main()

        # --- Assertions ---

        # Check that pip-audit was called
        mock_subprocess_run.assert_called_once()

        # Check that the requirements.txt file was read
        mock_read_text.assert_called_once()

        # Check that the requirements.txt file was written with the fix
        mock_write_text.assert_called_once_with("requests==2.26.0\nnumpy==1.20.3\n")

    @patch("auto_trivy_fix.tools.google_search")
    @patch("auto_trivy_fix.tools.view_text_website")
    def test_online_search_for_fix(self, mock_view_text_website, mock_google_search):
        # --- Mocks Setup ---
        mock_google_search.return_value = "https://example.com/fix"
        mock_view_text_website.return_value = "The vulnerability is patched in version 1.2.3 of the package."

        vulnerabilities = [{"name": "test-pkg", "id": "CVE-123", "fixed_versions": []}]

        # --- Run the function ---
        fixes = dependency_fix.generate_fixes(vulnerabilities)

        # --- Assertions ---
        self.assertEqual(fixes, {"test-pkg": "1.2.3"})

if __name__ == '__main__':
    unittest.main()
