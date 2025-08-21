import unittest
from unittest.mock import patch, MagicMock
import json
import os
from pathlib import Path

from auto_trivy_fix import js_dependency_fix

class TestJsDependencyFix(unittest.TestCase):

    @patch("subprocess.run")
    @patch("pathlib.Path.exists")
    def test_main_workflow_success(self, mock_exists, mock_subprocess_run):
        # --- Mocks Setup ---
        mock_exists.return_value = True

        # Mock npm audit scan result
        mock_subprocess_run.side_effect = [
            # First call for npm audit
            MagicMock(
                returncode=1,
                stdout=json.dumps({
                    "vulnerabilities": {
                        "axios": {
                            "name": "axios",
                            "severity": "high",
                            "fixAvailable": {
                                "name": "axios",
                                "version": "0.21.2",
                                "isSemVerMajor": True
                            }
                        }
                    }
                })
            ),
            # Second call for npm install
            MagicMock(returncode=0)
        ]

        # --- Run the main function ---
        with patch.dict(os.environ, {"PROJECT_PATH": "dummy_js_project"}):
            js_dependency_fix.main()

        # --- Assertions ---

        # Check that npm audit and npm install were called
        self.assertEqual(mock_subprocess_run.call_count, 2)

        # Check the call arguments
        # First call is npm audit
        self.assertEqual(mock_subprocess_run.call_args_list[0].args[0], ['npm', 'audit', '--json'])
        # Second call is npm install
        self.assertEqual(mock_subprocess_run.call_args_list[1].args[0], ['npm', 'install', 'axios@0.21.2'])


if __name__ == '__main__':
    unittest.main()
