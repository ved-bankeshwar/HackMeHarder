import unittest
import os
import sys
import time
import io
from contextlib import redirect_stdout
import json

# --- UPDATED IMPORT ---
# Import the new `run_sast` function from your updated runner
try:
    from sast_runner import run_sast
    from dast_runner import run_dast
    # Import the new correlation engine that now contains the DAST logic
    from correlation_engine import run_full_scan
except ImportError as e:
    print(f"Error: Could not import runner modules.")
    print("Please ensure sast_runner.py, dast_runner.py, and correlation_engine.py are in the same directory.")
    print(f"Details: {e}")
    sys.exit(1)

# Import the reusable testing components
from testing_utils import app, ServerThread, setup_test_project, cleanup_test_project

class ToolIntegrationTest(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        """Set up the test environment using the reusable utility functions."""
        cls.temp_dir = setup_test_project()
        cls.server_thread = ServerThread(app)
        cls.server_thread.start()
        time.sleep(1) 

    @classmethod
    def tearDownClass(cls):
        """Clean up the test environment."""
        cls.server_thread.shutdown()
        cleanup_test_project(cls.temp_dir)
            
    def test_01_sast_scan(self):
        """
        Tests the new SAST runner directly.
        It should return a translated list of DAST targets, not just print findings.
        """
        print("\n--- Running New SAST Runner (run_sast) ---")
        
        dast_targets = run_sast(self.temp_dir)
        
        print("SAST runner returned the following DAST targets:")
        print(json.dumps(dast_targets, indent=2))
        print("--- End of SAST Runner Output ---")

        self.assertIsInstance(dast_targets, list, "The SAST runner should return a list.")
        self.assertGreater(len(dast_targets), 0, "The SAST runner should find at least one potential target.")
        
        xss_target = dast_targets[0]
        self.assertEqual(xss_target.get('type'), 'XSS', "The translated type should be 'XSS'.")
        self.assertEqual(xss_target.get('url'), '/', "The Flask route URL should be '/'.")
        self.assertEqual(xss_target.get('method'), 'GET', "The HTTP method should be 'GET'.")
        self.assertEqual(xss_target.get('param'), 'name', "The vulnerable parameter should be 'name'.")
        self.assertIn('sast_details', xss_target, "The target should include original SAST details for context.")

    def test_02_dast_scan(self):
        """Tests the DAST runner directly to ensure it finds the XSS vulnerability."""
        print("\n--- Running DAST Scan Directly ---")
        f = io.StringIO()
        with redirect_stdout(f):
            run_dast("http://127.0.0.1:5000/")
        output = f.getvalue()
        print(output)
        print("--- End of DAST Scan ---")

        self.assertIn("VULNERABILITY FOUND: XSS", output, "DAST scan should find and report the XSS vulnerability.")
        self.assertIn("http://127.0.0.1:5000/", output, "DAST report should show the vulnerable URL.")

    # --- UPDATED TEST CASE ---
    def test_03_full_correlated_scan(self):
        """
        Tests the new correlation engine, which now includes its own DAST logic,
        to ensure it confirms the SAST finding with a detailed reason.
        """
        print("\n--- Running Full Correlated Scan Directly ---")
        f = io.StringIO()
        with redirect_stdout(f):
            # The base_url should point to the root of the test server
            run_full_scan(self.temp_dir, "http://127.0.0.1:5000/")
        output = f.getvalue()
        print(output)
        print("--- End of Full Correlated Scan ---")

        # Check that the vulnerability was confirmed with the expected message
        self.assertIn(
            "[+] CONFIRMED: Cross-Site Scripting is exploitable.", 
            output, 
            "Full scan should confirm the XSS vulnerability."
        )
        
        # Check that the new analysis engine provides a reason for the finding
        self.assertIn(
            "Reason: Payload",
            output,
            "The confirmation message should include a detailed reason."
        )

        self.assertNotIn(
            "could not be confirmed by DAST", 
            output, 
            "The correlated scan should not report a false positive for this intentional vulnerability."
        )

if __name__ == "__main__":
    unittest.main()

