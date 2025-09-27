# SAST_check.py
import unittest
import importlib.util
import os
import sys

# --- Set project root dynamically ---
PROJECT_ROOT = os.path.abspath(os.path.dirname(__file__))
sys.path.insert(0, PROJECT_ROOT)  # Allow imports from SAST and vul_app

# --- Path to test.py inside vul_app ---
TEST_PATH = os.path.join(PROJECT_ROOT, "vul_app", "test.py")

# --- Dynamically import the test module ---
spec = importlib.util.spec_from_file_location("test_module", TEST_PATH)
test_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(test_module)

def run_sast_checks():
    """Run all SAST tests from vul_app/test.py."""
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(test_module)

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print("\n===== SAST CHECK COMPLETE =====")
    print(f"Ran {result.testsRun} tests")
    print(f"Failures: {len(result.failures)}, Errors: {len(result.errors)}")

    return result

if __name__ == "__main__":
    run_sast_checks()
