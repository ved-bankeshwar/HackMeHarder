# test.py
# This file contains code to test the injection scanner.
# It includes vulnerable patterns that should be detected by the rules.

import subprocess
import os

# --- Mock Database Setup ---
# This class mimics a database cursor to make the SQL examples valid Python code.
class MockCursor:
    def execute(self, query, params=None):
        """Mocks the execute method of a DB cursor."""
        print(f"Executing query: {query}")
        if params:
            print(f"With params: {params}")

db_cursor = MockCursor()


# --- Test Cases for Injection Rules ---

def command_injection_subprocess_vulnerable(user_input):
    """
    VULNERABLE: Should be detected by rule PY-CMD-INJ-001.
    This uses subprocess.run with shell=True, which is dangerous with user input.
    """
    # This line should be flagged.
    subprocess.run(f"echo {user_input}", shell=True, check=True)

def command_injection_os_system_vulnerable(user_input):
    """
    VULNERABLE: Should be detected by rule PY-CMD-INJ-002.
    This uses os.system, which invokes the system shell and is insecure.
    """
    # This line should be flagged.
    os.system(f"ls -l {user_input}")

def sql_injection_fstring_vulnerable(user_id):
    """
    VULNERABLE: Should be detected by rule PY-SQLI-001.
    This uses an f-string to build an SQL query, allowing for SQL injection.
    """
    # This line should be flagged.
    db_cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

def sql_injection_concatenation_vulnerable(user_name):
    """
    VULNERABLE: Should also be detected by rule PY-SQLI-001.
    This uses string concatenation to build an SQL query.
    """
    # This line should be flagged.
    query = "SELECT username FROM users WHERE name = '" + user_name + "'"
    db_cursor.execute(query)


# --- Safe Code Examples ---
# These functions demonstrate secure coding practices and should NOT be flagged.

def command_injection_subprocess_safe(user_input):
    """
    SAFE: This should NOT be detected.
    Arguments are passed as a list, so shell=True is not needed. This prevents
    the input from being interpreted by the shell.
    """
    subprocess.run(["echo", user_input], check=True)

def sql_injection_safe(user_id):
    """
    SAFE: This should NOT be detected.
    This uses a parameterized query, which is the correct way to pass data
    to a database to prevent SQL injection.
    """
    db_cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))