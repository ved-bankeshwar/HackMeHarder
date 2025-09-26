import subprocess
import sqlite3
    
def command_injection(user_input):
        # VULNERABLE: Uses shell=True
        subprocess.run(f"echo {user_input}", shell=True)
    
def sql_injection(cursor, user_id):
        # VULNERABLE: Uses an f-string for the query
        cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    
def safe_sql(cursor, user_id):
        # SAFE: Uses parameterization
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))