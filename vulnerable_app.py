import os
import sqlite3
from flask import Flask, request, render_template_string

# --- Vulnerable Web Application for Testing ---
# This app contains intentional vulnerabilities for SAST and DAST scanning.

app = Flask(__name__)

# --- SAST Target: Hardcoded Secret ---
# Your secrets_scanner should find this.
API_KEY = "sk_live_123abc456def789ghi_VERY_SECRET" 

# --- Database Setup for SQLi Demo ---
def init_db():
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    cursor.execute('DROP TABLE IF EXISTS users')
    cursor.execute('CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)')
    cursor.execute("INSERT INTO users (id, name) VALUES (1, 'admin')")
    cursor.execute("INSERT INTO users (id, name) VALUES (2, 'user')")
    conn.commit()
    conn.close()

@app.route('/')
def index():
    return '<h1>Vulnerable Test App</h1><p>Navigate to the vulnerable endpoints to test the scanner.</p>'

@app.route('/user')
def get_user():
    user_id = request.args.get('id', '1')
    
    # --- SAST Target: SQL Injection ---
    # Your vulnerability_scanner should flag this raw string formatting in an execute call.
    # DAST can also find this by trying payloads like '1 OR 1=1'.
    query = f"SELECT name FROM users WHERE id = {user_id}"
    
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    try:
        cursor.execute(query)
        user = cursor.fetchone()
        return f"User found: {user[0] if user else 'None'}"
    except Exception as e:
        return f"Database error: {e}"
    finally:
        conn.close()

@app.route('/run')
def run_command():
    command = request.args.get('cmd', 'echo Hello')
    
    # --- SAST Target: Command Injection ---
    # Your vulnerability_scanner should flag the use of os.system.
    # DAST can confirm this with commands like 'echo Hello; ls'.
    os.system(command) 
    
    return f"Executed command: {command}"

@app.route('/search')
def search():
    query = request.args.get('q', '')
    
    # --- DAST Target: Reflected Cross-Site Scripting (XSS) ---
    # This is hard for SAST to find reliably but easy for DAST.
    # The user's query is reflected directly into the HTML.
    template = f"<h2>Search Results</h2><p>You searched for: {query}</p>"
    return render_template_string(template)

if __name__ == '__main__':
    print("[+] Initializing the database for the test app...")
    init_db()
    print("[+] Starting the vulnerable Flask application on http://127.0.0.1:5000")
    # Setting debug=False is important for a realistic DAST test environment.
    app.run(host='127.0.0.1', port=5000, debug=False)
