import os
import shutil
import threading
from werkzeug.serving import make_server
from flask import Flask, request, render_template_string

# --- A Mini Vulnerable Flask App for Testing ---
# This can be imported by any module that needs a test target.
app = Flask(__name__)

@app.route('/')
def home():
    name = request.args.get('name', 'Guest')
    # VULNERABLE: Directly rendering user input without escaping.
    template = f"<h1>Hello, {name}!</h1>"
    return render_template_string(template)

# --- Server Control for Running the App in the Background ---
class ServerThread(threading.Thread):
    """A helper class to run the Flask app in a background thread."""
    def __init__(self, flask_app, port=5000):
        super().__init__()
        self.srv = make_server('127.0.0.1', port, flask_app)
        self.ctx = flask_app.app_context()
        self.ctx.push()
        self.daemon = True # Allows main thread to exit even if this thread is running

    def run(self):
        print("Starting Flask server for DAST tests...")
        self.srv.serve_forever()

    def shutdown(self):
        print("Shutting down Flask server...")
        self.srv.shutdown()

# --- Test Project Setup Utilities ---
def setup_test_project(dir_name="temp_test_project"):
    """Creates a temporary directory with a vulnerable app file for SAST."""
    if not os.path.exists(dir_name):
        os.makedirs(dir_name)

    app_file_path = os.path.join(dir_name, "vulnerable_app.py")
    with open(app_file_path, "w") as f:
        f.write("""
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/')
def home():
    name = request.args.get('name')
    # This is the line SAST should flag (line 9)
    return render_template_string(f"<h1>Hello, {name}</h1>")

if __name__ == "__main__":
    app.run(debug=False)
""")
    # Return the full path to the created directory
    return os.path.abspath(dir_name)

def cleanup_test_project(dir_name="temp_test_project"):
    """Removes the temporary test project directory."""
    if os.path.exists(dir_name):
        shutil.rmtree(dir_name)

