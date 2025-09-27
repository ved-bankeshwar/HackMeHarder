
from flask import Flask, request, render_template_string, redirect, Response
import sqlite3

app = Flask(__name__)


def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('DROP TABLE IF EXISTS users')
    cursor.execute('CREATE TABLE users (id TEXT, name TEXT)')
    cursor.execute("INSERT INTO users (id, name) VALUES ('1', 'admin')")
    conn.commit()
    conn.close()

@app.route('/')
def index():
    return """
    <h1>Vulnerable App Sandbox</h1>
    <ul>
        <li><a href="/search?q=test">Test XSS</a></li>
        <li><a href="/user/1">Test SQLi</a></li>
        <li><a href="/download?filename=../../../../../../../../../../etc/passwd">Test Path Traversal (Linux/macOS)</a></li>
        <li><a href="/redirect?next_url=https://www.google.com">Test Unvalidated Redirect</a></li>
    </ul>

    <h2>Forms to Test</h2>
    <form action="/search" method="GET">
        <input type="text" name="q" placeholder="Search (XSS)">
        <input type="submit" value="Search">
    </form>
    <br>
    <form action="/user" method="GET">
        <input type="text" name="id" placeholder="User ID (SQLi)">
        <input type="submit" value="Get User">
    </form>
    <br>
    <form action="/download" method="GET">
        <input type="text" name="filename" placeholder="Filename (Path Traversal)">
        <input type="submit" value="Download">
    </form>
    <br>
    <form action="/redirect" method="GET">
        <input type="text" name="next_url" placeholder="Redirect URL">
        <input type="submit" value="Redirect">
    </form>
    """


@app.route('/search')
def search():
    query = request.args.get('q', '')
    
    return render_template_string(f"<h2>Search results for: {query}</h2>")


@app.route('/user')
def get_user():
    user_id = request.args.get('id', '')
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    try:
        
        query = f"SELECT name FROM users WHERE id = '{user_id}'"
        cursor.execute(query)
        result = cursor.fetchone()
        return f"User found: {result[0] if result else 'Not Found'}"
    except Exception as e:
        return f"Database error: {e}"
    finally:
        conn.close()



@app.route('/download')
def download_file():
    filename = request.args.get('filename', '')
    try:
        with open(filename, 'r') as f:
            return Response(f.read(), mimetype='text/plain')
    except Exception as e:
        return f"Error reading file: {e}", 404


@app.route('/redirect')
def redirect_to_url():
    next_url = request.args.get('next_url', '/')

    return redirect(next_url, code=302)

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)