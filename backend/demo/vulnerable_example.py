"""
PATCHPILOT Demo: Vulnerable Python File
This file intentionally contains multiple security vulnerabilities for demonstration purposes.
DO NOT use patterns from this file in production code.
"""
import os
import pickle
import subprocess
import random

# VULNERABILITY 1: Hardcoded credentials (CWE-798)
DB_PASSWORD = "admin123!secret"
API_KEY = "sk-live-abcdef1234567890abcdef1234567890"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# VULNERABILITY 2: Debug mode enabled (CWE-94)
DEBUG = True


def connect_to_database():
    """Connect using hardcoded credentials — INSECURE."""
    import sqlite3
    # Uses hardcoded password above — never do this
    conn = sqlite3.connect(f"mydb_{DB_PASSWORD}.db")
    return conn


# VULNERABILITY 3: SQL Injection via string concatenation (CWE-89)
def get_user_by_name(username):
    """Fetch user by name — VULNERABLE to SQL injection."""
    conn = connect_to_database()
    cursor = conn.cursor()
    # INSECURE: Direct string concatenation
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchall()


# VULNERABILITY 4: SQL Injection via f-string (CWE-89)
def get_user_orders(user_id):
    """Fetch orders — VULNERABLE via f-string."""
    conn = connect_to_database()
    cursor = conn.cursor()
    # INSECURE: f-string interpolation
    sql = f"SELECT * FROM orders WHERE user_id = {user_id}"
    cursor.execute(sql)
    return cursor.fetchall()


# VULNERABILITY 5: SQL Injection via .format() (CWE-89)
def search_products(search_term):
    """Search products — VULNERABLE via .format()."""
    conn = connect_to_database()
    cursor = conn.cursor()
    # INSECURE: .format() in SQL
    query = "SELECT * FROM products WHERE name LIKE '%{}%'".format(search_term)
    cursor.execute(query)
    return cursor.fetchall()


# VULNERABILITY 6: Unsafe eval (CWE-95)
def calculate(expression):
    """Evaluate a math expression from user input — DANGEROUS."""
    # INSECURE: eval() on user input allows arbitrary code execution
    return eval(expression)


# VULNERABILITY 7: OS command injection (CWE-78)
def list_files(directory):
    """List files in a directory — VULNERABLE to command injection."""
    # INSECURE: os.system with user input
    os.system("ls " + directory)


# VULNERABILITY 8: subprocess with shell=True (CWE-78)
def run_script(script_name):
    """Run a script — VULNERABLE to shell injection."""
    # INSECURE: shell=True with unsanitized input
    subprocess.run("python " + script_name, shell=True)


# VULNERABILITY 9: Insecure deserialization (CWE-502)
def load_session(session_data: bytes):
    """Load a user session — VULNERABLE to pickle exploitation."""
    # INSECURE: Deserializing untrusted data with pickle
    return pickle.loads(session_data)


# VULNERABILITY 10: Insecure random for security token (CWE-338)
def generate_session_token():
    """Generate a session token — INSECURE PRNG."""
    # INSECURE: random is predictable
    return str(random.randint(100000, 999999))


# VULNERABILITY 11: Assert used for authorization (CWE-617)
def delete_user(user_id, is_admin):
    """Delete a user — INSECURE authorization via assert."""
    # INSECURE: assert is removed with python -O flag
    assert is_admin, "Only admins can delete users"
    conn = connect_to_database()
    cursor = conn.cursor()
    # Also vulnerable to SQL injection
    cursor.execute("DELETE FROM users WHERE id = " + str(user_id))
    conn.commit()


if __name__ == "__main__":
    from flask import Flask, request
    app = Flask(__name__)

    @app.route("/user")
    def user():
        name = request.args.get("name")
        return str(get_user_by_name(name))

    # VULNERABILITY 12: Debug=True in Flask (CWE-94)
    app.run(host="0.0.0.0", port=5000, debug=True)
