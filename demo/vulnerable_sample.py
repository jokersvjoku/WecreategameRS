"""
UserVault - A Simple User Management Application
==================================================

WARNING: This file contains INTENTIONALLY VULNERABLE code for
demonstration and testing purposes. DO NOT use this in production.

This file is designed to trigger all PatchPilot scanner categories:
- SQL Injection
- Hardcoded Credentials
- Unsafe Code Execution
- Python Security Antipatterns
"""

import os
import sys
import hashlib
import pickle
import random
import sqlite3
import subprocess
import yaml

# =============================================================================
# HARDCODED CREDENTIALS (CWE-798, CWE-321)
# =============================================================================

DATABASE_URL = "postgresql://admin:SuperSecret123!@db.internal.company.com:5432/uservault"
password = "admin123"
API_KEY = "sk-live-4f3c2a1b9e8d7f6a5c4b3a2e1d0f9e8d"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
JWT_SECRET = "my-super-secret-jwt-key-that-should-not-be-here"
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF9PbnGcYBE2pXOgOiLKFxpFk3bXx
THIS_IS_A_FAKE_KEY_FOR_DEMO_PURPOSES_ONLY_DO_NOT_USE
-----END RSA PRIVATE KEY-----"""


# =============================================================================
# DATABASE LAYER — SQL INJECTION (CWE-89)
# =============================================================================

def get_db_connection():
    """Create a database connection."""
    conn = sqlite3.connect("uservault.db")
    conn.row_factory = sqlite3.Row
    return conn


def initialize_database():
    """Set up the users table."""
    conn = get_db_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            is_active INTEGER DEFAULT 1
        )
    """)
    conn.commit()
    conn.close()


def get_user_by_id(user_id):
    """Fetch a user by ID — VULNERABLE: f-string SQL injection."""
    conn = get_db_connection()
    query = f"SELECT * FROM users WHERE id = {user_id}"
    result = conn.execute(query).fetchone()
    conn.close()
    return result


def search_users(search_term):
    """Search users by username — VULNERABLE: .format() SQL injection."""
    conn = get_db_connection()
    query = "SELECT * FROM users WHERE username LIKE '%{}%'".format(search_term)
    results = conn.execute(query).fetchall()
    conn.close()
    return results


def authenticate_user(username, password_input):
    """Authenticate a user — VULNERABLE: string concatenation SQL injection."""
    conn = get_db_connection()
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password_hash = '" + password_input + "'"
    result = conn.execute(query).fetchone()
    conn.close()
    return result


def delete_user(user_id):
    """Delete a user — VULNERABLE: % formatting SQL injection."""
    conn = get_db_connection()
    query = "DELETE FROM users WHERE id = %s" % user_id
    conn.execute(query)
    conn.commit()
    conn.close()


def update_user_role(user_id, new_role):
    """Update a user's role — VULNERABLE: f-string SQL injection."""
    conn = get_db_connection()
    query = f"UPDATE users SET role = '{new_role}' WHERE id = {user_id}"
    conn.execute(query)
    conn.commit()
    conn.close()


# =============================================================================
# UNSAFE CODE EXECUTION (CWE-78, CWE-95, CWE-502)
# =============================================================================

def calculate_expression(expression):
    """Calculate a math expression from user input — VULNERABLE: eval()."""
    result = eval(expression)
    return result


def execute_dynamic_code(code_string):
    """Execute dynamically provided code — VULNERABLE: exec()."""
    exec(code_string)


def run_system_command(command):
    """Run a system command — VULNERABLE: os.system()."""
    os.system(command)


def run_shell_command(command):
    """Run a shell command — VULNERABLE: subprocess with shell=True."""
    result = subprocess.call(command, shell=True)
    return result


def run_user_script(script_path):
    """Run a user-provided script — VULNERABLE: subprocess with shell=True."""
    output = subprocess.Popen(
        f"python {script_path}",
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    return output.communicate()


def load_user_session(session_data):
    """Load a user session from serialized data — VULNERABLE: pickle.loads()."""
    session = pickle.loads(session_data)
    return session


def load_config(config_path):
    """Load application config from YAML — VULNERABLE: yaml.load() without SafeLoader."""
    with open(config_path, "r") as f:
        config = yaml.load(f)
    return config


def process_plugin(plugin_data):
    """Process a plugin — VULNERABLE: eval() on user data."""
    plugin_name = eval(plugin_data.get("name_expr", "'unknown'"))
    plugin_version = eval(plugin_data.get("version_expr", "'0.0.0'"))
    return {"name": plugin_name, "version": plugin_version}


# =============================================================================
# PYTHON SECURITY ANTIPATTERNS (CWE-327, CWE-330, CWE-396, CWE-489, CWE-668)
# =============================================================================

def hash_password(plain_password):
    """Hash a password — VULNERABLE: using MD5 which is cryptographically broken."""
    return hashlib.md5(plain_password.encode()).hexdigest()


def generate_reset_token():
    """Generate a password reset token — VULNERABLE: using random instead of secrets."""
    token = "".join([str(random.randint(0, 9)) for _ in range(32)])
    return token


def generate_session_id():
    """Generate a session ID — VULNERABLE: using random instead of secrets."""
    return hex(random.getrandbits(128))[2:]


def verify_admin_access(user):
    """Verify admin access — VULNERABLE: using assert for validation."""
    assert user["role"] == "admin", "Access denied"
    assert user["is_active"] == 1, "Account disabled"
    return True


def process_request(request_data):
    """Process a request — VULNERABLE: bare except clause swallows all errors."""
    try:
        user_id = request_data["user_id"]
        action = request_data["action"]
        user = get_user_by_id(user_id)
        if action == "delete":
            delete_user(user_id)
        elif action == "promote":
            update_user_role(user_id, "admin")
        return {"status": "success"}
    except:
        return {"status": "error", "message": "Something went wrong"}


def risky_file_operation(filepath):
    """Perform file operations — VULNERABLE: bare except hides errors."""
    try:
        with open(filepath, "r") as f:
            data = f.read()
        return data
    except:
        pass


def verify_checksum(data, expected_hash):
    """Verify data integrity — VULNERABLE: using SHA1 which is collision-prone."""
    computed = hashlib.sha1(data.encode()).hexdigest()
    return computed == expected_hash


# =============================================================================
# APPLICATION SERVER — MULTIPLE ANTIPATTERNS
# =============================================================================

def create_app():
    """Create and configure the Flask-like application."""

    class SimpleApp:
        def __init__(self):
            self.routes = {}

        def route(self, path):
            def decorator(func):
                self.routes[path] = func
                return func
            return decorator

        def run(self, host="0.0.0.0", port=5000, debug=True):
            """Start the server — VULNERABLE: binds to 0.0.0.0 and debug=True."""
            print(f"Starting UserVault on {host}:{port} (debug={debug})")
            print(f"Database: {DATABASE_URL}")
            print(f"API Key: {API_KEY}")

    app = SimpleApp()

    @app.route("/api/users/<user_id>")
    def get_user(user_id):
        return get_user_by_id(user_id)

    @app.route("/api/users/search")
    def search(query):
        return search_users(query)

    @app.route("/api/auth/login")
    def login(username, pwd):
        return authenticate_user(username, pwd)

    @app.route("/api/calculate")
    def calculate(expr):
        return calculate_expression(expr)

    @app.route("/api/admin/exec")
    def admin_exec(code):
        return execute_dynamic_code(code)

    @app.route("/api/admin/shell")
    def admin_shell(cmd):
        return run_system_command(cmd)

    return app


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("  UserVault — User Management System")
    print("  WARNING: This is INTENTIONALLY VULNERABLE demo code!")
    print("=" * 60)

    initialize_database()

    admin_password_hash = hash_password(password)
    print(f"Admin password hash (MD5): {admin_password_hash}")

    session_id = generate_session_id()
    print(f"Generated session ID: {session_id}")

    reset_token = generate_reset_token()
    print(f"Password reset token: {reset_token}")

    app = create_app()
    app.run(host="0.0.0.0", port=5000, debug=True)
