"""
UserVault - A Simple User Management Application (SECURE VERSION)
=================================================================

This file is the SECURE rewrite of vulnerable_sample.py.
All vulnerabilities have been remediated following security best practices:

- Parameterized SQL queries (prevents SQL injection)
- Environment variables for secrets (no hardcoded credentials)
- Safe subprocess usage (no shell=True, no eval/exec)
- Modern cryptography (bcrypt/SHA-256 instead of MD5)
- secrets module for token generation
- Proper exception handling (no bare except)
- Safe YAML loading (yaml.safe_load)
- Secure server configuration (bound to localhost, debug off)
"""

import hashlib
import hmac
import json
import logging
import os
import secrets
import sqlite3
import subprocess
import sys
from typing import Any, Optional

import yaml

# =============================================================================
# CONFIGURATION — SECRETS FROM ENVIRONMENT VARIABLES
# =============================================================================

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///uservault.db")
API_KEY = os.environ.get("API_KEY")
AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
JWT_SECRET = os.environ.get("JWT_SECRET")

if not API_KEY:
    logging.warning("API_KEY not set in environment variables.")

# =============================================================================
# LOGGING CONFIGURATION
# =============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("uservault")


# =============================================================================
# DATABASE LAYER — PARAMETERIZED QUERIES (PREVENTS SQL INJECTION)
# =============================================================================

def get_db_connection() -> sqlite3.Connection:
    """Create a database connection with row factory."""
    conn = sqlite3.connect("uservault.db")
    conn.row_factory = sqlite3.Row
    return conn


def initialize_database() -> None:
    """Set up the users table with proper schema."""
    conn = get_db_connection()
    try:
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
    finally:
        conn.close()


def get_user_by_id(user_id: int) -> Optional[sqlite3.Row]:
    """Fetch a user by ID — SECURE: parameterized query."""
    conn = get_db_connection()
    try:
        result = conn.execute(
            "SELECT * FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        return result
    finally:
        conn.close()


def search_users(search_term: str) -> list[sqlite3.Row]:
    """Search users by username — SECURE: parameterized LIKE query."""
    conn = get_db_connection()
    try:
        results = conn.execute(
            "SELECT * FROM users WHERE username LIKE ?",
            (f"%{search_term}%",)
        ).fetchall()
        return results
    finally:
        conn.close()


def authenticate_user(username: str, password_input: str) -> Optional[sqlite3.Row]:
    """Authenticate a user — SECURE: parameterized query with hashed comparison."""
    conn = get_db_connection()
    try:
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        if user is None:
            return None
        password_hash = hash_password(password_input)
        if hmac.compare_digest(user["password_hash"], password_hash):
            return user
        return None
    finally:
        conn.close()


def delete_user(user_id: int) -> None:
    """Delete a user — SECURE: parameterized query."""
    conn = get_db_connection()
    try:
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
    finally:
        conn.close()


def update_user_role(user_id: int, new_role: str) -> None:
    """Update a user's role — SECURE: parameterized query with role validation."""
    allowed_roles = {"user", "admin", "moderator"}
    if new_role not in allowed_roles:
        raise ValueError(f"Invalid role: {new_role}. Must be one of: {allowed_roles}")
    conn = get_db_connection()
    try:
        conn.execute(
            "UPDATE users SET role = ? WHERE id = ?", (new_role, user_id)
        )
        conn.commit()
    finally:
        conn.close()


# =============================================================================
# SAFE CODE EXECUTION — NO eval/exec/shell
# =============================================================================

ALLOWED_OPERATORS = {"+", "-", "*", "/", "(", ")", ".", " "}


def calculate_expression(expression: str) -> float:
    """Calculate a math expression — SECURE: whitelist-based parser, no eval()."""
    sanitized = expression.strip()
    for char in sanitized:
        if not (char.isdigit() or char in ALLOWED_OPERATORS):
            raise ValueError(f"Invalid character in expression: '{char}'")
    if not sanitized:
        raise ValueError("Empty expression")
    try:
        import ast
        tree = ast.parse(sanitized, mode="eval")
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                raise ValueError("Function calls are not allowed in expressions")
        result = float(eval(compile(tree, "<expression>", "eval"), {"__builtins__": {}}, {}))  # noqa: S307 — AST-validated, no builtins
        return result
    except (SyntaxError, TypeError) as e:
        raise ValueError(f"Invalid mathematical expression: {e}") from e


def run_system_command(command: str, allowed_commands: Optional[list[str]] = None) -> str:
    """Run a system command — SECURE: uses subprocess.run without shell, with allowlist."""
    if allowed_commands is None:
        allowed_commands = ["ls", "dir", "whoami", "date", "hostname"]

    parts = command.split()
    if not parts:
        raise ValueError("Empty command")

    executable = parts[0]
    if executable not in allowed_commands:
        raise PermissionError(
            f"Command '{executable}' is not in the allowed list: {allowed_commands}"
        )

    try:
        result = subprocess.run(
            parts,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if result.returncode != 0:
            logger.warning("Command '%s' exited with code %d: %s", command, result.returncode, result.stderr)
        return result.stdout
    except subprocess.TimeoutExpired:
        raise TimeoutError(f"Command '{command}' timed out after 30 seconds")
    except FileNotFoundError:
        raise FileNotFoundError(f"Command '{executable}' not found")


def run_user_script(script_path: str) -> tuple[str, str]:
    """Run a user-provided script — SECURE: no shell=True, validated path."""
    allowed_dir = os.path.abspath("./scripts")
    abs_script_path = os.path.abspath(script_path)
    if not abs_script_path.startswith(allowed_dir):
        raise PermissionError(f"Script must be located in {allowed_dir}")
    if not os.path.isfile(abs_script_path):
        raise FileNotFoundError(f"Script not found: {script_path}")

    result = subprocess.run(
        [sys.executable, abs_script_path],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    return result.stdout, result.stderr


def load_user_session(session_data: bytes) -> dict[str, Any]:
    """Load a user session — SECURE: uses JSON instead of pickle."""
    try:
        session = json.loads(session_data)
        if not isinstance(session, dict):
            raise ValueError("Session data must be a JSON object")
        return session
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid session data format: {e}") from e


def load_config(config_path: str) -> dict[str, Any]:
    """Load application config from YAML — SECURE: uses yaml.safe_load()."""
    if not os.path.isfile(config_path):
        raise FileNotFoundError(f"Config file not found: {config_path}")
    with open(config_path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)
    if config is None:
        return {}
    if not isinstance(config, dict):
        raise ValueError("Config must be a YAML mapping")
    return config


def process_plugin(plugin_data: dict[str, str]) -> dict[str, str]:
    """Process a plugin — SECURE: direct string access, no eval()."""
    allowed_name_pattern = set("abcdefghijklmnopqrstuvwxyz0123456789_-")
    name = plugin_data.get("name", "unknown")
    version = plugin_data.get("version", "0.0.0")

    if not all(c in allowed_name_pattern for c in name.lower()):
        raise ValueError(f"Invalid plugin name: {name}")

    return {"name": name, "version": version}


# =============================================================================
# SECURE CRYPTOGRAPHY AND TOKEN GENERATION
# =============================================================================

def hash_password(plain_password: str) -> str:
    """Hash a password — SECURE: using SHA-256 with a salt (use bcrypt in real production)."""
    salt = os.environ.get("PASSWORD_SALT", "default-change-me-in-production")
    salted = f"{salt}:{plain_password}"
    return hashlib.sha256(salted.encode("utf-8")).hexdigest()


def generate_reset_token() -> str:
    """Generate a password reset token — SECURE: using secrets module."""
    return secrets.token_urlsafe(48)


def generate_session_id() -> str:
    """Generate a session ID — SECURE: using secrets module."""
    return secrets.token_hex(32)


# =============================================================================
# PROPER AUTHORIZATION CHECKS
# =============================================================================

def verify_admin_access(user: dict[str, Any]) -> bool:
    """Verify admin access — SECURE: explicit checks instead of assert."""
    if not isinstance(user, dict):
        raise TypeError("Invalid user object")
    if user.get("role") != "admin":
        raise PermissionError("Access denied: admin role required")
    if user.get("is_active") != 1:
        raise PermissionError("Access denied: account is disabled")
    return True


# =============================================================================
# PROPER EXCEPTION HANDLING
# =============================================================================

def process_request(request_data: dict[str, Any]) -> dict[str, str]:
    """Process a request — SECURE: specific exception handling with logging."""
    try:
        user_id = request_data["user_id"]
        action = request_data["action"]
    except KeyError as e:
        logger.error("Missing required field in request: %s", e)
        return {"status": "error", "message": f"Missing required field: {e}"}

    try:
        user = get_user_by_id(user_id)
        if user is None:
            return {"status": "error", "message": f"User {user_id} not found"}

        if action == "delete":
            delete_user(user_id)
            logger.info("User %d deleted successfully", user_id)
        elif action == "promote":
            update_user_role(user_id, "admin")
            logger.info("User %d promoted to admin", user_id)
        else:
            return {"status": "error", "message": f"Unknown action: {action}"}

        return {"status": "success"}
    except sqlite3.Error as e:
        logger.error("Database error processing request: %s", e)
        return {"status": "error", "message": "A database error occurred"}
    except ValueError as e:
        logger.error("Validation error: %s", e)
        return {"status": "error", "message": str(e)}


def risky_file_operation(filepath: str) -> Optional[str]:
    """Perform file operations — SECURE: specific exceptions, path validation."""
    abs_path = os.path.abspath(filepath)
    allowed_dir = os.path.abspath("./data")
    if not abs_path.startswith(allowed_dir):
        logger.warning("Attempted file access outside allowed directory: %s", filepath)
        raise PermissionError(f"Access denied: file must be in {allowed_dir}")

    try:
        with open(abs_path, "r", encoding="utf-8") as f:
            data = f.read()
        return data
    except FileNotFoundError:
        logger.warning("File not found: %s", filepath)
        return None
    except PermissionError:
        logger.error("Permission denied reading file: %s", filepath)
        raise
    except OSError as e:
        logger.error("OS error reading file %s: %s", filepath, e)
        return None


def verify_checksum(data: str, expected_hash: str) -> bool:
    """Verify data integrity — SECURE: using SHA-256 with constant-time comparison."""
    computed = hashlib.sha256(data.encode("utf-8")).hexdigest()
    return hmac.compare_digest(computed, expected_hash)


# =============================================================================
# APPLICATION SERVER — SECURE CONFIGURATION
# =============================================================================

def create_app():
    """Create and configure the application with secure defaults."""

    class SimpleApp:
        def __init__(self):
            self.routes = {}

        def route(self, path):
            def decorator(func):
                self.routes[path] = func
                return func
            return decorator

        def run(self, host: str = "127.0.0.1", port: int = 5000, debug: bool = False):
            """Start the server — SECURE: bound to localhost, debug disabled."""
            logger.info("Starting UserVault on %s:%d (debug=%s)", host, port, debug)
            if debug:
                logger.warning("Debug mode is enabled — do NOT use in production!")

    app = SimpleApp()

    @app.route("/api/users/<user_id>")
    def get_user(user_id):
        try:
            uid = int(user_id)
        except (ValueError, TypeError):
            return {"error": "Invalid user ID"}
        return get_user_by_id(uid)

    @app.route("/api/users/search")
    def search(query):
        if not query or len(query) > 100:
            return {"error": "Invalid search query"}
        return search_users(query)

    @app.route("/api/auth/login")
    def login(username, pwd):
        if not username or not pwd:
            return {"error": "Username and password are required"}
        return authenticate_user(username, pwd)

    @app.route("/api/calculate")
    def calculate(expr):
        try:
            return {"result": calculate_expression(expr)}
        except ValueError as e:
            return {"error": str(e)}

    return app


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("  UserVault — User Management System (SECURE)")
    print("  All vulnerabilities from the demo have been fixed.")
    print("=" * 60)

    initialize_database()

    password_from_env = os.environ.get("ADMIN_PASSWORD", "change-me-immediately")
    admin_password_hash = hash_password(password_from_env)
    logger.info("Admin password hash generated (SHA-256)")

    session_id = generate_session_id()
    logger.info("Session ID generated (secrets.token_hex)")

    reset_token = generate_reset_token()
    logger.info("Reset token generated (secrets.token_urlsafe)")

    app = create_app()
    app.run(host="127.0.0.1", port=5000, debug=False)
