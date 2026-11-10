"""
PATCHPILOT Demo: SQL Injection Patterns
Shows various SQL injection vulnerability patterns for scanner demonstration.
DO NOT use these patterns in production.
"""
import sqlite3


def connect():
    return sqlite3.connect(":memory:")


# PATTERN 1: String concatenation
def get_user_concat(user_id):
    conn = connect()
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    return cursor.fetchall()


# PATTERN 2: f-string interpolation
def get_user_fstring(username):
    conn = connect()
    cursor = conn.cursor()
    query = f"SELECT id, email FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()


# PATTERN 3: .format() method
def search_by_email(email):
    conn = connect()
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE email = '{}'".format(email)
    cursor.execute(query)
    return cursor.fetchall()


# PATTERN 4: % operator formatting
def get_by_role(role):
    conn = connect()
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE role = '%s'" % role
    cursor.execute(query)
    return cursor.fetchall()


# PATTERN 5: Multi-line concatenated query
def complex_search(name, city, min_age):
    conn = connect()
    cursor = conn.cursor()
    query = (
        "SELECT u.id, u.name, u.email "
        "FROM users u JOIN profiles p ON u.id = p.user_id "
        "WHERE u.name = '" + name + "' "
        "AND p.city = '" + city + "' "
        "AND u.age >= " + min_age
    )
    cursor.execute(query)
    return cursor.fetchall()


# PATTERN 6: INSERT with concatenation
def create_user(username, email):
    conn = connect()
    cursor = conn.cursor()
    query = "INSERT INTO users (username, email) VALUES ('" + username + "', '" + email + "')"
    cursor.execute(query)
    conn.commit()


# SAFE VERSIONS (for comparison / patch demonstration)

def get_user_safe(user_id):
    """SECURE: Parameterized query."""
    conn = connect()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchall()


def search_by_email_safe(email):
    """SECURE: Parameterized query."""
    conn = connect()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    return cursor.fetchall()


def create_user_safe(username, email):
    """SECURE: Parameterized INSERT."""
    conn = connect()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO users (username, email) VALUES (?, ?)",
        (username, email),
    )
    conn.commit()
