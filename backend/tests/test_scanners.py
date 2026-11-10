"""Tests for all security scanners."""
import pytest
from app.scanners.sql_injection import SQLInjectionScanner
from app.scanners.hardcoded_creds import HardcodedCredsScanner
from app.scanners.unsafe_eval import UnsafeEvalScanner
from app.scanners.python_static import PythonStaticScanner
from app.scanners.engine import ScanEngine


# ===========================================================================
# SQL Injection Scanner
# ===========================================================================

class TestSQLInjectionScanner:
    scanner = SQLInjectionScanner()

    def test_detects_string_concatenation(self):
        code = '''
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
'''
        vulns = self.scanner.scan(code, "test.py")
        assert len(vulns) >= 1
        assert any(v.rule_id == "SQL001" for v in vulns)
        assert any(v.severity == "critical" for v in vulns)

    def test_detects_fstring_injection(self):
        code = '''
def get_user(name):
    query = f"SELECT * FROM users WHERE name = '{name}'"
    cursor.execute(query)
'''
        vulns = self.scanner.scan(code, "test.py")
        assert len(vulns) >= 1
        assert any(v.rule_id == "SQL002" for v in vulns)

    def test_detects_format_method(self):
        code = '''
def get_order(order_id):
    sql = "SELECT * FROM orders WHERE id = {}".format(order_id)
    db.execute(sql)
'''
        vulns = self.scanner.scan(code, "test.py")
        assert len(vulns) >= 1
        assert any(v.rule_id == "SQL003" for v in vulns)

    def test_detects_percent_formatting(self):
        code = '''
def search(term):
    sql = "SELECT * FROM products WHERE name = '%s'" % term
    cursor.execute(sql)
'''
        vulns = self.scanner.scan(code, "test.py")
        assert len(vulns) >= 1
        assert any(v.rule_id == "SQL004" for v in vulns)

    def test_no_false_positive_parameterized(self):
        code = '''
def get_user(user_id):
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
'''
        vulns = self.scanner.scan(code, "test.py")
        assert len(vulns) == 0

    def test_cwe_89_assigned(self):
        code = '''
name = user_input
query = "SELECT * FROM t WHERE name = " + name
'''
        vulns = self.scanner.scan(code, "test.py")
        assert any(v.cwe_id == "CWE-89" for v in vulns)


# ===========================================================================
# Hardcoded Credentials Scanner
# ===========================================================================

class TestHardcodedCredsScanner:
    scanner = HardcodedCredsScanner()

    def test_detects_hardcoded_password(self):
        code = 'password = "supersecret123"'
        vulns = self.scanner.scan(code, "test.py")
        assert len(vulns) >= 1
        assert any(v.rule_id == "CRED001" for v in vulns)

    def test_detects_api_key(self):
        code = 'api_key = "abcdef1234567890abcdef1234567890"'
        vulns = self.scanner.scan(code, "test.py")
        assert len(vulns) >= 1

    def test_detects_aws_key(self):
        code = 'aws_key = "AKIAIOSFODNN7EXAMPLE"'
        vulns = self.scanner.scan(code, "test.py")
        assert any(v.rule_id == "CRED002" for v in vulns)
        assert any(v.severity == "critical" for v in vulns)

    def test_ignores_placeholder_password(self):
        code = 'password = "your_password_here"'
        vulns = self.scanner.scan(code, "test.py")
        assert len(vulns) == 0

    def test_detects_secret_variable(self):
        code = 'secret = "my-real-secret-value-xyz"'
        vulns = self.scanner.scan(code, "test.py")
        assert len(vulns) >= 1

    def test_cwe_798_assigned(self):
        code = 'db_password = "real_db_pass_123"'
        vulns = self.scanner.scan(code, "test.py")
        assert any(v.cwe_id == "CWE-798" for v in vulns)


# ===========================================================================
# Unsafe Eval Scanner
# ===========================================================================

class TestUnsafeEvalScanner:
    scanner = UnsafeEvalScanner()

    def test_detects_eval(self):
        code = '''
user_input = input("Enter expression: ")
result = eval(user_input)
'''
        vulns = self.scanner.scan(code, "test.py")
        assert any(v.rule_id == "EVAL001" for v in vulns)
        assert any(v.severity == "critical" for v in vulns)

    def test_detects_exec(self):
        code = '''
code_str = request.data.decode()
exec(code_str)
'''
        vulns = self.scanner.scan(code, "test.py")
        assert any(v.rule_id == "EVAL002" for v in vulns)

    def test_detects_os_system(self):
        code = '''
import os
filename = request.args.get("file")
os.system("cat " + filename)
'''
        vulns = self.scanner.scan(code, "test.py")
        assert any(v.rule_id == "EVAL004" for v in vulns)

    def test_detects_subprocess_shell_true(self):
        code = '''
import subprocess
cmd = request.args.get("cmd")
subprocess.run(cmd, shell=True)
'''
        vulns = self.scanner.scan(code, "test.py")
        assert any(v.rule_id == "EVAL005" for v in vulns)

    def test_detects_pickle_loads(self):
        code = '''
import pickle
data = request.get_data()
obj = pickle.loads(data)
'''
        vulns = self.scanner.scan(code, "test.py")
        assert any(v.rule_id == "EVAL006" for v in vulns)

    def test_no_false_positive_literal_eval(self):
        code = '''
import ast
result = ast.literal_eval("[1, 2, 3]")
'''
        vulns = self.scanner.scan(code, "test.py")
        # ast.literal_eval should not be flagged as unsafe eval
        eval_vulns = [v for v in vulns if v.rule_id == "EVAL001"]
        assert len(eval_vulns) == 0


# ===========================================================================
# Python Static Scanner
# ===========================================================================

class TestPythonStaticScanner:
    scanner = PythonStaticScanner()

    def test_detects_pickle_import(self):
        code = "import pickle"
        vulns = self.scanner.scan(code, "test.py")
        assert any("PICKLE" in v.rule_id for v in vulns)

    def test_detects_debug_true(self):
        code = '''
from flask import Flask
app = Flask(__name__)
app.run(debug=True)
'''
        vulns = self.scanner.scan(code, "test.py")
        assert any(v.rule_id == "PY002" for v in vulns)

    def test_detects_insecure_random(self):
        code = "import random"
        vulns = self.scanner.scan(code, "test.py")
        assert any(v.rule_id == "PY003" for v in vulns)

    def test_detects_zero_binding(self):
        code = '''
app.run(host="0.0.0.0", port=5000)
'''
        vulns = self.scanner.scan(code, "test.py")
        assert any(v.rule_id == "PY005" for v in vulns)

    def test_no_false_positive_safe_code(self):
        code = '''
import json
import os
from typing import List

def greet(name: str) -> str:
    return f"Hello, {name}"
'''
        vulns = self.scanner.scan(code, "test.py")
        assert len(vulns) == 0


# ===========================================================================
# Scan Engine
# ===========================================================================

class TestScanEngine:
    engine = ScanEngine()

    def test_aggregates_multiple_scanners(self):
        code = '''
import pickle
password = "hardcoded_pass_123"
query = "SELECT * FROM users WHERE id = " + user_id
result = eval(user_input)
'''
        result = self.engine.run_scan(code, "python", "test.py")
        assert result.summary.total >= 4
        assert result.scan_id is not None
        assert result.language == "python"

    def test_returns_scan_id(self):
        result = self.engine.run_scan("x = 1", "python", "test.py")
        assert len(result.scan_id) == 36  # UUID format

    def test_clean_code_no_vulns(self):
        code = '''
import os
import secrets

def get_token() -> str:
    return secrets.token_urlsafe(32)

def get_db_password() -> str:
    return os.environ.get("DB_PASSWORD", "")
'''
        result = self.engine.run_scan(code, "python", "clean.py")
        assert result.summary.critical == 0
        assert result.summary.high == 0
