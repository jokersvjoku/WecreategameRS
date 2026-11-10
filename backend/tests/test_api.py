"""Integration tests for the FastAPI API endpoints."""
import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


VULNERABLE_CODE = '''
import pickle
import os

password = "supersecret123"
api_key = "AKIAIOSFODNN7EXAMPLE"

def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)

def run_command(cmd):
    os.system(cmd)

def parse(data):
    return eval(data)
'''

CLEAN_CODE = '''
import os
import secrets

def get_token():
    return secrets.token_urlsafe(32)

def get_password():
    return os.environ.get("DB_PASSWORD", "")
'''


class TestHealthEndpoint:
    def test_health_returns_ok(self):
        response = client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "version" in data
        assert "ai_available" in data
        assert "scanners_available" in data

    def test_health_lists_all_scanners(self):
        response = client.get("/api/health")
        data = response.json()
        scanners = data["scanners_available"]
        assert "sql_injection" in scanners
        assert "hardcoded_creds" in scanners
        assert "unsafe_eval" in scanners
        assert "python_static" in scanners


class TestScanEndpoint:
    def test_scan_vulnerable_code(self):
        response = client.post("/api/scan", json={
            "code": VULNERABLE_CODE,
            "language": "python",
            "filename": "test.py",
        })
        assert response.status_code == 200
        data = response.json()
        assert "scan_id" in data
        assert "vulnerabilities" in data
        assert "summary" in data
        assert data["summary"]["total"] >= 4

    def test_scan_clean_code(self):
        response = client.post("/api/scan", json={
            "code": CLEAN_CODE,
            "language": "python",
        })
        assert response.status_code == 200
        data = response.json()
        assert data["summary"]["critical"] == 0

    def test_scan_returns_scan_id(self):
        response = client.post("/api/scan", json={"code": "x = 1", "language": "python"})
        assert response.status_code == 200
        data = response.json()
        assert len(data["scan_id"]) == 36

    def test_scan_severity_counts_correct(self):
        response = client.post("/api/scan", json={
            "code": VULNERABLE_CODE,
            "language": "python",
        })
        data = response.json()
        summary = data["summary"]
        counted = summary["critical"] + summary["high"] + summary["medium"] + summary["low"] + summary["info"]
        assert counted == summary["total"]

    def test_scan_rejects_oversized_code(self):
        huge_code = "x = 1\n" * 200_000  # Well over 512KB
        response = client.post("/api/scan", json={"code": huge_code, "language": "python"})
        assert response.status_code == 413

    def test_scan_vulnerability_structure(self):
        response = client.post("/api/scan", json={
            "code": VULNERABLE_CODE,
            "language": "python",
        })
        data = response.json()
        if data["vulnerabilities"]:
            vuln = data["vulnerabilities"][0]
            required_fields = ["id", "rule_id", "severity", "title", "description",
                               "file", "line_start", "line_end", "code_snippet",
                               "category", "recommendation"]
            for field in required_fields:
                assert field in vuln, f"Missing field: {field}"


class TestRescanEndpoint:
    def test_rescan_patched_code(self):
        # After fixing, re-scan should find fewer issues
        clean_after_patch = '''
import os
import secrets

db_password = os.environ.get("DB_PASSWORD", "")

def get_user(user_id):
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
'''
        response = client.post("/api/rescan", json={
            "code": clean_after_patch,
            "language": "python",
        })
        assert response.status_code == 200
        data = response.json()
        assert data["summary"]["critical"] == 0
