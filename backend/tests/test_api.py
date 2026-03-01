import pytest
from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)

def test_analyze_email_basic():
    payload = {
        "sender": "alice@example.com",
        "subject": "Please verify",
        "body": "This is a test email.",
        "links": ["http://example.com"]
    }
    resp = client.post("/analyze/email", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert "severity" in data
    assert "flags" in data
    assert "ai_explanation" in data
    assert "education_tip" in data
    assert data["severity"] in {"low", "medium", "high"}
    assert isinstance(data["flags"], list)
    assert isinstance(data["ai_explanation"], str)
    assert isinstance(data["education_tip"], str)

def test_analyze_link_basic():
    payload = {"url": "http://example.com"}
    resp = client.post("/analyze/link", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert "severity" in data
    assert "flags" in data
    assert "ai_explanation" in data
    assert data["severity"] in {"low", "medium", "high"}
    assert isinstance(data["flags"], list)
    assert isinstance(data["ai_explanation"], str)

def test_analyze_download_basic():
    payload = {
        "url": "http://downloads.example.com/install.exe",
        "filename": "installer.exe",
        "content_type": "application/x-msdownload"
    }
    resp = client.post("/analyze/download", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert "severity" in data
    assert "flags" in data
    assert "ai_explanation" in data
    assert "education_tip" in data
    assert data["severity"] in {"low", "medium", "high"}
    assert isinstance(data["flags"], list)
    assert isinstance(data["ai_explanation"], str)
    assert isinstance(data["education_tip"], str)

def test_health_check():
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["service"] == "unhookd"
