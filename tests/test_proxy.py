import os
import pytest
from fastapi.testclient import TestClient

os.environ["DATABASE_URL"] = "sqlite:///./test_gateway.db"
os.environ["ENCRYPTION_KEY"] = ""

from src.main import app
from src.database import Base, engine

client = TestClient(app)


def setup_module():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def teardown_module():
    engine.dispose()
    Base.metadata.drop_all(bind=engine)
    try:
        os.remove("test_gateway.db")
    except (FileNotFoundError, PermissionError):
        pass


def get_admin_token():
    resp = client.post("/api/login", json={
        "username": "admin",
        "password": "admin123"
    })
    return resp.json()["access_token"]


class TestRoot:
    def test_root(self):
        response = client.get("/")
        assert response.status_code == 200
        assert "text/html" in response.headers.get("content-type", "")
        assert "بوابة" in response.text
        assert "AI Gateway" in response.text


class TestChatCompletion:
    def test_without_keys_configured(self):
        response = client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-3.5-turbo",
                "messages": [{"role": "user", "content": "Hello"}]
            }
        )
        assert response.status_code in [503, 500]

    def test_missing_model(self):
        response = client.post(
            "/v1/chat/completions",
            json={"messages": [{"role": "user", "content": "Hello"}]}
        )
        assert response.status_code == 400


class TestAuth:
    def test_login_success(self):
        response = client.post("/api/login", json={
            "username": "admin",
            "password": "admin123"
        })
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"

    def test_login_failure(self):
        response = client.post("/api/login", json={
            "username": "admin",
            "password": "wrong"
        })
        assert response.status_code == 401

    def test_protected_endpoint_without_token(self):
        response = client.post("/api/keys", json={
            "name": "test",
            "provider": "openai",
            "key": "sk-test"
        })
        assert response.status_code == 401


class TestKeyManagement:
    def test_list_keys_empty(self):
        token = get_admin_token()
        response = client.get(
            "/api/keys",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        assert response.json() == []

    def test_add_and_delete_key(self):
        token = get_admin_token()
        headers = {"Authorization": f"Bearer {token}"}

        add_resp = client.post(
            "/api/keys",
            json={"name": "test-key", "provider": "openai", "key": "sk-test123"},
            headers=headers
        )
        assert add_resp.status_code == 200
        key_id = add_resp.json()["id"]
        assert add_resp.json()["name"] == "test-key"
        assert add_resp.json()["provider"] == "openai"
        assert add_resp.json()["is_active"] is True

        list_resp = client.get("/api/keys", headers=headers)
        assert list_resp.status_code == 200
        assert len(list_resp.json()) == 1

        del_resp = client.delete(f"/api/keys/{key_id}", headers=headers)
        assert del_resp.status_code == 200

        list_resp2 = client.get("/api/keys", headers=headers)
        assert len(list_resp2.json()) == 0

    def test_delete_nonexistent_key(self):
        token = get_admin_token()
        headers = {"Authorization": f"Bearer {token}"}

        response = client.delete("/api/keys/99999", headers=headers)
        assert response.status_code == 404


class TestAnalytics:
    def test_stats_endpoint(self):
        response = client.get("/api/stats")
        assert response.status_code == 200
        data = response.json()
        assert "total_requests" in data
        assert "daily_requests" in data
        assert "avg_response_time_ms" in data

    def test_daily_stats(self):
        response = client.get("/api/stats/daily?days=3")
        assert response.status_code == 200
        data = response.json()
        assert data["days"] == 3
        assert "data" in data
