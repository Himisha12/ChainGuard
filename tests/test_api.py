"""Tests for FastAPI REST API endpoints, Auth, RBAC, and Scans (D2, D3, D5, D7)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from src.api.app import app
from src.core.database import init_db


@pytest.fixture(scope="module", autouse=True)
def setup_database() -> None:
    """Ensure database tables exist before API tests."""
    init_db()


@pytest.fixture
def client() -> TestClient:
    """Create test client with lifespan handling."""
    with TestClient(app) as test_client:
        yield test_client


class TestHealthAndMetrics:
    """Test public health and metrics endpoints."""

    def test_health_check(self, client: TestClient) -> None:
        response = client.get("/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "timestamp" in data
        assert "version" in data

    def test_metrics_endpoint(self, client: TestClient) -> None:
        response = client.get("/v1/metrics")
        assert response.status_code == 200
        data = response.json()
        assert "scans_total" in data
        assert "uptime_seconds" in data


class TestAuthAndRBAC:
    """Test user registration, JWT login, and RBAC authorization (D3, D5)."""

    def test_register_and_login_flow(self, client: TestClient) -> None:
        import uuid
        username = f"user_{uuid.uuid4().hex[:8]}"
        email = f"{username}@example.com"
        password = "SecurePassword123!"

        # 1. Register new user
        reg_res = client.post(
            "/v1/auth/register",
            json={
                "username": username,
                "email": email,
                "password": password,
                "tenant_id": "tenant-alpha",
                "role": "analyst",
            },
        )
        assert reg_res.status_code == 201
        user_data = reg_res.json()
        assert user_data["username"] == username
        # Server ignores client-supplied role for security (assigned role is viewer)
        assert user_data["role"] == "viewer"
        assert "access_token" in user_data

        # 2. Login to receive JWT token
        login_res = client.post(
            "/v1/auth/login",
            data={"username": username, "password": password},
        )
        assert login_res.status_code == 200
        token_data = login_res.json()
        assert "access_token" in token_data
        assert token_data["token_type"] == "bearer"

    def test_unauthenticated_access_denied(self, client: TestClient) -> None:
        response = client.get("/v1/scans")
        assert response.status_code == 401

    def test_invalid_credentials_rejected(self, client: TestClient) -> None:
        response = client.post(
            "/v1/auth/login",
            data={"username": "nonexistent", "password": "wrongpassword"},
        )
        assert response.status_code == 401


class TestScanLifecycle:
    """Test scan creation, retrieval, and approval endpoints (D2, D20)."""

    @pytest.fixture
    def auth_headers(self, client: TestClient) -> dict[str, str]:
        import uuid
        username = f"approver_{uuid.uuid4().hex[:8]}"
        password = "Password123!"
        client.post(
            "/v1/auth/register",
            json={
                "username": username,
                "email": f"{username}@test.com",
                "password": password,
                "tenant_id": "test-tenant",
            },
        )
        token_res = client.post(
            "/v1/auth/login",
            data={"username": username, "password": password},
        )
        token = token_res.json()["access_token"]
        return {"Authorization": f"Bearer {token}"}

    def test_create_and_list_scans(self, client: TestClient, auth_headers: dict[str, str]) -> None:
        # Create scan
        content = "flask==2.0.0\nrequests==2.25.0\n"
        scan_res = client.post(
            "/v1/scans",
            headers=auth_headers,
            json={
                "file_content": content,
                "file_type": "requirements.txt",
                "project_name": "Test Web App",
            },
        )
        assert scan_res.status_code in (200, 201)
        scan = scan_res.json()
        assert "scan_id" in scan
        scan_id = scan["scan_id"]

        # Get scan details
        get_res = client.get(f"/v1/scans/{scan_id}", headers=auth_headers)
        assert get_res.status_code == 200
        details = get_res.json()
        assert details["scan_id"] == scan_id
        assert details["project_name"] == "Test Web App"

        # List scans (paginated)
        list_res = client.get("/v1/scans", headers=auth_headers)
        assert list_res.status_code == 200
        scans_list = list_res.json()
        assert any(s["scan_id"] == scan_id for s in scans_list["items"])

    def test_viewer_role_gets_403_on_approve_endpoint(self, client: TestClient) -> None:
        """Verify requirement 10: Authenticated user with VIEWER role receives HTTP 403 Forbidden on approve."""
        import uuid
        viewer_username = f"viewer_{uuid.uuid4().hex[:8]}"
        password = "Password123!"

        # 1. Register a user (server automatically assigns role 'viewer')
        client.post(
            "/v1/auth/register",
            json={
                "username": viewer_username,
                "email": f"{viewer_username}@example.com",
                "password": password,
            },
        )

        # 2. Login to obtain viewer JWT token
        login_res = client.post(
            "/v1/auth/login",
            data={"username": viewer_username, "password": password},
        )
        assert login_res.status_code == 200
        viewer_token = login_res.json()["access_token"]
        viewer_headers = {"Authorization": f"Bearer {viewer_token}"}

        # 3. Attempt to submit decision on OpsPilot approval endpoint -> must return 403 Forbidden
        decision_res = client.post(
            "/v1/approvals/fake-approval-id/decision",
            headers=viewer_headers,
            json={"action": "approve", "operator": viewer_username},
        )
        assert decision_res.status_code == 403
        assert "not authorized" in decision_res.text.lower() or "forbidden" in decision_res.text.lower()

        # 4. Attempt to submit decision on ChainGuard scan approval endpoint -> must return 403 Forbidden
        scan_decision_res = client.post(
            "/v1/scans/fake-scan-id/approve",
            headers=viewer_headers,
            json={"action": "approve", "feedback": "looks good"},
        )
        assert scan_decision_res.status_code == 403
