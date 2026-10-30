import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app

engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
TestSession = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


@pytest.fixture
def client():
    Base.metadata.create_all(engine)

    def override_get_db():
        with TestSession() as session:
            yield session

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
    Base.metadata.drop_all(engine)


def create_account(client: TestClient, email: str) -> str:
    registered = client.post(
        "/api/auth/register",
        json={"email": email, "full_name": "Demo User", "password": "a-very-secure-password"},
    )
    assert registered.status_code == 201
    response = client.post("/api/auth/login", json={"email": email, "password": "a-very-secure-password"})
    assert response.status_code == 200
    return response.json()["access_token"]


def test_demo_inventory_filters_and_summary_are_explicitly_simulated(client):
    token = create_account(client, "demo@example.com")
    headers = {"Authorization": f"Bearer {token}"}

    resources = client.get("/api/resources", headers=headers)
    assert resources.status_code == 200
    assert len(resources.json()) == 3
    assert all(resource["simulated"] for resource in resources.json())
    assert len(client.get("/api/resources?resource_type=storage", headers=headers).json()) == 1
    summary = client.get("/api/dashboard/summary", headers=headers).json()
    assert summary == {
        "total_resources": 3,
        "active_connections": 1,
        "open_findings": 2,
        "unread_alerts": 2,
        "simulated_resources": 3,
    }


def test_create_connection_resource_and_filter(client):
    token = create_account(client, "owner@example.com")
    headers = {"Authorization": f"Bearer {token}"}
    connection = client.post(
        "/api/connections",
        headers=headers,
        json={"provider": "gcp", "display_name": "Test GCP"},
    )
    assert connection.status_code == 201
    assert connection.json()["simulated"] is True
    assert connection.json()["status"] == "pending"
    duplicate = client.post(
        "/api/connections",
        headers=headers,
        json={"provider": "gcp", "display_name": "Test GCP"},
    )
    assert duplicate.status_code == 409

    created = client.post(
        "/api/resources",
        headers=headers,
        json={
            "connection_id": connection.json()["id"],
            "provider": "gcp",
            "name": "new-demo-resource",
            "resource_type": "compute",
            "region": "us-central1",
            "status": "running",
            "tags": {"source": "test"},
        },
    )
    assert created.status_code == 201
    assert created.json()["simulated"] is True
    mismatch = client.post(
        "/api/resources",
        headers=headers,
        json={
            "connection_id": connection.json()["id"],
            "provider": "aws",
            "name": "provider-mismatch",
            "resource_type": "compute",
            "region": "us-east-1",
            "status": "running",
        },
    )
    assert mismatch.status_code == 422
    assert len(client.get("/api/resources?provider=gcp", headers=headers).json()) == 1
    assert len(client.get("/api/alerts", headers=headers).json()) == 2


def test_resources_and_connections_are_scoped_to_owner(client):
    owner_token = create_account(client, "first@example.com")
    other_token = create_account(client, "second@example.com")
    owner_headers = {"Authorization": f"Bearer {owner_token}"}
    other_headers = {"Authorization": f"Bearer {other_token}"}
    owner_resources = client.get("/api/resources", headers=owner_headers).json()

    assert len(owner_resources) == 3
    other_resources = client.get("/api/resources", headers=other_headers).json()
    assert len(other_resources) == 3
    assert {resource["id"] for resource in owner_resources}.isdisjoint(
        resource["id"] for resource in other_resources
    )
    assert client.get("/api/connections", headers=other_headers).json()[0]["display_name"] == "CloudBridge Demo Account"
    response = client.post(
        "/api/resources",
        headers=other_headers,
        json={
            "connection_id": owner_resources[0]["connection_id"],
            "provider": "aws",
            "name": "cross-tenant",
            "resource_type": "compute",
            "region": "us-east-1",
            "status": "running",
        },
    )
    assert response.status_code == 404


def test_protected_cloud_endpoints_require_authentication(client):
    assert client.get("/api/resources").status_code == 401
    assert client.get("/api/alerts").status_code == 401


def test_demo_costs_findings_and_alert_lifecycle_are_explicit_and_user_scoped(client):
    owner_token = create_account(client, "alerts-owner@example.com")
    other_token = create_account(client, "alerts-other@example.com")
    owner_headers = {"Authorization": f"Bearer {owner_token}"}
    other_headers = {"Authorization": f"Bearer {other_token}"}

    costs = client.get("/api/connections/1/costs", headers=owner_headers)
    assert costs.status_code == 200
    assert costs.json()["total"] == 378
    assert costs.json()["currency"] == "USD"
    assert costs.json()["estimated"] is True
    assert costs.json()["simulated"] is True
    findings = client.get("/api/security/findings", headers=owner_headers)
    assert findings.status_code == 200
    assert len(findings.json()) == 2
    assert all(finding["simulated"] for finding in findings.json())
    assert {finding["affected_resource"] for finding in findings.json()} == {
        "assets-bucket-demo",
        "analytics-db-demo",
    }
    assert all(finding["recommendation"] for finding in findings.json())

    alerts = client.get("/api/alerts", headers=owner_headers).json()
    alert_id = alerts[0]["id"]
    acknowledged = client.patch(f"/api/alerts/{alert_id}/acknowledge", headers=owner_headers)
    assert acknowledged.status_code == 200
    assert acknowledged.json()["status"] == "acknowledged"
    assert acknowledged.json()["acknowledged_at"] is not None
    assert client.patch(f"/api/alerts/{alert_id}/resolve", headers=owner_headers).json()["status"] == "resolved"
    assert client.get("/api/alerts?status=resolved", headers=owner_headers).json()[0]["id"] == alert_id
    assert client.patch(f"/api/alerts/{alert_id}/resolve", headers=other_headers).status_code == 404


def test_live_aws_connection_sync_and_security_findings_are_server_side_and_deduplicated(client, monkeypatch):
    from app.routers import cloud as cloud_router

    class FakeAWS:
        def __init__(self, region=None):
            self.region = region

        def validate(self):
            return {"account_id": "123456789012", "arn": "arn:aws:iam::123456789012:role/read-only"}

        def discover_resources(self):
            return (
                [
                    {
                        "name": "live-api",
                        "resource_type": "ec2",
                        "region": "us-east-1",
                        "status": "running",
                        "tags": {"resource_id": "i-0123456789abcdef0"},
                        "metrics": {"cpu_utilization": 0.0, "memory_utilization": None},
                    }
                ],
                [],
            )

    class FakeScanner:
        def __init__(self, aws):
            pass

        def scan(self):
            return {
                "findings": [
                    {
                        "finding_id": "security-group-ingress:sg-example:tcp:22:22",
                        "affected_resource": "sg-0123456789abcdef0",
                        "title": "Sensitive ingress exposed",
                        "severity": "high",
                        "description": "Port 22 is exposed to the internet.",
                        "recommendation": "Restrict the source CIDR.",
                    }
                ],
                "checks": {"security_groups": "complete", "root_mfa": "permission_denied"},
            }

    monkeypatch.setattr(cloud_router, "AWSCloudService", FakeAWS)
    monkeypatch.setattr(cloud_router, "AWSSecurityScanner", FakeScanner)
    token = create_account(client, "live-owner@example.com")
    headers = {"Authorization": f"Bearer {token}"}
    connected = client.post(
        "/api/connections/aws",
        headers=headers,
        json={"display_name": "Live read-only account", "region": "us-east-1"},
    )
    assert connected.status_code == 201
    assert connected.json()["simulated"] is False
    assert connected.json()["account_identifier"] == "123456789012"
    assert not ({"access_key", "secret_key", "session_token"} & connected.json().keys())
    rejected_credentials = client.post(
        "/api/connections/aws",
        headers=headers,
        json={"display_name": "Credential payload", "region": "us-east-1", "secret_access_key": "must-not-accept"},
    )
    assert rejected_credentials.status_code == 422
    connection_id = connected.json()["id"]

    synced = client.post(f"/api/connections/{connection_id}/sync", headers=headers)
    assert synced.status_code == 200
    assert synced.json()["resource_count"] == 1
    resource = client.get("/api/resources?search=live-api", headers=headers).json()[0]
    assert resource["metrics"] == {"cpu_utilization": 0.0, "memory_utilization": None}
    assert resource["simulated"] is False

    first_scan = client.post(f"/api/connections/{connection_id}/scan", headers=headers)
    second_scan = client.post(f"/api/connections/{connection_id}/scan", headers=headers)
    assert first_scan.status_code == second_scan.status_code == 200
    assert first_scan.json()["checks"]["root_mfa"] == "permission_denied"
    assert first_scan.json()["findings"][0]["recommendation"] == "Restrict the source CIDR."
    alerts = client.get("/api/alerts", headers=headers).json()
    assert sum(alert["title"] == "Sensitive ingress exposed" for alert in alerts) == 1
    FakeScanner.scan = lambda self: {"findings": [], "checks": {"security_groups": "permission_denied"}}
    client.post(f"/api/connections/{connection_id}/scan", headers=headers)
    assert client.get("/api/security/findings?status=open", headers=headers).json()
    FakeScanner.scan = lambda self: {"findings": [], "checks": {"security_groups": "complete"}}
    client.post(f"/api/connections/{connection_id}/scan", headers=headers)
    open_findings = client.get("/api/security/findings?status=open", headers=headers).json()
    assert not any(finding["finding_id"].startswith(f"{connection_id}:") for finding in open_findings)
    resolved_findings = client.get("/api/security/findings?status=resolved", headers=headers).json()
    assert any(finding["finding_id"].startswith(f"{connection_id}:") for finding in resolved_findings)
    assert any(
        alert["title"] == "Sensitive ingress exposed"
        for alert in client.get("/api/alerts?status=resolved", headers=headers).json()
    )
    FakeAWS.discover_resources = lambda self: (
        [
            {
                "name": "live-api",
                "resource_type": "ec2",
                "region": "us-east-1",
                "status": "running",
                "tags": {"resource_id": "i-0123456789abcdef0"},
                "metrics": {"cpu_utilization": 87.5, "memory_utilization": None},
            }
        ],
        [],
    )
    client.post(f"/api/connections/{connection_id}/sync", headers=headers)
    client.post(f"/api/connections/{connection_id}/sync", headers=headers)
    cpu_alerts = [
        alert for alert in client.get("/api/alerts", headers=headers).json() if alert["title"] == "High CPU utilization"
    ]
    assert len(cpu_alerts) == 1


def test_cost_explorer_pages_are_aggregated_and_billing_permissions_are_reported(client, monkeypatch):
    from botocore.exceptions import ClientError

    from app.routers import cloud as cloud_router

    class CostClient:
        def __init__(self):
            self.page = 0

        def get_cost_and_usage(self, **request):
            if request.get("NextPageToken") == "page-2":
                return {
                    "ResultsByTime": [
                        {
                            "Estimated": True,
                            "Total": {"UnblendedCost": {"Amount": "12.00", "Unit": "USD"}},
                            "Groups": [
                                {"Keys": ["Amazon RDS"], "Metrics": {"UnblendedCost": {"Amount": "2.00", "Unit": "USD"}}}
                            ],
                        }
                    ]
                }
            return {
                "NextPageToken": "page-2",
                "ResultsByTime": [
                    {
                        "Estimated": True,
                        "Total": {"UnblendedCost": {"Amount": "12.00", "Unit": "USD"}},
                        "Groups": [
                            {"Keys": ["Amazon EC2"], "Metrics": {"UnblendedCost": {"Amount": "10.00", "Unit": "USD"}}}
                        ],
                    }
                ],
            }

    class FakeAWS:
        def __init__(self, region=None):
            pass

        def validate(self):
            return {"account_id": "123456789012", "arn": "arn:aws:iam::123456789012:role/read-only"}

        def client(self, service, region=None):
            assert service == "ce"
            return CostClient()

    monkeypatch.setattr(cloud_router, "AWSCloudService", FakeAWS)
    token = create_account(client, "billing-owner@example.com")
    headers = {"Authorization": f"Bearer {token}"}
    connection = client.post(
        "/api/connections/aws",
        headers=headers,
        json={"display_name": "Billing AWS", "region": "us-east-1"},
    ).json()
    report = client.get(f"/api/connections/{connection['id']}/costs", headers=headers)
    assert report.status_code == 200
    assert report.json()["total"] == 12
    assert report.json()["estimated"] is True
    assert [(row["service"], row["amount"]) for row in report.json()["services"]] == [
        ("Amazon EC2", 10),
        ("Amazon RDS", 2),
    ]
    assert report.json()["simulated"] is False

    class DeniedAWS(FakeAWS):
        def client(self, service, region=None):
            class DeniedCostClient:
                def get_cost_and_usage(self, **kwargs):
                    raise ClientError(
                        {"Error": {"Code": "AccessDenied", "Message": "billing access disabled"}},
                        "GetCostAndUsage",
                    )

            return DeniedCostClient()

    monkeypatch.setattr(cloud_router, "AWSCloudService", DeniedAWS)
    denied = client.get(f"/api/connections/{connection['id']}/costs", headers=headers)
    assert denied.status_code == 403
    assert "lacks permission" in denied.json()["detail"]


def test_invalid_aws_credentials_do_not_create_a_connection(client, monkeypatch):
    from app.routers import cloud as cloud_router
    from app.services.aws import AWSIntegrationError

    class InvalidAWS:
        def __init__(self, region=None):
            pass

        def validate(self):
            raise AWSIntegrationError("AWS rejected the configured credentials.", status_code=401)

    monkeypatch.setattr(cloud_router, "AWSCloudService", InvalidAWS)
    token = create_account(client, "invalid-aws@example.com")
    headers = {"Authorization": f"Bearer {token}"}
    response = client.post(
        "/api/connections/aws",
        headers=headers,
        json={"display_name": "Invalid AWS", "region": "us-east-1"},
    )
    assert response.status_code == 401
    connections = client.get("/api/connections", headers=headers).json()
    assert len(connections) == 1
    assert connections[0]["simulated"] is True


def test_aws_sync_permission_failure_is_reported_in_connection_status(client, monkeypatch):
    from app.routers import cloud as cloud_router
    from app.services.aws import AWSIntegrationError

    class DeniedAWS:
        def __init__(self, region=None):
            pass

        def validate(self):
            return {"account_id": "123456789012", "arn": "arn:aws:iam::123456789012:role/read-only"}

        def discover_resources(self):
            raise AWSIntegrationError("Missing discovery permission.", status_code=403)

    monkeypatch.setattr(cloud_router, "AWSCloudService", DeniedAWS)
    token = create_account(client, "permission-aws@example.com")
    headers = {"Authorization": f"Bearer {token}"}
    connection = client.post(
        "/api/connections/aws",
        headers=headers,
        json={"display_name": "Restricted AWS", "region": "us-east-1"},
    ).json()
    result = client.post(f"/api/connections/{connection['id']}/sync", headers=headers)
    assert result.status_code == 403
    stored = client.get("/api/connections", headers=headers).json()
    live_connection = next(item for item in stored if not item["simulated"])
    assert live_connection["status"] == "degraded"
