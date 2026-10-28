from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError

from app import main
from app.main import app


def test_health_endpoint_confirms_database_readiness():
    with TestClient(app) as client:
        response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "CloudBridge"}


def test_health_endpoint_returns_service_unavailable_when_database_probe_fails(monkeypatch):
    with TestClient(app) as client:
        def fail_connection():
            raise OperationalError("SELECT 1", {}, Exception("database unavailable"))

        monkeypatch.setattr(main.engine, "connect", fail_connection)
        response = client.get("/health")

    assert response.status_code == 503
    assert response.json()["detail"] == "Database is unavailable"