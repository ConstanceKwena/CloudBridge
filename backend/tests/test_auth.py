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


def test_register_login_and_protected_profile(client):
    registered = client.post(
        "/api/auth/register",
        json={"email": "owner@example.com", "full_name": "Test Owner", "password": "a-very-secure-password"},
    )
    assert registered.status_code == 201
    assert "password" not in registered.json()
    assert "password_hash" not in registered.json()

    login = client.post(
        "/api/auth/login", json={"email": "owner@example.com", "password": "a-very-secure-password"}
    )
    assert login.status_code == 200
    token = login.json()["access_token"]
    profile = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert profile.status_code == 200
    assert profile.json()["email"] == "owner@example.com"


def test_duplicate_registration_and_invalid_credentials(client):
    payload = {"email": "owner@example.com", "full_name": "Test Owner", "password": "a-very-secure-password"}
    assert client.post("/api/auth/register", json=payload).status_code == 201
    assert client.post("/api/auth/register", json=payload).status_code == 409
    assert client.post("/api/auth/login", json={"email": payload["email"], "password": "wrong-password"}).status_code == 401


def test_profile_requires_valid_token(client):
    assert client.get("/api/auth/me").status_code == 401
    assert client.get("/api/auth/me", headers={"Authorization": "Bearer invalid"}).status_code == 401
