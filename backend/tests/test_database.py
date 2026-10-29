from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.database import Base
from app.models import Alert, CloudConnection, CloudResource, SecurityFinding, User


def test_models_persist_and_relationships_work():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)

    with Session(engine) as session:
        user = User(email="owner@example.com", full_name="Test Owner", password_hash="hash")
        connection = CloudConnection(provider="aws", display_name="Demo AWS", user=user)
        resource = CloudResource(
            user=user,
            connection=connection,
            provider="aws",
            name="demo-instance",
            resource_type="compute",
            region="us-east-1",
            status="running",
        )
        finding = SecurityFinding(
            user=user, resource=resource, title="Example finding", description="Simulated.", severity="medium"
        )
        alert = Alert(user=user, title="Example alert", message="Simulated.", severity="low")
        session.add_all([user, connection, resource, finding, alert])
        session.commit()

        stored_user = session.scalar(select(User).where(User.email == "owner@example.com"))
        assert stored_user is not None
        assert stored_user.cloud_connections[0].resources[0].name == "demo-instance"
        assert stored_user.security_findings[0].severity == "medium"
        assert stored_user.alerts[0].is_read is False
        assert stored_user.cpu_alert_threshold == 80.0
        assert stored_user.memory_alert_threshold == 85.0
        assert stored_user.cloud_connections[0].scan_checks == {}
        assert stored_user.alerts[0].affected_resource == "Unknown resource"
        assert stored_user.alerts[0].recommendation == ""
        assert stored_user.created_at is not None

    engine.dispose()
