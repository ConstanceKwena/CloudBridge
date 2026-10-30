from sqlalchemy.orm import Session

from app.models import Alert, CloudConnection, CloudResource, SecurityFinding, User


def add_demo_data(db: Session, user: User) -> None:
    connection = CloudConnection(
        user=user,
        provider="aws",
        display_name="CloudBridge Demo Account",
        status="connected",
        region="us-east-1",
        account_identifier="DEMO-0001",
        simulated=True,
    )
    db.add(connection)
    db.flush()

    resources = [
        CloudResource(
            user=user,
            connection=connection,
            provider="aws",
            name="production-api-demo",
            resource_type="compute",
            region="us-east-1",
            status="running",
            monthly_cost=124,
            tags={"environment": "demo", "team": "platform"},
            simulated=True,
        ),
        CloudResource(
            user=user,
            connection=connection,
            provider="aws",
            name="assets-bucket-demo",
            resource_type="storage",
            region="us-east-1",
            status="active",
            monthly_cost=38,
            tags={"environment": "demo", "team": "web"},
            simulated=True,
        ),
        CloudResource(
            user=user,
            connection=connection,
            provider="aws",
            name="analytics-db-demo",
            resource_type="database",
            region="us-west-2",
            status="available",
            monthly_cost=216,
            tags={"environment": "demo", "team": "data"},
            simulated=True,
        ),
    ]
    db.add_all(resources)
    db.flush()
    db.add_all(
        [
            SecurityFinding(
                user=user,
                resource=resources[1],
                affected_resource=resources[1].name,
                title="Storage access review recommended",
                description="Simulated finding: review public access settings for the demo storage bucket.",
                recommendation=(
                    "Review the bucket's public access block, policy, and ACL settings "
                    "before connecting live infrastructure."
                ),
                severity="high",
                simulated=True,
            ),
            SecurityFinding(
                user=user,
                resource=resources[2],
                affected_resource=resources[2].name,
                title="Database maintenance window",
                description="Simulated finding: a maintenance window is approaching for the demo database.",
                recommendation=(
                    "Review the planned database maintenance window and confirm it fits "
                    "the service's availability requirements."
                ),
                severity="medium",
                simulated=True,
            ),
            Alert(
                user=user,
                title="Demo resource inventory ready",
                message="Three simulated cloud resources have been added to your workspace.",
                severity="info",
            ),
            Alert(
                user=user,
                title="Demo storage review",
                message="Review the simulated storage finding before connecting real infrastructure.",
                severity="high",
            ),
        ]
    )
