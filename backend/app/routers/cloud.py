from datetime import date, datetime, timedelta, timezone
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_current_user
from app.models import Alert, CloudConnection, CloudResource, SecurityFinding, User
from app.services.aws import AWSCloudService, AWSIntegrationError, raise_aws_error
from app.services.security_scanner import AWSSecurityScanner

router = APIRouter(prefix="/api", tags=["cloud management"])


class ConnectionCreate(BaseModel):
    provider: Literal["aws", "azure", "gcp"]
    display_name: str = Field(min_length=2, max_length=100)
    region: str | None = Field(default=None, max_length=64)
    account_identifier: str | None = Field(default=None, max_length=128)


class ConnectionPublic(BaseModel):
    id: int
    provider: str
    display_name: str
    status: str
    region: str | None
    account_identifier: str | None
    simulated: bool
    last_synced_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)


class ResourceCreate(BaseModel):
    connection_id: int | None = None
    provider: Literal["aws", "azure", "gcp"]
    name: str = Field(min_length=1, max_length=120)
    resource_type: str = Field(min_length=1, max_length=64)
    region: str = Field(min_length=1, max_length=64)
    status: str = Field(min_length=1, max_length=32)
    monthly_cost: int = Field(default=0, ge=0)
    tags: dict[str, str] = Field(default_factory=dict)


class ResourcePublic(BaseModel):
    id: int
    connection_id: int | None
    provider: str
    name: str
    resource_type: str
    region: str
    status: str
    monthly_cost: int
    tags: dict[str, str]
    metrics: dict[str, float | None]
    last_synced_at: datetime | None
    simulated: bool

    model_config = ConfigDict(from_attributes=True)


class FindingPublic(BaseModel):
    id: int
    finding_id: str
    resource_id: int | None
    affected_resource: str
    title: str
    description: str
    recommendation: str
    severity: str
    status: str
    simulated: bool
    detected_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AlertPublic(BaseModel):
    id: int
    title: str
    message: str
    severity: str
    is_read: bool
    simulated: bool
    status: str
    created_at: datetime
    acknowledged_at: datetime | None
    resolved_at: datetime | None

    model_config = ConfigDict(from_attributes=True)


class DashboardSummary(BaseModel):
    total_resources: int
    active_connections: int
    open_findings: int
    unread_alerts: int
    simulated_resources: int


class AWSConnectionCreate(BaseModel):
    display_name: str = Field(min_length=2, max_length=100)
    region: str = Field(default="us-east-1", min_length=1, max_length=64)

    model_config = ConfigDict(extra="forbid")


class SyncResponse(BaseModel):
    connection_id: int
    synchronized_at: datetime | None
    resource_count: int
    simulated: bool
    warnings: list[str] = Field(default_factory=list)


class SecurityScanResponse(BaseModel):
    findings: list[FindingPublic]
    checks: dict[str, str]
    simulated: bool


class ServiceCost(BaseModel):
    service: str
    amount: float


class CostReport(BaseModel):
    period_start: date
    period_end: date
    total: float
    currency: str
    estimated: bool
    simulated: bool
    services: list[ServiceCost]


def _aws_or_http_error(error: AWSIntegrationError) -> HTTPException:
    return HTTPException(status_code=error.status_code, detail=str(error))


def _create_or_reopen_alert(
    db: Session, user_id: int, title: str, message: str, severity: str, deduplication_key: str
) -> Alert:
    alert = db.scalar(
        select(Alert).where(Alert.user_id == user_id, Alert.deduplication_key == deduplication_key)
    )
    if alert is not None:
        if alert.status == "resolved":
            alert.status = "active"
            alert.is_read = False
            alert.acknowledged_at = None
            alert.resolved_at = None
            alert.title = title
            alert.message = message
            alert.severity = severity
        return alert
    alert = Alert(
        user_id=user_id,
        title=title,
        message=message,
        severity=severity,
        simulated=False,
        deduplication_key=deduplication_key,
    )
    db.add(alert)
    return alert


def _check_for_finding(finding_id: str) -> str | None:
    finding_check_prefixes = (
        ("s3-public-access-block", "s3_public_access_block"),
        ("s3-public-policy", "s3_bucket_policy"),
        ("s3-public-acl", "s3_bucket_acl"),
        ("s3-encryption", "s3_encryption"),
        ("security-group-ingress", "security_groups"),
        ("ec2-public-ip", "ec2_configuration"),
        ("ebs-encryption", "ec2_configuration"),
        ("rds-", "rds_configuration"),
        ("iam-root-mfa", "root_mfa"),
        ("iam-user-mfa", "iam_user_mfa"),
    )
    return next((check for prefix, check in finding_check_prefixes if finding_id.startswith(prefix)), None)


@router.get("/connections", response_model=list[ConnectionPublic])
def list_connections(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[CloudConnection]:
    return list(
        db.scalars(
            select(CloudConnection)
            .where(CloudConnection.user_id == current_user.id)
            .order_by(CloudConnection.created_at.desc())
        )
    )


@router.post("/connections", response_model=ConnectionPublic, status_code=status.HTTP_201_CREATED)
def create_connection(
    payload: ConnectionCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> CloudConnection:
    connection = CloudConnection(
        user_id=current_user.id,
        provider=payload.provider,
        display_name=payload.display_name.strip(),
        region=payload.region,
        account_identifier=payload.account_identifier,
        status="pending",
        simulated=True,
    )
    if len(connection.display_name) < 2:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Name must contain at least 2 characters")
    existing = db.scalar(
        select(CloudConnection).where(
            CloudConnection.user_id == current_user.id,
            CloudConnection.display_name == connection.display_name,
        )
    )
    if existing is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="A connection with this name already exists")
    db.add(connection)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A connection with this name already exists",
        ) from None
    db.refresh(connection)
    return connection


@router.post("/connections/aws", response_model=ConnectionPublic, status_code=status.HTTP_201_CREATED)
def create_aws_connection(
    payload: AWSConnectionCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> CloudConnection:
    display_name = payload.display_name.strip()
    if len(display_name) < 2:
        raise HTTPException(status_code=422, detail="Name must contain at least 2 characters")
    existing = db.scalar(
        select(CloudConnection).where(
            CloudConnection.user_id == current_user.id,
            CloudConnection.display_name == display_name,
        )
    )
    if existing is not None:
        raise HTTPException(status_code=409, detail="A connection with this name already exists")
    try:
        identity = AWSCloudService(payload.region).validate()
    except AWSIntegrationError as error:
        raise _aws_or_http_error(error) from None
    connection = CloudConnection(
        user_id=current_user.id,
        provider="aws",
        display_name=display_name,
        region=payload.region,
        account_identifier=identity["account_id"],
        status="connected",
        simulated=False,
    )
    db.add(connection)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="A connection with this name already exists") from None
    db.refresh(connection)
    return connection


@router.post("/connections/{connection_id}/sync", response_model=SyncResponse)
def synchronize_connection(
    connection_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> SyncResponse:
    connection = db.scalar(
        select(CloudConnection).where(
            CloudConnection.id == connection_id,
            CloudConnection.user_id == current_user.id,
        )
    )
    if connection is None:
        raise HTTPException(status_code=404, detail="Connection not found")
    if connection.simulated:
        count = db.scalar(
            select(func.count()).select_from(CloudResource).where(
                CloudResource.user_id == current_user.id,
                CloudResource.connection_id == connection.id,
            )
        ) or 0
        return SyncResponse(
            connection_id=connection.id,
            synchronized_at=connection.last_synced_at,
            resource_count=count,
            simulated=True,
        )
    try:
        discovered, warnings = AWSCloudService(connection.region).discover_resources()
    except AWSIntegrationError as error:
        connection.status = "degraded" if error.status_code == 403 else "error"
        db.commit()
        raise _aws_or_http_error(error) from None

    existing = list(
        db.scalars(
            select(CloudResource).where(
                CloudResource.user_id == current_user.id,
                CloudResource.connection_id == connection.id,
            )
        )
    )
    by_key = {(resource.resource_type, resource.tags.get("resource_id", resource.name)): resource for resource in existing}
    for resource in existing:
        resource.status = "not_found"
    for item in discovered:
        resource = by_key.get((item["resource_type"], item["tags"].get("resource_id", item["name"])))
        if resource is None:
            resource = CloudResource(
                user_id=current_user.id,
                connection_id=connection.id,
                provider="aws",
                name=item["name"],
                resource_type=item["resource_type"],
                region=item["region"],
                status=item["status"],
                tags=item["tags"],
                metrics=item["metrics"],
                last_synced_at=datetime.now(timezone.utc),
                simulated=False,
            )
            db.add(resource)
        else:
            resource.name = item["name"]
            resource.region = item["region"]
            resource.status = item["status"]
            resource.tags = item["tags"]
            resource.metrics = item["metrics"]
            resource.last_synced_at = datetime.now(timezone.utc)
    synchronized_at = datetime.now(timezone.utc)
    connection.last_synced_at = synchronized_at
    connection.status = "connected"
    for item in discovered:
        cpu = item["metrics"].get("cpu_utilization")
        if cpu is not None and cpu >= 80:
            _create_or_reopen_alert(
                db,
                current_user.id,
                "High CPU utilization",
                f"{item['name']} reported {cpu:.1f}% average CPU utilization in the last hour (threshold: 80%).",
                "high",
                f"cpu:{connection.id}:{item['resource_type']}:{item['tags'].get('resource_id', item['name'])}",
            )
    db.commit()
    return SyncResponse(
        connection_id=connection.id,
        synchronized_at=synchronized_at,
        resource_count=len(discovered),
        simulated=False,
        warnings=warnings,
    )


@router.get("/resources", response_model=list[ResourcePublic])
def list_resources(
    provider: str | None = Query(default=None, min_length=1, max_length=32),
    region: str | None = Query(default=None, min_length=1, max_length=64),
    resource_type: str | None = Query(default=None, min_length=1, max_length=64),
    resource_status: str | None = Query(default=None, alias="status", min_length=1, max_length=32),
    search: str | None = Query(default=None, min_length=1, max_length=120),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=500),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[CloudResource]:
    query = select(CloudResource).where(CloudResource.user_id == current_user.id)
    if provider:
        query = query.where(CloudResource.provider == provider.lower())
    if region:
        query = query.where(CloudResource.region == region)
    if resource_type:
        query = query.where(CloudResource.resource_type == resource_type)
    if resource_status:
        query = query.where(CloudResource.status == resource_status)
    if search:
        term = f"%{search.strip()}%"
        query = query.where(
            CloudResource.name.ilike(term)
            | CloudResource.region.ilike(term)
            | CloudResource.resource_type.ilike(term)
        )
    query = query.order_by(CloudResource.created_at.desc()).offset(offset).limit(limit)
    return list(db.scalars(query))


@router.post("/resources", response_model=ResourcePublic, status_code=status.HTTP_201_CREATED)
def create_resource(
    payload: ResourceCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> CloudResource:
    if payload.connection_id is not None:
        connection = db.scalar(
            select(CloudConnection).where(
                CloudConnection.id == payload.connection_id,
                CloudConnection.user_id == current_user.id,
            )
        )
        if connection is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Connection not found")
        if connection.provider != payload.provider:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Provider must match the connection")

    resource = CloudResource(
        user_id=current_user.id,
        connection_id=payload.connection_id,
        provider=payload.provider,
        name=payload.name.strip(),
        resource_type=payload.resource_type.strip(),
        region=payload.region.strip(),
        status=payload.status.strip(),
        monthly_cost=payload.monthly_cost,
        tags=payload.tags,
        simulated=True,
    )
    db.add(resource)
    db.commit()
    db.refresh(resource)
    return resource


@router.get("/alerts", response_model=list[AlertPublic])
def list_alerts(
    alert_status: Literal["active", "acknowledged", "resolved"] | None = Query(default=None, alias="status"),
    limit: int = Query(default=50, ge=1, le=200),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[Alert]:
    query = select(Alert).where(Alert.user_id == current_user.id)
    if alert_status:
        query = query.where(Alert.status == alert_status)
    return list(
        db.scalars(
            query.order_by(Alert.created_at.desc()).limit(limit)
        )
    )


@router.patch("/alerts/{alert_id}/acknowledge", response_model=AlertPublic)
def acknowledge_alert(
    alert_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Alert:
    alert = db.scalar(select(Alert).where(Alert.id == alert_id, Alert.user_id == current_user.id))
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    if alert.status == "active":
        alert.status = "acknowledged"
        alert.is_read = True
        alert.acknowledged_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(alert)
    return alert


@router.patch("/alerts/{alert_id}/resolve", response_model=AlertPublic)
def resolve_alert(
    alert_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Alert:
    alert = db.scalar(select(Alert).where(Alert.id == alert_id, Alert.user_id == current_user.id))
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    if alert.status != "resolved":
        alert.status = "resolved"
        alert.is_read = True
        alert.resolved_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(alert)
    return alert


@router.get("/security/findings", response_model=list[FindingPublic])
def list_security_findings(
    finding_status: Literal["open", "resolved"] | None = Query(default=None, alias="status"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[SecurityFinding]:
    query = select(SecurityFinding).where(SecurityFinding.user_id == current_user.id)
    if finding_status:
        query = query.where(SecurityFinding.status == finding_status)
    return list(db.scalars(query.order_by(SecurityFinding.detected_at.desc())))


@router.post("/connections/{connection_id}/scan", response_model=SecurityScanResponse)
def scan_connection(
    connection_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> SecurityScanResponse:
    connection = db.scalar(
        select(CloudConnection).where(
            CloudConnection.id == connection_id,
            CloudConnection.user_id == current_user.id,
        )
    )
    if connection is None:
        raise HTTPException(status_code=404, detail="Connection not found")
    if connection.simulated:
        demo_findings = list(
            db.scalars(
                select(SecurityFinding).where(
                    SecurityFinding.user_id == current_user.id,
                    SecurityFinding.simulated.is_(True),
                    SecurityFinding.status == "open",
                )
            )
        )
        return SecurityScanResponse(
            findings=demo_findings,
            checks={"demo_mode": "simulated_data"},
            simulated=True,
        )

    scanner = AWSSecurityScanner(AWSCloudService(connection.region))
    try:
        report = scanner.scan()
    except AWSIntegrationError as error:
        connection.status = "degraded" if error.status_code == 403 else "error"
        db.commit()
        raise _aws_or_http_error(error) from None
    persisted: list[SecurityFinding] = []
    for item in report["findings"]:
        finding_id = f"{connection.id}:{item['finding_id']}"
        finding = db.scalar(
            select(SecurityFinding).where(
                SecurityFinding.user_id == current_user.id,
                SecurityFinding.finding_id == finding_id,
            )
        )
        if finding is None:
            finding = SecurityFinding(
                user_id=current_user.id,
                finding_id=finding_id,
                affected_resource=item["affected_resource"],
                title=item["title"],
                description=item["description"],
                recommendation=item["recommendation"],
                severity=item["severity"],
                simulated=False,
            )
            db.add(finding)
        else:
            finding.status = "open"
            finding.affected_resource = item["affected_resource"]
            finding.description = item["description"]
            finding.recommendation = item["recommendation"]
            finding.detected_at = datetime.now(timezone.utc)
        _create_or_reopen_alert(
            db,
            current_user.id,
            item["title"],
            f"{item['affected_resource']}: {item['description']}",
            item["severity"],
            f"security:{finding_id}",
        )
        persisted.append(finding)
    observed = {f"{connection.id}:{item['finding_id']}" for item in report["findings"]}
    previous_findings = list(
        db.scalars(
            select(SecurityFinding).where(
                SecurityFinding.user_id == current_user.id,
                SecurityFinding.simulated.is_(False),
                SecurityFinding.finding_id.like(f"{connection.id}:%"),
                SecurityFinding.status == "open",
            )
        )
    )
    for finding in previous_findings:
        if finding.finding_id in observed:
            continue
        raw_finding_id = finding.finding_id.partition(":")[2]
        check = _check_for_finding(raw_finding_id)
        if check is None or report["checks"].get(check) != "complete":
            continue
        finding.status = "resolved"
        alert = db.scalar(
            select(Alert).where(
                Alert.user_id == current_user.id,
                Alert.deduplication_key == f"security:{finding.finding_id}",
            )
        )
        if alert is not None and alert.status != "resolved":
            alert.status = "resolved"
            alert.is_read = True
            alert.resolved_at = datetime.now(timezone.utc)
    db.commit()
    return SecurityScanResponse(findings=persisted, checks=report["checks"], simulated=False)


@router.get("/connections/{connection_id}/costs", response_model=CostReport)
def get_connection_costs(
    connection_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> CostReport:
    connection = db.scalar(
        select(CloudConnection).where(
            CloudConnection.id == connection_id,
            CloudConnection.user_id == current_user.id,
        )
    )
    if connection is None:
        raise HTTPException(status_code=404, detail="Connection not found")
    today = datetime.now(timezone.utc).date()
    start = today.replace(day=1)
    if connection.simulated:
        resources = list(
            db.scalars(
                select(CloudResource).where(
                    CloudResource.user_id == current_user.id,
                    CloudResource.connection_id == connection.id,
                    CloudResource.simulated.is_(True),
                )
            )
        )
        totals: dict[str, float] = {}
        for resource in resources:
            service = {"compute": "Compute (demo)", "storage": "Storage (demo)", "database": "Database (demo)"}.get(
                resource.resource_type, f"{resource.resource_type.title()} (demo)"
            )
            totals[service] = totals.get(service, 0) + resource.monthly_cost
        return CostReport(
            period_start=start,
            period_end=today,
            total=sum(totals.values()),
            currency="USD",
            estimated=True,
            simulated=True,
            services=[ServiceCost(service=name, amount=amount) for name, amount in sorted(totals.items())],
        )

    end = today + timedelta(days=1)
    try:
        cost_client = AWSCloudService("us-east-1").client("ce", "us-east-1")
        request: dict[str, Any] = {
            "TimePeriod": {"Start": start.isoformat(), "End": end.isoformat()},
            "Granularity": "MONTHLY",
            "Metrics": ["UnblendedCost"],
            "GroupBy": [{"Type": "DIMENSION", "Key": "SERVICE"}],
        }
        results: list[dict[str, Any]] = []
        next_page_token = None
        while True:
            if next_page_token:
                request["NextPageToken"] = next_page_token
            response = cost_client.get_cost_and_usage(**request)
            results.extend(response.get("ResultsByTime", []))
            next_page_token = response.get("NextPageToken")
            if not next_page_token:
                break
    except Exception as error:
        try:
            raise_aws_error(error)
        except AWSIntegrationError as aws_error:
            raise _aws_or_http_error(aws_error) from None
    if not results:
        raise HTTPException(status_code=503, detail="AWS Cost Explorer returned no cost data for this period.")
    groups = [group for result in results for group in result.get("Groups", [])]
    currency = "USD"
    services: list[ServiceCost] = []
    for group in groups:
        amount = group.get("Metrics", {}).get("UnblendedCost", {})
        currency = amount.get("Unit", currency)
        services.append(ServiceCost(service=group.get("Keys", ["Unknown"])[0], amount=float(amount.get("Amount", 0))))
    total_data = results[0].get("Total", {}).get("UnblendedCost", {}) if results else {}
    if "Amount" not in total_data and not services:
        raise HTTPException(status_code=503, detail="AWS Cost Explorer did not provide a cost total for this period.")
    currency = total_data.get("Unit", currency)
    total = float(total_data.get("Amount", sum(service.amount for service in services)))
    estimated = any(result.get("Estimated", True) for result in results)
    return CostReport(
        period_start=start,
        period_end=today,
        total=total,
        currency=currency,
        estimated=estimated,
        simulated=False,
        services=sorted(services, key=lambda service: service.amount, reverse=True),
    )


@router.get("/dashboard/summary", response_model=DashboardSummary)
def dashboard_summary(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> DashboardSummary:
    user_id = current_user.id
    return DashboardSummary(
        total_resources=db.scalar(
            select(func.count()).select_from(CloudResource).where(CloudResource.user_id == user_id)
        )
        or 0,
        active_connections=db.scalar(
            select(func.count())
            .select_from(CloudConnection)
            .where(CloudConnection.user_id == user_id, CloudConnection.status == "connected")
        )
        or 0,
        open_findings=db.scalar(
            select(func.count())
            .select_from(SecurityFinding)
            .where(SecurityFinding.user_id == user_id, SecurityFinding.status == "open")
        )
        or 0,
        unread_alerts=db.scalar(
            select(func.count()).select_from(Alert).where(Alert.user_id == user_id, Alert.is_read.is_(False))
        )
        or 0,
        simulated_resources=db.scalar(
            select(func.count())
            .select_from(CloudResource)
            .where(CloudResource.user_id == user_id, CloudResource.simulated.is_(True))
        )
        or 0,
    )
