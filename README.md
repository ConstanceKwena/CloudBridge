# CloudBridge

## WTC Reference

**WTC-JLCNQUHE**

CloudBridge is a cloud management and security dashboard for connecting infrastructure visibility, operational alerts, and security findings in one place. Demo Mode is available without cloud credentials; a live AWS connection can use the backend's standard AWS credential provider chain.

## Architecture

- `backend/`: FastAPI application, SQLAlchemy persistence, Alembic migrations, and pytest suite.
- `frontend/`: React + Vite dashboard, Tailwind styling, and Vitest suite.
- SQLite is the local default. Set `DATABASE_URL` to a PostgreSQL SQLAlchemy URL to use PostgreSQL.
- Demo cloud resources and sample cost estimates are explicitly labeled simulated and are never connected to a real provider.
- AWS integration is read-only and runs only in the backend. Access keys and session credentials are never accepted by frontend APIs or stored in CloudBridge.

## Requirements

- Python 3.11+
- Node.js 20+ and npm
- SQLite (included with Python), or PostgreSQL

## Local setup

Copy `.env.example` to `.env` and set a unique `JWT_SECRET_KEY` before exposing the service. In a terminal:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r backend\requirements.txt
python -m uvicorn app.main:app --reload --app-dir backend
```

In another terminal:

```powershell
cd frontend
npm ci
npm run dev
```

The API is available at `http://localhost:8000`, interactive API documentation at `/docs`, and the frontend at `http://localhost:5173`. The health endpoint is `GET /health`. Apply schema migrations before starting the API:

```powershell
python -m alembic -c backend\alembic.ini upgrade head
python -m uvicorn app.main:app --reload --app-dir backend
```

The frontend uses `/api` as its API base and Vite proxies it to the backend in development.

Run backend tests from `backend\` with `python -m pytest tests`. Run frontend tests from `frontend\` with `npm test`, and create a production build with `npm run build`.

## Authentication and data

Register through the UI or `POST /api/auth/register`, then sign in through `POST /api/auth/login`. Authenticated endpoints require `Authorization: Bearer <access_token>`. User-owned data is scoped to the authenticated user. Never commit `.env` or use development secrets in production.

Alembic migrations manage schema changes. `create_all` on startup creates new development databases but does not upgrade existing databases; apply migrations after upgrading CloudBridge.

## AWS integration

Create a connection from **Connections → Add connection → Live AWS**. CloudBridge validates the backend AWS identity with STS; it does not accept or return credentials. Then synchronize inventory or run a security assessment. AWS access uses boto3's default credential chain, which supports environment credentials, shared AWS profiles, IAM roles attached to EC2/ECS/Lambda, web identity, and temporary credentials. Configure the provider on the backend host only; never put AWS values in frontend environment variables or browser requests.

For local development, configure an AWS profile using your normal AWS tooling, then set the profile in the same PowerShell session that starts the backend:

```powershell
$env:AWS_PROFILE = "cloudbridge-read-only"
$env:AWS_DEFAULT_REGION = "us-east-1"
python -m uvicorn app.main:app --reload --app-dir backend
```

Use an IAM role for hosted deployments. A minimal custom policy must allow these read-only actions (some list/describe APIs require `Resource: "*"`):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "sts:GetCallerIdentity",
        "ec2:DescribeInstances",
        "ec2:DescribeSecurityGroups",
        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation",
        "s3:GetPublicAccessBlock",
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketAcl",
        "s3:GetEncryptionConfiguration",
        "rds:DescribeDBInstances",
        "cloudwatch:GetMetricStatistics",
        "iam:GetAccountSummary",
        "iam:ListUsers",
        "iam:ListMFADevices",
        "ce:GetCostAndUsage"
      ],
      "Resource": "*"
    }
  ]
}
```

Remove Cost Explorer or IAM permissions if those reports are not required. Billing data may be unavailable until Cost Explorer is enabled and has processed usage; missing permissions are returned as errors, and security checks with insufficient permissions are labeled incomplete. Memory utilization is displayed only when the `CWAgent` `mem_used_percent` metric is published. CPU and memory values absent from CloudWatch are shown as unavailable, not zero.

`POST /api/connections/aws` validates and creates a live AWS connection. `POST /api/connections/{id}/sync` refreshes EC2, S3, RDS, and available CloudWatch metrics. `POST /api/connections/{id}/scan` runs read-only S3, network, encryption, and IAM checks. `GET /api/connections/{id}/costs` retrieves month-to-date Cost Explorer data. `GET /api/security/findings` returns findings. `GET /api/alerts` lists user-owned alerts; `PATCH /api/alerts/{id}/acknowledge` and `/resolve` manage their lifecycle.

The scanner reports only detected configuration issues; it does not certify an account as secure. AWS APIs can be eventually consistent, checks are limited to the documented resources, and findings do not replace a full security audit. Resource synchronization and assessment never modify or delete AWS resources. Cost Explorer values may be estimates. Monitoring generates a deduplicated high-severity alert when an EC2 instance's available one-hour average CPU metric is at least 80%.

Live connections currently use the backend execution identity for each authenticated CloudBridge user. This is appropriate for a single-tenant deployment or trusted demo environment; before exposing a shared multi-tenant service, implement tenant-specific role assumption and authorization boundaries so users cannot independently invoke a shared AWS identity.

## Demo Mode

Registration creates clearly labeled simulated AWS resources, findings, and alerts. Demo cost reports are derived from sample resource estimates and are marked estimated and simulated. Demo Mode makes no AWS calls; live API responses are never filled with mock fallbacks.

## Day 1 foundation

Included: health check, persistence models and migrations, registration/login/profile, user-scoped connection/resource/alert APIs, a responsive dashboard, and automated tests. Real AWS access, scanning, cost analysis, intelligent alert delivery, and deployment automation are planned for later days.
