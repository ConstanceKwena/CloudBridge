from datetime import datetime, timedelta, timezone
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError, PartialCredentialsError


class AWSIntegrationError(Exception):
    def __init__(self, message: str, *, status_code: int = 502):
        super().__init__(message)
        self.status_code = status_code


def raise_aws_error(error: Exception) -> None:
    if isinstance(error, (NoCredentialsError, PartialCredentialsError)):
        raise AWSIntegrationError("AWS credentials are unavailable or incomplete. Configure the AWS credential provider chain.") from None
    if isinstance(error, ClientError):
        code = error.response.get("Error", {}).get("Code", "AWSRequestFailed")
        if code in {
            "InvalidAccessKeyId",
            "InvalidClientTokenId",
            "UnrecognizedClientException",
            "SignatureDoesNotMatch",
            "ExpiredToken",
            "ExpiredTokenException",
        }:
            raise AWSIntegrationError("AWS rejected the configured credentials. Check the credential provider and retry.", status_code=401) from None
        if code in {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "AuthorizationError"}:
            raise AWSIntegrationError("The AWS identity is valid but lacks permission for this operation.", status_code=403) from None
        raise AWSIntegrationError(f"AWS request failed ({code}).") from None
    if isinstance(error, BotoCoreError):
        raise AWSIntegrationError("Unable to communicate with AWS. Check the network and AWS configuration.") from None
    raise error


class AWSCloudService:
    """Uses boto3's standard provider chain; credentials are never accepted as request data."""

    def __init__(self, region: str | None = None):
        self.session = boto3.Session(region_name=region)
        self.region = region or self.session.region_name or "us-east-1"

    def client(self, service: str, region: str | None = None):
        return self.session.client(service, region_name=region or self.region)

    def validate(self) -> dict[str, str]:
        try:
            identity = self.client("sts", "us-east-1").get_caller_identity()
        except Exception as error:
            raise_aws_error(error)
        return {"account_id": identity["Account"], "arn": identity["Arn"]}

    def _metric(self, cloudwatch, instance_id: str, metric_name: str, namespace: str) -> float | None:
        end = datetime.now(timezone.utc)
        response = cloudwatch.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
            StartTime=end - timedelta(hours=1),
            EndTime=end,
            Period=300,
            Statistics=["Average"],
        )
        values = [point["Average"] for point in response.get("Datapoints", []) if "Average" in point]
        return round(sum(values) / len(values), 2) if values else None

    def discover_resources(self) -> tuple[list[dict[str, Any]], list[str]]:
        resources: list[dict[str, Any]] = []
        warnings: list[str] = []
        ec2 = self.client("ec2")
        cloudwatch = self.client("cloudwatch")
        try:
            reservations = ec2.describe_instances().get("Reservations", [])
            for reservation in reservations:
                for instance in reservation.get("Instances", []):
                    instance_id = instance["InstanceId"]
                    tags = {tag["Key"]: tag["Value"] for tag in instance.get("Tags", [])}
                    availability_zone = instance.get("Placement", {}).get("AvailabilityZone")
                    metrics: dict[str, float | None] = {"cpu_utilization": None, "memory_utilization": None}
                    for key, name, namespace in (
                        ("cpu_utilization", "CPUUtilization", "AWS/EC2"),
                        ("memory_utilization", "mem_used_percent", "CWAgent"),
                    ):
                        try:
                            metrics[key] = self._metric(cloudwatch, instance_id, name, namespace)
                        except ClientError as error:
                            code = error.response.get("Error", {}).get("Code", "CloudWatchUnavailable")
                            warning = f"CloudWatch metrics unavailable ({code})."
                            if warning not in warnings:
                                warnings.append(warning)
                    resources.append(
                        {
                            "name": tags.get("Name") or instance_id,
                            "resource_type": "ec2",
                            "region": availability_zone[:-1] if availability_zone else self.region,
                            "status": instance.get("State", {}).get("Name", "unknown"),
                            "tags": {
                                **tags,
                                "resource_id": instance_id,
                                "instance_type": instance.get("InstanceType", "unknown"),
                            },
                            "metrics": metrics,
                        }
                    )
        except Exception as error:
            raise_aws_error(error)

        s3 = self.client("s3", "us-east-1")
        try:
            for bucket in s3.list_buckets().get("Buckets", []):
                bucket_name = bucket["Name"]
                location = s3.get_bucket_location(Bucket=bucket_name).get("LocationConstraint") or "us-east-1"
                resources.append(
                    {
                        "name": bucket_name,
                        "resource_type": "s3",
                        "region": location,
                        "status": "active",
                        "tags": {"resource_id": bucket_name},
                        "metrics": {},
                    }
                )
        except Exception as error:
            raise_aws_error(error)

        try:
            for database in self.client("rds").describe_db_instances().get("DBInstances", []):
                availability_zone = database.get("AvailabilityZone")
                resources.append(
                    {
                        "name": database["DBInstanceIdentifier"],
                        "resource_type": "rds",
                        "region": availability_zone[:-1] if availability_zone else self.region,
                        "status": database.get("DBInstanceStatus", "unknown"),
                        "tags": {
                            "resource_id": database["DBInstanceIdentifier"],
                            "engine": database.get("Engine", "unknown"),
                            "instance_class": database.get("DBInstanceClass", "unknown"),
                            "encrypted": str(database.get("StorageEncrypted", False)).lower(),
                            "publicly_accessible": str(database.get("PubliclyAccessible", False)).lower(),
                        },
                        "metrics": {},
                    }
                )
        except Exception as error:
            raise_aws_error(error)
        return resources, warnings


def is_permission_error(error: ClientError) -> bool:
    return error.response.get("Error", {}).get("Code") in {
        "AccessDenied",
        "AccessDeniedException",
        "UnauthorizedOperation",
        "AuthorizationError",
    }


def is_missing_configuration(error: ClientError, *codes: str) -> bool:
    return error.response.get("Error", {}).get("Code") in codes
