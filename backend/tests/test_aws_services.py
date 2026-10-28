from datetime import datetime, timezone
from unittest.mock import patch

import boto3
import pytest
from botocore.exceptions import ClientError, NoCredentialsError
from botocore.stub import Stubber

from app.services.aws import AWSCloudService, AWSIntegrationError, raise_aws_error
from app.services.security_scanner import AWSSecurityScanner


@pytest.fixture(autouse=True)
def isolated_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test-access-key")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test-secret-key")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")


def test_sts_validates_connection_without_returning_credentials():
    aws = AWSCloudService("us-west-2")
    sts = boto3.client("sts", region_name="us-east-1")
    with Stubber(sts) as stubber:
        stubber.add_response(
            "get_caller_identity",
            {"UserId": "AIDATEST", "Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/test"},
        )
        with patch.object(aws, "client", return_value=sts):
            assert aws.validate() == {
                "account_id": "123456789012",
                "arn": "arn:aws:iam::123456789012:user/test",
            }


def test_invalid_credentials_and_permission_errors_are_reported():
    with pytest.raises(AWSIntegrationError, match="credentials are unavailable"):
        raise_aws_error(NoCredentialsError())
    access_denied = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "denied"}},
        "DescribeInstances",
    )
    with pytest.raises(AWSIntegrationError, match="lacks permission") as error:
        raise_aws_error(access_denied)
    assert error.value.status_code == 403


def test_discovers_ec2_s3_rds_and_keeps_missing_metrics_distinct_from_zero():
    aws = AWSCloudService("us-east-1")
    clients = {
        service: boto3.client(service, region_name="us-east-1")
        for service in ("ec2", "cloudwatch", "s3", "rds")
    }
    stubbers = [Stubber(client) for client in clients.values()]
    for stubber in stubbers:
        stubber.activate()
    try:
        stubbers[0].add_response(
            "describe_instances",
            {
                "Reservations": [
                    {
                        "Instances": [
                            {
                                "InstanceId": "i-0123456789abcdef0",
                                "State": {"Code": 16, "Name": "running"},
                                "Placement": {"AvailabilityZone": "us-east-1a"},
                                "Tags": [{"Key": "Name", "Value": "api"}],
                            }
                        ]
                    }
                ]
            },
        )
        stubbers[2].add_response(
            "list_buckets",
            {"Buckets": [{"Name": "assets-bucket", "CreationDate": datetime(2026, 1, 1, tzinfo=timezone.utc)}]},
        )
        stubbers[2].add_response("get_bucket_location", {}, {"Bucket": "assets-bucket"})
        stubbers[3].add_response(
            "describe_db_instances",
            {
                "DBInstances": [
                    {"DBInstanceIdentifier": "analytics", "DBInstanceStatus": "available", "AvailabilityZone": "us-east-1b"}
                ]
            },
        )
        with patch.object(aws, "client", side_effect=lambda name, region=None: clients[name]), patch.object(
            aws, "_metric", side_effect=[0, None]
        ):
            resources, warnings = aws.discover_resources()
        assert warnings == []
        assert [(resource["resource_type"], resource["name"]) for resource in resources] == [
            ("ec2", "api"),
            ("s3", "assets-bucket"),
            ("rds", "analytics"),
        ]
        assert resources[0]["metrics"] == {"cpu_utilization": 0, "memory_utilization": None}
        assert resources[0]["region"] == "us-east-1"
    finally:
        for stubber in stubbers:
            stubber.deactivate()


def test_cloudwatch_metric_averages_datapoints_and_returns_none_when_unpublished():
    aws = AWSCloudService("us-east-1")
    cloudwatch = boto3.client("cloudwatch", region_name="us-east-1")
    with Stubber(cloudwatch) as stubber:
        stubber.add_response(
            "get_metric_statistics",
            {
                "Label": "CPUUtilization",
                "Datapoints": [
                    {"Timestamp": datetime(2026, 1, 1, tzinfo=timezone.utc), "Average": 0.0, "Unit": "Percent"},
                    {"Timestamp": datetime(2026, 1, 1, 0, 5, tzinfo=timezone.utc), "Average": 20.0, "Unit": "Percent"},
                ],
            },
        )
        with patch.object(aws, "client", return_value=cloudwatch):
            assert aws._metric(cloudwatch, "i-0123456789abcdef0", "CPUUtilization", "AWS/EC2") == 10.0
    with Stubber(cloudwatch) as stubber:
        stubber.add_response("get_metric_statistics", {"Label": "mem_used_percent", "Datapoints": []})
        with patch.object(aws, "client", return_value=cloudwatch):
            assert aws._metric(cloudwatch, "i-0123456789abcdef0", "mem_used_percent", "CWAgent") is None


def test_security_scanner_flags_sensitive_ipv6_ingress_and_permission_limits():
    class FakeAWS:
        def client(self, service, region=None):
            if service == "ec2":
                return FakeEC2()
            return FakeIAM()

    class FakeEC2:
        def describe_security_groups(self):
            return {
                "SecurityGroups": [
                    {
                        "GroupId": "sg-example",
                        "IpPermissions": [
                            {
                                "IpProtocol": "tcp",
                                "FromPort": 22,
                                "ToPort": 22,
                                "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                            }
                        ],
                    }
                ]
            }

    class FakeIAM:
        def get_account_summary(self):
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "denied"}}, "GetAccountSummary")

        def get_paginator(self, operation):
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "denied"}}, "ListUsers")

    scanner = AWSSecurityScanner(FakeAWS())
    scanner._scan_security_groups()
    assert scanner.checks["security_groups"] == "complete"
    assert scanner.findings[0]["finding_id"] == "security-group-ingress:sg-example:tcp:22:22"
    assert scanner.findings[0]["severity"] == "high"
    scanner._scan_iam()
    assert scanner.checks["root_mfa"] == "permission_denied"
    assert scanner.checks["iam_user_mfa"] == "permission_denied"
    assert len(scanner.findings) == 1


def test_security_scanner_detects_public_s3_access_and_missing_encryption():
    class FakeS3:
        def list_buckets(self):
            return {"Buckets": [{"Name": "public-data"}]}

        def get_public_access_block(self, **kwargs):
            return {
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": False,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                }
            }

        def get_bucket_policy_status(self, **kwargs):
            return {"PolicyStatus": {"IsPublic": True}}

        def get_bucket_acl(self, **kwargs):
            return {
                "Grants": [
                    {"Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/global/AllUsers"}}
                ]
            }

        def get_bucket_encryption(self, **kwargs):
            raise ClientError(
                {"Error": {"Code": "ServerSideEncryptionConfigurationNotFoundError", "Message": "missing"}},
                "GetBucketEncryption",
            )

    class FakeAWS:
        def client(self, service, region=None):
            return FakeS3()

    scanner = AWSSecurityScanner(FakeAWS())
    scanner._scan_s3()
    assert scanner.checks["s3_inventory"] == "complete"
    assert {finding["finding_id"] for finding in scanner.findings} == {
        "s3-public-access-block:public-data",
        "s3-public-policy:public-data",
        "s3-public-acl:public-data",
        "s3-encryption:public-data",
    }


def test_security_scanner_detects_unencrypted_resources_and_missing_mfa():
    class FakeEC2:
        def describe_instances(self):
            return {
                "Reservations": [
                    {
                        "Instances": [
                            {
                                "InstanceId": "i-example",
                                "PublicIpAddress": "203.0.113.12",
                                "BlockDeviceMappings": [{"Ebs": {"Encrypted": False, "VolumeId": "vol-example"}}],
                            }
                        ]
                    }
                ]
            }

    class FakeRDS:
        def describe_db_instances(self):
            return {
                "DBInstances": [
                    {
                        "DBInstanceIdentifier": "public-db",
                        "StorageEncrypted": False,
                        "PubliclyAccessible": True,
                    }
                ]
            }

    class UserPaginator:
        def paginate(self):
            return [{"Users": [{"UserName": "operator"}]}]

    class FakeIAM:
        def get_account_summary(self):
            return {"SummaryMap": {"AccountMFAEnabled": 0}}

        def get_paginator(self, operation):
            assert operation == "list_users"
            return UserPaginator()

        def list_mfa_devices(self, **kwargs):
            return {"MFADevices": []}

    class FakeAWS:
        def client(self, service, region=None):
            return {"ec2": FakeEC2(), "rds": FakeRDS(), "iam": FakeIAM()}[service]

    scanner = AWSSecurityScanner(FakeAWS())
    scanner._scan_compute_and_databases()
    scanner._scan_iam()
    finding_ids = {finding["finding_id"] for finding in scanner.findings}
    assert finding_ids == {
        "ec2-public-ip:i-example",
        "ebs-encryption:vol-example",
        "rds-encryption:public-db",
        "rds-public-access:public-db",
        "iam-root-mfa",
        "iam-user-mfa:operator",
    }
    assert scanner.checks == {
        "ec2_configuration": "complete",
        "rds_configuration": "complete",
        "root_mfa": "complete",
        "iam_user_mfa": "complete",
    }
