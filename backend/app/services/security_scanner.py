from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from app.services.aws import AWSCloudService, is_missing_configuration, is_permission_error, raise_aws_error


SENSITIVE_PORTS = {22, 3389, 3306, 5432, 6379, 27017}


class AWSSecurityScanner:
    def __init__(self, aws: AWSCloudService):
        self.aws = aws
        self.checks: dict[str, str] = {}
        self.findings: list[dict[str, str]] = []

    def _finding(
        self, finding_id: str, resource: str, title: str, severity: str, description: str, recommendation: str
    ) -> None:
        self.findings.append(
            {
                "finding_id": finding_id,
                "affected_resource": resource,
                "title": title,
                "severity": severity,
                "description": description,
                "recommendation": recommendation,
            }
        )

    def _check_failed(self, name: str, error: ClientError) -> None:
        code = error.response.get("Error", {}).get("Code", "AWSRequestFailed")
        if code in {
            "InvalidAccessKeyId",
            "InvalidClientTokenId",
            "UnrecognizedClientException",
            "SignatureDoesNotMatch",
            "ExpiredToken",
            "ExpiredTokenException",
        }:
            raise_aws_error(error)
        self.checks[name] = "permission_denied" if is_permission_error(error) else f"unavailable:{code}"

    def scan(self) -> dict[str, Any]:
        try:
            self._scan_s3()
            self._scan_security_groups()
            self._scan_compute_and_databases()
            self._scan_iam()
        except BotoCoreError as error:
            raise_aws_error(error)
        return {"findings": self.findings, "checks": self.checks}

    def _scan_s3(self) -> None:
        s3 = self.aws.client("s3", "us-east-1")
        try:
            buckets = s3.list_buckets().get("Buckets", [])
        except ClientError as error:
            self._check_failed("s3_inventory", error)
            return
        self.checks["s3_inventory"] = "complete"
        self.checks.update(
            {
                "s3_public_access_block": "complete",
                "s3_bucket_policy": "complete",
                "s3_bucket_acl": "complete",
                "s3_encryption": "complete",
            }
        )
        for bucket in buckets:
            name = bucket["Name"]
            try:
                block = s3.get_public_access_block(Bucket=name).get("PublicAccessBlockConfiguration", {})
                if not all(
                    block.get(setting, False)
                    for setting in (
                        "BlockPublicAcls",
                        "IgnorePublicAcls",
                        "BlockPublicPolicy",
                        "RestrictPublicBuckets",
                    )
                ):
                    self._finding(
                        f"s3-public-access-block:{name}",
                        name,
                        "S3 public access block is incomplete",
                        "high",
                        "One or more bucket-level public access protections are disabled.",
                        "Enable all four S3 Block Public Access settings and review account-level protections.",
                    )
            except ClientError as error:
                if is_missing_configuration(error, "NoSuchPublicAccessBlockConfiguration"):
                    self._finding(
                        f"s3-public-access-block:{name}",
                        name,
                        "S3 public access block is not configured",
                        "high",
                        "No bucket-level S3 Block Public Access configuration is present.",
                        "Enable all four S3 Block Public Access settings and review account-level protections.",
                    )
                else:
                    self._check_failed("s3_public_access_block", error)

            try:
                if s3.get_bucket_policy_status(Bucket=name).get("PolicyStatus", {}).get("IsPublic"):
                    self._finding(
                        f"s3-public-policy:{name}",
                        name,
                        "S3 bucket policy allows public access",
                        "critical",
                        "AWS reports that the bucket policy grants public access.",
                        "Remove unintended public principals and restrict the bucket policy to required identities.",
                    )
            except ClientError as error:
                if not is_missing_configuration(error, "NoSuchBucketPolicy"):
                    self._check_failed("s3_bucket_policy", error)
            try:
                grants = s3.get_bucket_acl(Bucket=name).get("Grants", [])
                if any(
                    grant.get("Grantee", {}).get("URI", "").endswith(("AllUsers", "AuthenticatedUsers"))
                    for grant in grants
                ):
                    self._finding(
                        f"s3-public-acl:{name}",
                        name,
                        "S3 bucket ACL grants public access",
                        "high",
                        "The bucket ACL grants access to the global or authenticated-users group.",
                        "Remove public ACL grants and use a least-privilege bucket policy.",
                    )
            except ClientError as error:
                self._check_failed("s3_bucket_acl", error)

            try:
                s3.get_bucket_encryption(Bucket=name)
            except ClientError as error:
                if is_missing_configuration(error, "ServerSideEncryptionConfigurationNotFoundError"):
                    self._finding(
                        f"s3-encryption:{name}",
                        name,
                        "S3 default encryption is not configured",
                        "medium",
                        "No default server-side encryption configuration is present on the bucket.",
                        "Configure default server-side encryption, preferably with an approved KMS key.",
                    )
                else:
                    self._check_failed("s3_encryption", error)

    def _scan_security_groups(self) -> None:
        try:
            groups = self.aws.client("ec2").describe_security_groups().get("SecurityGroups", [])
        except ClientError as error:
            self._check_failed("security_groups", error)
            return
        self.checks["security_groups"] = "complete"
        for group in groups:
            group_id = group["GroupId"]
            for permission in group.get("IpPermissions", []):
                protocol = permission.get("IpProtocol")
                start = permission.get("FromPort", 0)
                end = permission.get("ToPort", 65535)
                exposed = protocol == "-1" or any(start <= port <= end for port in SENSITIVE_PORTS)
                if not exposed:
                    continue
                public_cidr = any(entry.get("CidrIp") == "0.0.0.0/0" for entry in permission.get("IpRanges", []))
                public_cidr = public_cidr or any(
                    entry.get("CidrIpv6") == "::/0" for entry in permission.get("Ipv6Ranges", [])
                )
                if public_cidr:
                    ports = "all traffic" if protocol == "-1" else f"port range {start}-{end}"
                    self._finding(
                        f"security-group-ingress:{group_id}:{protocol}:{start}:{end}",
                        group_id,
                        "Sensitive security group ingress is open to the internet",
                        "critical" if protocol == "-1" else "high",
                        f"Security group {group_id} exposes {ports} to a public IPv4 or IPv6 range.",
                        "Restrict ingress to trusted CIDR ranges and only the ports required by the workload.",
                    )

    def _scan_compute_and_databases(self) -> None:
        try:
            instances = self.aws.client("ec2").describe_instances().get("Reservations", [])
            for reservation in instances:
                for instance in reservation.get("Instances", []):
                    instance_id = instance["InstanceId"]
                    if instance.get("PublicIpAddress"):
                        self._finding(
                            f"ec2-public-ip:{instance_id}",
                            instance_id,
                            "EC2 instance has a public IP address",
                            "low",
                            "The instance has a public IPv4 address; this increases its internet exposure.",
                            "Confirm public reachability is required and restrict access with security group rules.",
                        )
                    for mapping in instance.get("BlockDeviceMappings", []):
                        ebs = mapping.get("Ebs", {})
                        if ebs and ebs.get("Encrypted") is False:
                            volume_id = ebs.get("VolumeId", instance_id)
                            self._finding(
                                f"ebs-encryption:{volume_id}",
                                instance_id,
                                "EC2 EBS volume is not encrypted",
                                "medium",
                                f"Attached EBS volume {volume_id} reports encryption disabled.",
                                "Migrate the workload to encrypted EBS volumes using an approved KMS key.",
                            )
        except ClientError as error:
            self._check_failed("ec2_configuration", error)
        else:
            self.checks["ec2_configuration"] = "complete"

        try:
            databases = self.aws.client("rds").describe_db_instances().get("DBInstances", [])
            for database in databases:
                name = database["DBInstanceIdentifier"]
                if database.get("StorageEncrypted") is False:
                    self._finding(
                        f"rds-encryption:{name}",
                        name,
                        "RDS database storage is not encrypted",
                        "high",
                        "AWS reports that storage encryption is disabled for this database.",
                        "Create an encrypted replacement database and migrate using an approved KMS key.",
                    )
                if database.get("PubliclyAccessible"):
                    self._finding(
                        f"rds-public-access:{name}",
                        name,
                        "RDS database is configured as publicly accessible",
                        "high",
                        "The database endpoint is configured for public accessibility.",
                        "Disable public accessibility and connect through private networking where possible.",
                    )
        except ClientError as error:
            self._check_failed("rds_configuration", error)
        else:
            self.checks["rds_configuration"] = "complete"

    def _scan_iam(self) -> None:
        iam = self.aws.client("iam", "us-east-1")
        try:
            summary = iam.get_account_summary().get("SummaryMap", {})
            if "AccountMFAEnabled" not in summary:
                self.checks["root_mfa"] = "unavailable:missing_data"
            elif summary["AccountMFAEnabled"] == 0:
                self._finding(
                    "iam-root-mfa",
                    "AWS account root user",
                    "Root account MFA is not enabled",
                    "critical",
                    "The account summary reports that root MFA is disabled.",
                    "Enable a hardware or virtual MFA device on the root user and avoid root access for daily work.",
                )
            if "AccountMFAEnabled" in summary:
                self.checks["root_mfa"] = "complete"
        except ClientError as error:
            self._check_failed("root_mfa", error)

        try:
            paginator = iam.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page.get("Users", []):
                    user_name = user["UserName"]
                    devices = iam.list_mfa_devices(UserName=user_name).get("MFADevices", [])
                    if not devices:
                        self._finding(
                            f"iam-user-mfa:{user_name}",
                            user_name,
                            "IAM user does not have MFA enabled",
                            "high",
                            f"IAM user {user_name} has no MFA device registered.",
                            "Require MFA for this user, or replace long-lived IAM users with federated access.",
                        )
            self.checks["iam_user_mfa"] = "complete"
        except ClientError as error:
            self._check_failed("iam_user_mfa", error)
