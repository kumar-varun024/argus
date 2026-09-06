"""ssrf: Data models, enums, and constants."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List

from argus.collectors.toolkit.enums import Severity


class SSRFTechnique(str, Enum):
    """Detection technique classifications for SSRF."""
    CLOUD_METADATA = "cloud_metadata"
    INTERNAL_SERVICE = "internal_service"
    DIFFERENTIAL_TIMING = "differential_timing"

class SSRFCloudProvider(str, Enum):
    """Cloud providers with accessible instance metadata services."""
    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"
    DIGITALOCEAN = "digitalocean"
    ORACLE = "oracle"
    ALIBABA = "alibaba"
    GENERIC = "generic"

@dataclass
class SSRFResult:
    """Represents the structured result of an SSRF analysis."""
    technique: str  # "cloud_metadata", "internal_service", "differential_timing"
    payload: str
    parameter: str
    parameter_type: str  # "query", "body", "json", "path", "header"
    status_code: int = 200
    target_service: str = "generic"  # "aws_imds", "gcp_metadata", "redis", "mysql", etc.
    matched_pattern: str = ""
    snippet: str = ""
    severity: str = Severity.CRITICAL
    confidence: float = 0.95
    template_id: str = "ssrf"
    delay_delta: float = 0.0
    baseline_elapsed: float = 0.0
    injected_elapsed: float = 0.0
    bypass_strategy: str = "none"
    cloud_provider: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)

CLOUD_METADATA_SIGNATURES: Dict[str, Dict[str, Any]] = {
    "aws_iam_role": {
        "pattern": re.compile(r"security-credentials/[a-zA-Z0-9_\-\.]+", re.IGNORECASE),
        "provider": SSRFCloudProvider.AWS.value,
        "description": "AWS IMDS IAM Role listing",
    },
    "aws_security_credentials": {
        "pattern": re.compile(
            r"\{\s*\"Code\"\s*:\s*\"Success\"[^\}]*\"AccessKeyId\"\s*:\s*\"(?:AKIA|ASIA)[A-Z0-9]{16}\"",
            re.IGNORECASE,
        ),
        "provider": SSRFCloudProvider.AWS.value,
        "description": "AWS IMDS IAM Security Credentials JSON",
    },
    "aws_instance_identity": {
        "pattern": re.compile(
            r"\"instanceId\"\s*:\s*\"i-[0-9a-f]{8,17}\"|\"imageId\"\s*:\s*\"ami-[0-9a-f]{8,17}\"|\"architecture\"\s*:\s*\"(?:x86_64|arm64)\"",
            re.IGNORECASE,
        ),
        "provider": SSRFCloudProvider.AWS.value,
        "description": "AWS EC2 Dynamic Instance Identity Document",
    },
    "aws_ami_id": {
        "pattern": re.compile(r"\bami-[0-9a-f]{8,17}\b", re.IGNORECASE),
        "provider": SSRFCloudProvider.AWS.value,
        "description": "AWS EC2 AMI Identifier",
    },
    "aws_imds_token": {
        "pattern": re.compile(r"aws-ec2-metadata-token-ttl-seconds|\bEC2_METADATA_TOKEN\b", re.IGNORECASE),
        "provider": SSRFCloudProvider.AWS.value,
        "description": "AWS IMDSv2 Token Header / Parameter Echo",
    },
    "gcp_instance_id": {
        "pattern": re.compile(
            r"\bcomputeMetadata/v1\b|\"project\":\s*\{\s*\"projectId\"|\"numericProjectId\"\s*:\s*\d+",
            re.IGNORECASE,
        ),
        "provider": SSRFCloudProvider.GCP.value,
        "description": "GCP Compute Engine Metadata Document",
    },
    "gcp_service_accounts": {
        "pattern": re.compile(
            r"instance/service-accounts/[a-zA-Z0-9_\-\.]+@(?:developer|[a-z0-9\-]+)\.gserviceaccount\.com",
            re.IGNORECASE,
        ),
        "provider": SSRFCloudProvider.GCP.value,
        "description": "GCP Service Account Email Reference",
    },
    "azure_vm_metadata": {
        "pattern": re.compile(
            r"\{\s*\"compute\"\s*:\s*\{[^\}]*\"vmId\"\s*:\s*\"[0-9a-f\-]{36}\"|\"osType\"\s*:\s*\"(?:Linux|Windows)\"",
            re.IGNORECASE,
        ),
        "provider": SSRFCloudProvider.AZURE.value,
        "description": "Azure Instance Metadata Service (IMDS) VM JSON",
    },
    "digitalocean_droplet": {
        "pattern": re.compile(
            r"\"droplet_id\"\s*:\s*\d+|\"vendor_data\"|\"hostname\"\s*:\s*\"[^\"]+\.digitalocean\.com\"",
            re.IGNORECASE,
        ),
        "provider": SSRFCloudProvider.DIGITALOCEAN.value,
        "description": "DigitalOcean Droplet Metadata JSON",
    },
    "oracle_cloud": {
        "pattern": re.compile(
            r"\"id\"\s*:\s*\"ocid1\.instance\.|\"canonicalRegionName\"\s*:\s*\"[a-z]{2}-[a-z]+-\d+\"",
            re.IGNORECASE,
        ),
        "provider": SSRFCloudProvider.ORACLE.value,
        "description": "Oracle Cloud Infrastructure (OCI) Instance Metadata",
    },
    "alibaba_cloud": {
        "pattern": re.compile(
            r"\binstance-id\b.*\bimage-id\b|\"zone-id\"\s*:\s*\"[a-z0-9\-]+\"|\"eipv4\"\s*:\s*\"[0-9.]+\"",
            re.IGNORECASE,
        ),
        "provider": SSRFCloudProvider.ALIBABA.value,
        "description": "Alibaba Cloud ECS Instance Metadata",
    },
}

INTERNAL_SERVICE_SIGNATURES: Dict[str, Dict[str, Any]] = {
    "redis_pong": {
        "pattern": re.compile(
            r"(?:\+PONG\b|PONG\b|\+OK\b|-ERR\s+(?:unknown\s+command|wrong\s+number\s+of\s+arguments)|redis_version:\d+\.\d+)",
            re.IGNORECASE,
        ),
        "service": "redis",
        "description": "Redis In-Memory Data Store Response",
        "severity": Severity.HIGH,
    },
    "mysql_handshake": {
        "pattern": re.compile(
            r"(?:\x00\x00\x00\n\d+\.\d+\.\d+|mysql_native_password|caching_sha2_password|mariadb\.org binary|Host '[^']+' is not allowed to connect to this MariaDB)",
            re.IGNORECASE,
        ),
        "service": "mysql",
        "description": "MySQL / MariaDB Server Protocol Handshake Banner",
        "severity": Severity.CRITICAL,
    },
    "postgres_handshake": {
        "pattern": re.compile(
            r"(?:FATAL:\s+password authentication failed|org\.postgresql\.util\.PSQLException|PostgreSQL.*?FATAL|database \".*?\" does not exist)",
            re.IGNORECASE,
        ),
        "service": "postgresql",
        "description": "PostgreSQL Server Handshake / Authentication Error",
        "severity": Severity.CRITICAL,
    },
    "elasticsearch_banner": {
        "pattern": re.compile(
            r"(?:You Know, for Search|\"cluster_name\"\s*:|\"lucene_version\"\s*:|\"tagline\"\s*:\s*\"You Know, for Search\")",
            re.IGNORECASE,
        ),
        "service": "elasticsearch",
        "description": "Elasticsearch REST API Status Response",
        "severity": Severity.CRITICAL,
    },
    "mongodb_banner": {
        "pattern": re.compile(
            r"(?:\"isWritablePrimary\"\s*:|\"ismaster\"\s*:|\"wireVersionMin\"\s*:|\"ok\"\s*:\s*1\.0.*\"connectionId\"|It looks like you are trying to access MongoDB over HTTP)",
            re.IGNORECASE,
        ),
        "service": "mongodb",
        "description": "MongoDB Wire / HTTP Status Banner",
        "severity": Severity.CRITICAL,
    },
    "memcached_banner": {
        "pattern": re.compile(
            r"(?:STAT pid \d+|STAT uptime \d+|VERSION \d+\.\d+|END\r?\n)",
            re.IGNORECASE,
        ),
        "service": "memcached",
        "description": "Memcached Stats / Version Response",
        "severity": Severity.HIGH,
    },
    "rabbitmq_banner": {
        "pattern": re.compile(
            r"(?:RabbitMQ|\"rabbitmq_version\"\s*:|AMQP:\d+-\d+|<title>RabbitMQ Management</title>)",
            re.IGNORECASE,
        ),
        "service": "rabbitmq",
        "description": "RabbitMQ Broker / Management Interface",
        "severity": Severity.HIGH,
    },
    "consul_etcd": {
        "pattern": re.compile(
            r"(?:\{\s*\"action\"\s*:\s*\"get\"|\"kvs\"\s*:\s*\[|\"Consul\"|\"raft_index\"|\"header\":\{\"cluster_id\")",
            re.IGNORECASE,
        ),
        "service": "consul_etcd",
        "description": "Consul / etcd Distributed Key-Value Store",
        "severity": Severity.CRITICAL,
    },
    "admin_dashboard_titles": {
        "pattern": re.compile(
            r"<title>[^<]*(?:Admin Dashboard|Internal Router|pfSense|phpMyAdmin|Kibana|Grafana|Jenkins|RabbitMQ Management|HAProxy Statistics|Spring Boot Actuator|Traefik|Kubernetes Dashboard|Webmin|Cockpit|OpenWrt)[^<]*</title>",
            re.IGNORECASE,
        ),
        "service": "internal_admin",
        "description": "Internal Administrative Portal / Dashboard Title",
        "severity": Severity.CRITICAL,
    },
}

DEFAULT_SSRF_TARGETS: List[Dict[str, Any]] = [
    # AWS
    {
        "provider": SSRFCloudProvider.AWS.value,
        "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "signature": "aws_iam_role",
        "description": "AWS IMDSv1 IAM Security Credentials",
    },
    {
        "provider": SSRFCloudProvider.AWS.value,
        "url": "http://169.254.169.254/latest/dynamic/instance-identity/document",
        "signature": "aws_instance_identity",
        "description": "AWS EC2 Instance Identity Document",
    },
    {
        "provider": SSRFCloudProvider.AWS.value,
        "url": "http://169.254.169.254/latest/meta-data/ami-id",
        "signature": "aws_ami_id",
        "description": "AWS EC2 AMI ID",
    },
    # GCP
    {
        "provider": SSRFCloudProvider.GCP.value,
        "url": "http://metadata.google.internal/computeMetadata/v1/instance/id",
        "signature": "gcp_instance_id",
        "headers": {"Metadata-Flavor": "Google"},
        "description": "GCP Compute Engine Instance ID",
    },
    {
        "provider": SSRFCloudProvider.GCP.value,
        "url": "http://169.254.169.254/computeMetadata/v1/project/project-id",
        "signature": "gcp_instance_id",
        "headers": {"Metadata-Flavor": "Google"},
        "description": "GCP Project Metadata via IP",
    },
    # Azure
    {
        "provider": SSRFCloudProvider.AZURE.value,
        "url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "signature": "azure_vm_metadata",
        "headers": {"Metadata": "true"},
        "description": "Azure IMDS Instance Metadata",
    },
    # DigitalOcean
    {
        "provider": SSRFCloudProvider.DIGITALOCEAN.value,
        "url": "http://169.254.169.254/metadata/v1.json",
        "signature": "digitalocean_droplet",
        "description": "DigitalOcean Droplet Metadata JSON",
    },
    # Oracle Cloud
    {
        "provider": SSRFCloudProvider.ORACLE.value,
        "url": "http://169.254.169.254/opc/v1/instance/",
        "signature": "oracle_cloud",
        "headers": {"Authorization": "Bearer Oracle"},
        "description": "Oracle Cloud Infrastructure Instance Metadata",
    },
    # Alibaba Cloud
    {
        "provider": SSRFCloudProvider.ALIBABA.value,
        "url": "http://100.100.100.200/latest/meta-data/instance-id",
        "signature": "alibaba_cloud",
        "description": "Alibaba Cloud ECS Instance Metadata",
    },
]

DEFAULT_INTERNAL_SERVICE_TARGETS: List[Dict[str, Any]] = [
    {
        "service": "redis",
        "url": "http://127.0.0.1:6379/",
        "signature": "redis_pong",
        "description": "Localhost Redis Service",
    },
    {
        "service": "mysql",
        "url": "http://127.0.0.1:3306/",
        "signature": "mysql_handshake",
        "description": "Localhost MySQL Service",
    },
    {
        "service": "postgresql",
        "url": "http://127.0.0.1:5432/",
        "signature": "postgres_handshake",
        "description": "Localhost PostgreSQL Service",
    },
    {
        "service": "elasticsearch",
        "url": "http://127.0.0.1:9200/",
        "signature": "elasticsearch_banner",
        "description": "Localhost Elasticsearch API",
    },
    {
        "service": "mongodb",
        "url": "http://127.0.0.1:27017/",
        "signature": "mongodb_banner",
        "description": "Localhost MongoDB Service",
    },
    {
        "service": "memcached",
        "url": "http://127.0.0.1:11211/",
        "signature": "memcached_banner",
        "description": "Localhost Memcached Service",
    },
    {
        "service": "internal_admin",
        "url": "http://127.0.0.1:8080/admin",
        "signature": "admin_dashboard_titles",
        "description": "Localhost Internal Administration Dashboard",
    },
]

DEFAULT_TIMING_TARGETS: List[Dict[str, Any]] = [
    {
        "url": "http://10.255.255.1:81/",
        "description": "Unroutable Private Subnet Drop IP",
        "delay": 5.0,
    },
    {
        "url": "http://192.0.2.1:81/",
        "description": "TEST-NET-1 Dropping Blackhole IP",
        "delay": 5.0,
    },
    {
        "url": "http://172.31.255.255:81/",
        "description": "RFC1918 Class B Broadcast Drop IP",
        "delay": 5.0,
    },
]

COMMON_SSRF_PARAMS: List[str] = [
    "url", "target", "dest", "destination", "uri", "webhook", "feed",
    "link", "src", "source", "redirect", "redirect_uri", "load", "fetch",
    "domain", "host", "path", "data", "proxy", "endpoint", "callback",
    "request", "view", "val", "file", "site", "html", "doc", "pdf",
    "image_url", "avatar", "preview", "service", "api", "download",
]

DEFAULT_SSRF_PROBE_ROUTES: List[str] = [
    "/webhook", "/fetch", "/proxy", "/download", "/preview",
    "/api/fetch", "/api/proxy", "/api/webhook", "/import",
    "/url", "/load", "/feed", "/api/v1/fetch", "/api/v1/proxy",
    "/service/fetch", "/crawler",
]
