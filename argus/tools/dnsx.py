from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional, Any, List, Union
import json
import logging
from argus.runtime.local import LocalRuntime
from argus.runtime.base import Runtime

logger = logging.getLogger(__name__)


@dataclass
class DNSResult:
    """Represents the DNS resolution result for a single host."""
    host: str
    cname: list[str] = field(default_factory=list)
    a: list[str] = field(default_factory=list)
    aaaa: list[str] = field(default_factory=list)
    status_code: str = ""
    resolver: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "cname": list(self.cname),
            "a": list(self.a),
            "aaaa": list(self.aaaa),
            "status_code": self.status_code,
            "resolver": list(self.resolver),
            "raw": dict(self.raw),
        }


class DNSXTool:
    """Tool wrapper for dnsx fast and multi-purpose DNS querying tool."""

    def __init__(self, executable: str = "dnsx", runtime: Optional[Runtime] = None):
        self.executable = executable
        self.runtime = runtime or LocalRuntime()

    def build_args(
        self,
        hosts: Optional[Union[List[str], str]] = None,
        cname: bool = True,
        resp: bool = True,
        json_output: bool = True,
        silent: bool = True,
        rcode: bool = True,
        extra_args: Optional[List[str]] = None,
    ) -> List[str]:
        args = []
        if silent:
            args.append("-silent")
        if json_output:
            args.append("-json")
        if cname:
            args.append("-cname")
        if resp:
            args.append("-resp")
        if rcode:
            args.append("-rcode")
        if extra_args:
            args.extend(extra_args)
        return args

    def parse_output(self, stdout: str) -> List[DNSResult]:
        """Parses dnsx output (JSON lines or plain text) into DNSResult objects."""
        from argus.runtime.parser import ReconParser
        parsed_dicts = ReconParser.parse_dnsx(stdout)
        results = []
        for d in parsed_dicts:
            results.append(
                DNSResult(
                    host=d.get("host", ""),
                    cname=d.get("cname", []),
                    a=d.get("a", []),
                    aaaa=d.get("aaaa", []),
                    status_code=d.get("status_code", "") or d.get("rcode", ""),
                    resolver=d.get("resolver", []),
                    raw=d.get("raw", d),
                )
            )
        return results

    def resolve(
        self,
        hosts: Union[List[str], str],
        cname: bool = True,
        resp: bool = True,
        json_output: bool = True,
        silent: bool = True,
        rcode: bool = True,
        extra_args: Optional[List[str]] = None,
    ) -> List[DNSResult]:
        """Resolves DNS records for the given list of hosts using dnsx."""
        if isinstance(hosts, str):
            host_list = [hosts]
        else:
            host_list = list(hosts)

        if not host_list:
            return []

        args = self.build_args(
            hosts=host_list,
            cname=cname,
            resp=resp,
            json_output=json_output,
            silent=silent,
            rcode=rcode,
            extra_args=extra_args,
        )

        stdin_input = "\n".join(host_list)
        try:
            res = self.runtime.run_command(
                executable=self.executable,
                args=args,
                stdin=stdin_input,
            )
            stdout = res.get("stdout", "") if isinstance(res, dict) else getattr(res, "stdout", "")
            return self.parse_output(stdout)
        except Exception as e:
            logger.error(f"Failed to execute dnsx tool: {e}")
            return []
