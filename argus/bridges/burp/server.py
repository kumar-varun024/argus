"""Model Context Protocol (MCP) JSON-RPC 2.0 Server for Burp Suite Integration."""

import io
import json
import logging
import sys
from typing import Any, Callable, Dict, List, Optional, TextIO

from argus.bridges.burp.collaborator import BurpCollaboratorClient
from argus.bridges.burp.importer import BurpScanImporter
from argus.bridges.burp.proxy import burp_configure_proxy
from argus.bridges.burp.scanner import BurpScannerClient

logger = logging.getLogger(__name__)

MCP_PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "argus-burp-bridge"
SERVER_VERSION = "1.0.0"

# JSON-RPC 2.0 Standard Error Codes
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603


class BurpMCPServer:
    """MCP Server providing Burp Suite automation tools via JSON-RPC 2.0."""

    def __init__(
        self,
        importer: Optional[BurpScanImporter] = None,
        scanner: Optional[BurpScannerClient] = None,
        collaborator: Optional[BurpCollaboratorClient] = None,
    ) -> None:
        self.importer = importer or BurpScanImporter()
        self.scanner = scanner or BurpScannerClient()
        self.collaborator = collaborator or BurpCollaboratorClient()
        self._tools: Dict[str, Dict[str, Any]] = {}
        self._register_default_tools()

    def register_tool(
        self,
        name: str,
        description: str,
        input_schema: Dict[str, Any],
        handler: Callable[..., Any],
    ) -> None:
        """Register a new tool handler on the MCP server."""
        self._tools[name] = {
            "name": name,
            "description": description,
            "inputSchema": input_schema,
            "handler": handler,
        }

    def _register_default_tools(self) -> None:
        """Register the 6 default Burp Suite MCP tools."""
        self.register_tool(
            name="burp_configure_proxy",
            description="Configure upstream proxy routing for ARGUS AuthenticatedHttpClient (default: http://127.0.0.1:8080).",
            input_schema={
                "type": "object",
                "properties": {
                    "proxy_url": {
                        "type": "string",
                        "description": "Burp Suite proxy URL",
                        "default": "http://127.0.0.1:8080",
                    },
                    "enabled": {
                        "type": "boolean",
                        "description": "Whether upstream proxy is enabled",
                        "default": True,
                    },
                },
            },
            handler=self._handle_configure_proxy,
        )

        self.register_tool(
            name="burp_import_scan",
            description="Parse Burp XML/JSON scan results, decode base64 HTTP requests/responses, map severities, and populate ARGUS Evidence store.",
            input_schema={
                "type": "object",
                "properties": {
                    "content": {
                        "type": "string",
                        "description": "Raw XML or JSON scan report string content",
                    },
                    "file_path": {
                        "type": "string",
                        "description": "Path to scan export file (XML or JSON)",
                    },
                    "format": {
                        "type": "string",
                        "enum": ["auto", "xml", "json"],
                        "description": "Scan export format",
                        "default": "auto",
                    },
                    "mission_id": {
                        "type": "string",
                        "description": "Optional mission ID to associate evidence with",
                        "default": "",
                    },
                },
            },
            handler=self._handle_import_scan,
        )

        self.register_tool(
            name="burp_launch_scan",
            description="Launch an active scan via Burp Suite REST API.",
            input_schema={
                "type": "object",
                "properties": {
                    "urls": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of target URLs to scan",
                    },
                    "api_url": {
                        "type": "string",
                        "description": "Burp REST API URL",
                        "default": "http://127.0.0.1:1337",
                    },
                    "api_key": {
                        "type": "string",
                        "description": "Optional Burp REST API key",
                    },
                    "scan_configurations": {
                        "type": "array",
                        "items": {"type": "object"},
                        "description": "Optional list of Burp scan configurations",
                    },
                },
                "required": ["urls"],
            },
            handler=self._handle_launch_scan,
        )

        self.register_tool(
            name="burp_poll_scan",
            description="Poll status, progress percentage, and discovered issues for an active scan from Burp Suite REST API.",
            input_schema={
                "type": "object",
                "properties": {
                    "scan_id": {
                        "type": "string",
                        "description": "Burp scan ID",
                    },
                    "api_url": {
                        "type": "string",
                        "description": "Burp REST API URL",
                        "default": "http://127.0.0.1:1337",
                    },
                    "api_key": {
                        "type": "string",
                        "description": "Optional Burp REST API key",
                    },
                },
                "required": ["scan_id"],
            },
            handler=self._handle_poll_scan,
        )

        self.register_tool(
            name="burp_collaborator_generate",
            description="Generate a unique Burp Collaborator / OAST payload domain for out-of-band interaction testing.",
            input_schema={
                "type": "object",
                "properties": {
                    "server_domain": {
                        "type": "string",
                        "description": "Collaborator server domain",
                        "default": "oastify.com",
                    },
                    "secret_key": {
                        "type": "string",
                        "description": "Optional secret key for polling",
                    },
                },
            },
            handler=self._handle_collaborator_generate,
        )

        self.register_tool(
            name="burp_collaborator_poll",
            description="Poll out-of-band interaction logs (DNS, HTTP, SMTP) for a Burp Collaborator payload domain.",
            input_schema={
                "type": "object",
                "properties": {
                    "payload_domain": {
                        "type": "string",
                        "description": "The payload domain to poll interactions for",
                    },
                    "api_url": {
                        "type": "string",
                        "description": "Optional Burp REST API or Collaborator polling endpoint",
                    },
                    "secret_key": {
                        "type": "string",
                        "description": "Optional secret key for polling",
                    },
                    "server_domain": {
                        "type": "string",
                        "description": "Collaborator server domain",
                        "default": "oastify.com",
                    },
                },
                "required": ["payload_domain"],
            },
            handler=self._handle_collaborator_poll,
        )

    # Tool handler bridges
    def _handle_configure_proxy(self, **kwargs: Any) -> Dict[str, Any]:
        proxy_url = kwargs.get("proxy_url", "http://127.0.0.1:8080")
        enabled = kwargs.get("enabled", True)
        return burp_configure_proxy(proxy_url=proxy_url, enabled=enabled)

    def _handle_import_scan(self, **kwargs: Any) -> Dict[str, Any]:
        return self.importer.import_scan(
            content=kwargs.get("content"),
            file_path=kwargs.get("file_path"),
            format=kwargs.get("format", "auto"),
            mission_id=kwargs.get("mission_id", ""),
        )

    def _handle_launch_scan(self, **kwargs: Any) -> Dict[str, Any]:
        urls = kwargs.get("urls", [])
        if not urls:
            raise ValueError("Parameter 'urls' is required and cannot be empty.")
        return self.scanner.launch_scan(
            urls=urls,
            api_url=kwargs.get("api_url"),
            api_key=kwargs.get("api_key"),
            scan_configurations=kwargs.get("scan_configurations"),
        )

    def _handle_poll_scan(self, **kwargs: Any) -> Dict[str, Any]:
        scan_id = kwargs.get("scan_id")
        if not scan_id:
            raise ValueError("Parameter 'scan_id' is required.")
        return self.scanner.poll_scan(
            scan_id=str(scan_id),
            api_url=kwargs.get("api_url"),
            api_key=kwargs.get("api_key"),
        )

    def _handle_collaborator_generate(self, **kwargs: Any) -> Dict[str, Any]:
        return self.collaborator.generate_payload(
            server_domain=kwargs.get("server_domain", "oastify.com"),
            secret_key=kwargs.get("secret_key"),
        )

    def _handle_collaborator_poll(self, **kwargs: Any) -> Dict[str, Any]:
        payload_domain = kwargs.get("payload_domain")
        if not payload_domain:
            raise ValueError("Parameter 'payload_domain' is required.")
        return self.collaborator.poll_interactions(
            payload_domain=str(payload_domain),
            api_url=kwargs.get("api_url"),
            secret_key=kwargs.get("secret_key"),
            server_domain=kwargs.get("server_domain", "oastify.com"),
        )

    def list_tools(self) -> List[Dict[str, Any]]:
        """Return tool definitions for tools/list."""
        return [
            {
                "name": tool["name"],
                "description": tool["description"],
                "inputSchema": tool["inputSchema"],
            }
            for tool in self._tools.values()
        ]

    def execute_tool(self, name: str, arguments: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Directly invoke a registered tool by name with arguments dict."""
        if name not in self._tools:
            raise KeyError(f"Unknown tool: '{name}'")
        handler = self._tools[name]["handler"]
        args = arguments or {}
        return handler(**args)

    def handle_request(self, request: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Handle a single parsed JSON-RPC 2.0 request dict.

        Returns response dictionary or None (for notifications).
        """
        if not isinstance(request, dict):
            return {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": INVALID_REQUEST, "message": "Invalid Request: expected JSON object"},
            }

        req_id = request.get("id")
        method = request.get("method")
        params = request.get("params", {})

        # Check for JSON-RPC version
        if request.get("jsonrpc") != "2.0" or not isinstance(method, str):
            if req_id is not None:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": INVALID_REQUEST, "message": "Invalid JSON-RPC request"},
                }
            return None

        # Notifications: methods like notifications/initialized
        if method in ("notifications/initialized", "initialized"):
            logger.info("Received client initialization notification")
            return None

        # Standard methods requiring response
        try:
            if method == "initialize":
                result = {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {
                        "tools": {
                            "listChanged": False,
                        }
                    },
                    "serverInfo": {
                        "name": SERVER_NAME,
                        "version": SERVER_VERSION,
                    },
                }
                return {"jsonrpc": "2.0", "id": req_id, "result": result}

            elif method == "ping":
                return {"jsonrpc": "2.0", "id": req_id, "result": {}}

            elif method == "tools/list":
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"tools": self.list_tools()},
                }

            elif method == "tools/call":
                if not isinstance(params, dict):
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {"code": INVALID_PARAMS, "message": "params must be an object"},
                    }

                tool_name = params.get("name")
                if not tool_name or not isinstance(tool_name, str):
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {"code": INVALID_PARAMS, "message": "Tool name is required"},
                    }

                arguments = params.get("arguments", {})
                if not isinstance(arguments, dict):
                    arguments = {}

                try:
                    tool_output = self.execute_tool(tool_name, arguments)
                    formatted_text = (
                        json.dumps(tool_output, indent=2, default=str)
                        if isinstance(tool_output, (dict, list))
                        else str(tool_output)
                    )
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "content": [
                                {
                                    "type": "text",
                                    "text": formatted_text,
                                }
                            ],
                            "isError": False,
                            "structuredContent": tool_output if isinstance(tool_output, dict) else {},
                        },
                    }
                except KeyError:
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {
                            "code": METHOD_NOT_FOUND,
                            "message": f"Unknown tool: '{tool_name}'",
                        },
                    }
                except Exception as e:
                    logger.warning("Tool execution error for %s: %s", tool_name, e)
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "content": [
                                {
                                    "type": "text",
                                    "text": f"Error executing tool '{tool_name}': {str(e)}",
                                }
                            ],
                            "isError": True,
                        },
                    }

            else:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": METHOD_NOT_FOUND,
                        "message": f"Method not found: '{method}'",
                    },
                }

        except Exception as e:
            logger.error("Internal error handling method %s: %s", method, e)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": INTERNAL_ERROR,
                    "message": f"Internal error: {str(e)}",
                },
            }

    def handle_jsonrpc(self, request_str: str) -> str:
        """Process a raw JSON-RPC 2.0 string and return serialized response JSON string."""
        if not request_str or not request_str.strip():
            return ""

        try:
            parsed = json.loads(request_str)
        except json.JSONDecodeError as e:
            return json.dumps({
                "jsonrpc": "2.0",
                "id": None,
                "error": {
                    "code": PARSE_ERROR,
                    "message": f"Parse error: {str(e)}",
                },
            })

        response = self.handle_request(parsed)
        if response is None:
            return ""
        return json.dumps(response)

    def run_stdio(
        self,
        stdin: Optional[TextIO] = None,
        stdout: Optional[TextIO] = None,
    ) -> None:
        """Run the MCP server over standard I/O streams reading line-delimited JSON-RPC messages."""
        in_stream = stdin or sys.stdin
        out_stream = stdout or sys.stdout

        logger.info("Starting Burp MCP Server over stdio")

        try:
            for line in in_stream:
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue

                resp_str = self.handle_jsonrpc(line)
                if resp_str:
                    out_stream.write(resp_str + "\n")
                    out_stream.flush()
        except (KeyboardInterrupt, BrokenPipeError):
            pass
        except Exception as e:
            logger.error("Stdio runner error: %s", e)
