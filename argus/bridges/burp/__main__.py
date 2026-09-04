"""Entry point for running ARGUS Burp Suite MCP Server via `python -m argus.bridges.burp`."""

import argparse
import logging
import sys

from argus.bridges.burp.server import SERVER_NAME, SERVER_VERSION, BurpMCPServer


def main() -> int:
    """CLI main function for starting the Burp MCP server."""
    parser = argparse.ArgumentParser(
        description="ARGUS Burp Suite Model Context Protocol (MCP) Bridge Server"
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{SERVER_NAME} v{SERVER_VERSION}",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose debug logging (to stderr)",
    )
    parser.add_argument(
        "--stdio",
        action="store_true",
        default=True,
        help="Run MCP server over standard I/O (default)",
    )

    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stderr,
    )

    server = BurpMCPServer()
    server.run_stdio()
    return 0


if __name__ == "__main__":
    sys.exit(main())
