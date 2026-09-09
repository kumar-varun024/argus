# Tools image for the gated hunt-agent sandbox (argus/hunt-tools:latest).
# Build:  docker build -f docker/huntAgentTools.Dockerfile -t argus/hunt-tools:latest .
#
# Only the binaries the toolCatalog allowlist references are installed. The
# container is run non-root, read-only, cap-dropped, and (ideally) on an
# egress-filtered network by DockerSandbox -- see argus/agent/dockerSandbox.py.
FROM debian:stable-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap curl dnsutils whois \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ProjectDiscovery + fuzzing tools (httpx, nuclei, ffuf, gobuster) and wafw00f/
# whatweb are added here in a real build (Go/pip installs); pinned by digest.
# Left as a documented placeholder so the image builds with the apt tools alone
# until the operator pins versions for their environment.

# Drop to an unprivileged user; DockerSandbox also forces --user 65534:65534.
USER 65534:65534
ENTRYPOINT []
