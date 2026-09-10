# Tools image for the gated hunt-agent sandbox (argus/hunt-tools:latest).
# Build:  docker build -f docker/huntAgentTools.Dockerfile -t argus/hunt-tools:latest .
#
# Only the binaries the toolCatalog allowlist references are installed. The
# container is run non-root, read-only, cap-dropped, and (ideally) on an
# egress-filtered network by DockerSandbox -- see argus/agent/dockerSandbox.py.
FROM debian:stable-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap curl dnsutils whois \
        whatweb wafw00f \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# The apt tools above cover the whole passive AUTO_TOOLS set (dig, whois,
# whatweb, wafw00f) plus the confirm-gated active tools nmap and curl, so a
# real hunt produces output out of the box.
#
# The ProjectDiscovery + fuzzing tools (httpx, nuclei, ffuf, gobuster) are Go
# binaries pinned by digest in a build stage for the operator's environment;
# left as a documented placeholder. Until added, the gate still authorizes them
# but the sandbox exits non-zero ("not found") and the agent adapts -- it never
# fails open.

# Drop to an unprivileged user; DockerSandbox also forces --user 65534:65534.
USER 65534:65534
ENTRYPOINT []
