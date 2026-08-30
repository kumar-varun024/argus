from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class TakeoverSignature:
    """Fingerprint signature for Subdomain Takeover detection."""
    service: str
    cname_patterns: List[str]
    fingerprints: List[str] = field(default_factory=list)
    nxdomain: bool = False
    status_codes: List[int] = field(default_factory=lambda: [404, 400, 502, 503])
    severity: str = "critical"
    discussion: str = ""

    def matches_cname(self, cname: str) -> bool:
        if not cname:
            return False
        cname_lower = cname.lower().rstrip(".")
        for pattern in self.cname_patterns:
            p_lower = pattern.lower().rstrip(".")
            if cname_lower == p_lower or cname_lower.endswith("." + p_lower) or p_lower in cname_lower:
                return True
        return False

    def matches_body(self, body: str) -> bool:
        if not body:
            return False
        body_lower = body.lower()
        for fp in self.fingerprints:
            if fp.lower() in body_lower:
                return True
        return False

    def matches_status(self, status_code: int) -> bool:
        if not self.status_codes:
            return True
        return status_code in self.status_codes


TAKEOVER_SIGNATURES: List[TakeoverSignature] = [
    TakeoverSignature(
        service="GitHub Pages",
        cname_patterns=["github.io", "github.map.fastly.net"],
        fingerprints=[
            "There isn't a GitHub Pages site here.",
            "404 Not Found - There isn't a GitHub Pages site here",
            "For root URLs (like http://example.com/) you must provide an index.html file",
        ],
        nxdomain=False,
        status_codes=[404],
        severity="critical",
        discussion="Domain points to GitHub Pages but no repository is configured to serve content for it.",
    ),
    TakeoverSignature(
        service="AWS S3",
        cname_patterns=["s3.amazonaws.com", "s3-website", "s3.dualstack", "amazonaws.com/s3"],
        fingerprints=[
            "The specified bucket does not exist",
            "NoSuchBucket",
            "BucketName",
        ],
        nxdomain=False,
        status_codes=[404, 403],
        severity="critical",
        discussion="Domain points to an AWS S3 bucket that has been deleted or does not exist.",
    ),
    TakeoverSignature(
        service="Heroku",
        cname_patterns=["herokuapp.com", "herokussl.com", "herokudns.com"],
        fingerprints=[
            "No such app",
            "herokucdn.com/error-pages/no-such-app.html",
            "There's nothing here, yet.",
        ],
        nxdomain=False,
        status_codes=[404, 502, 503],
        severity="critical",
        discussion="Domain CNAME points to Heroku app that has been deleted or renamed.",
    ),
    TakeoverSignature(
        service="Azure App Service",
        cname_patterns=["azurewebsites.net", "cloudapp.net", "azure-api.net", "trafficmanager.net"],
        fingerprints=[
            "404 Web Site not found",
            "The web site you want to access doesn't exist in our system",
            "Microsoft-Azure-Application-Gateway",
        ],
        nxdomain=False,
        status_codes=[404],
        severity="critical",
        discussion="Domain points to Azure App Service slot or resource that is unregistered.",
    ),
    TakeoverSignature(
        service="AWS CloudFront",
        cname_patterns=["cloudfront.net"],
        fingerprints=[
            "Bad request: ERROR: The request could not be satisfied",
            "The request could not be satisfied",
            "CloudFront",
        ],
        nxdomain=False,
        status_codes=[403, 404, 400],
        severity="critical",
        discussion="Domain points to AWS CloudFront distribution that is disabled or missing alternate domain name.",
    ),
    TakeoverSignature(
        service="Shopify",
        cname_patterns=["myshopify.com"],
        fingerprints=[
            "Sorry, this shop is currently unavailable",
            "Whatever you are looking for that is on this page cannot be found",
            "Only one step left!",
        ],
        nxdomain=False,
        status_codes=[404],
        severity="critical",
        discussion="Domain points to Shopify store that is deleted or unassigned.",
    ),
    TakeoverSignature(
        service="Fastly",
        cname_patterns=["fastly.net", "fastlylb.net"],
        fingerprints=[
            "Fastly error: unknown domain",
            "Fastly error: unknown domain:",
            "Details: cache-",
        ],
        nxdomain=False,
        status_codes=[500, 404],
        severity="critical",
        discussion="Domain points to Fastly CDN without a corresponding service configuration.",
    ),
    TakeoverSignature(
        service="Pantheon",
        cname_patterns=["pantheonsite.io", "pantheon.io"],
        fingerprints=[
            "404 Unknown Site",
            "The gods are wise, but do not know of the site which you seek",
        ],
        nxdomain=False,
        status_codes=[404],
        severity="critical",
        discussion="Domain points to Pantheon infrastructure without active site binding.",
    ),
    TakeoverSignature(
        service="Helpjuice",
        cname_patterns=["helpjuice.com"],
        fingerprints=[
            "We could not find what you're looking for",
            "The page you requested does not exist",
        ],
        nxdomain=False,
        status_codes=[404],
        severity="critical",
        discussion="Helpjuice knowledge base account was removed but CNAME record remains.",
    ),
    TakeoverSignature(
        service="Surge.sh",
        cname_patterns=["surge.sh", "na-bootstrap1.surge.sh"],
        fingerprints=[
            "project not found",
            "Surge.sh - project not found",
        ],
        nxdomain=False,
        status_codes=[404],
        severity="critical",
        discussion="Domain points to Surge.sh but no project is deployed on that custom domain.",
    ),
    TakeoverSignature(
        service="Tumblr",
        cname_patterns=["domains.tumblr.com", "tumblr.com"],
        fingerprints=[
            "Whatever you're looking for isn't here",
            "There's nothing here.",
        ],
        nxdomain=False,
        status_codes=[404],
        severity="critical",
        discussion="Tumblr custom domain is unassigned.",
    ),
    TakeoverSignature(
        service="WordPress.com",
        cname_patterns=["wordpress.com", "wpengine.com"],
        fingerprints=[
            "Do you want to register",
            "is not registered on WordPress.com",
        ],
        nxdomain=False,
        status_codes=[404],
        severity="critical",
        discussion="WordPress.com domain mapping points to unassigned site.",
    ),
    TakeoverSignature(
        service="Ghost",
        cname_patterns=["ghost.io"],
        fingerprints=[
            "The thing you were looking for is no longer here",
            "The site you were looking for doesn't exist",
        ],
        nxdomain=False,
        status_codes=[404],
        severity="critical",
        discussion="Ghost(Pro) blog instance was deleted but DNS alias remains.",
    ),
    TakeoverSignature(
        service="Cargo Collective",
        cname_patterns=["cargocollective.com", "cargo.site"],
        fingerprints=[
            "404 Not Found",
            "If you're moving your domain away from Cargo",
            "Cargo: 404",
        ],
        nxdomain=False,
        status_codes=[404],
        severity="critical",
        discussion="Cargo collective website removed.",
    ),
    TakeoverSignature(
        service="Bitbucket",
        cname_patterns=["bitbucket.io"],
        fingerprints=[
            "Repository not found",
            "The page you have requested cannot be found",
        ],
        nxdomain=False,
        status_codes=[404],
        severity="critical",
        discussion="Bitbucket Cloud page repository does not exist.",
    ),
    TakeoverSignature(
        service="Feedpress",
        cname_patterns=["feedpress.me", "redirect.feedpress.me"],
        fingerprints=[
            "The feed has not been found.",
        ],
        nxdomain=False,
        status_codes=[404],
        severity="critical",
        discussion="Feedpress feed mapping is inactive.",
    ),
    TakeoverSignature(
        service="Readme.io",
        cname_patterns=["readme.io"],
        fingerprints=[
            "Project doesnt exist",
            "Project doesn't exist",
        ],
        nxdomain=False,
        status_codes=[404],
        severity="critical",
        discussion="Readme documentation project was removed.",
    ),
    TakeoverSignature(
        service="Statuspage",
        cname_patterns=["statuspage.io"],
        fingerprints=[
            "You are being redirected to",
            "Hosted Status Pages | Statuspage by Atlassian",
            "Better Downtime Communication",
        ],
        nxdomain=False,
        status_codes=[404],
        severity="critical",
        discussion="Statuspage host points to unconfigured account.",
    ),
    TakeoverSignature(
        service="Zendesk",
        cname_patterns=["zendesk.com"],
        fingerprints=[
            "Help Center Closed",
            "this help center no longer exists",
        ],
        nxdomain=False,
        status_codes=[404],
        severity="critical",
        discussion="Zendesk help center is closed or unassigned.",
    ),
    TakeoverSignature(
        service="Webflow",
        cname_patterns=["webflow.io", "proxy.webflow.io", "proxy-ssl.webflow.io"],
        fingerprints=[
            "The page you are looking for doesn't exist or has been moved",
            "The site you are looking for is not published.",
        ],
        nxdomain=False,
        status_codes=[404],
        severity="critical",
        discussion="Webflow custom domain not published to any site.",
    ),
    TakeoverSignature(
        service="Strikingly",
        cname_patterns=["strikinglydns.com", "s.strikingly.com"],
        fingerprints=[
            "page not found",
            "This domain is not configured to any site on Strikingly",
        ],
        nxdomain=False,
        status_codes=[404],
        severity="critical",
        discussion="Strikingly domain is unassigned.",
    ),
    TakeoverSignature(
        service="Unbounce",
        cname_patterns=["unbouncepages.com"],
        fingerprints=[
            "The requested URL was not found on this server.",
            "The page you're looking for is unavailable",
        ],
        nxdomain=False,
        status_codes=[404],
        severity="critical",
        discussion="Unbounce landing page missing or deleted.",
    ),
    TakeoverSignature(
        service="HubSpot",
        cname_patterns=["hubspot.net"],
        fingerprints=[
            "Domain not found",
            "HubSpot - Domain not found",
        ],
        nxdomain=False,
        status_codes=[404],
        severity="critical",
        discussion="HubSpot domain is unmapped.",
    ),
    TakeoverSignature(
        service="Fly.io",
        cname_patterns=["fly.dev", "edge.fly.dev"],
        fingerprints=[
            "404 Not Found: App not found",
            "404 Not Found",
        ],
        nxdomain=False,
        status_codes=[404],
        severity="critical",
        discussion="Fly.io app has been deleted or unassigned.",
    ),
    TakeoverSignature(
        service="Vercel",
        cname_patterns=["vercel.app", "cname.vercel-dns.com"],
        fingerprints=[
            "404: NOT_FOUND",
            "The deployment could not be found",
        ],
        nxdomain=False,
        status_codes=[404],
        severity="critical",
        discussion="Vercel deployment is missing or project not connected.",
    ),
    TakeoverSignature(
        service="Netlify",
        cname_patterns=["netlify.app", "netlify.com"],
        fingerprints=[
            "Not Found - Request ID",
            "Netlify: Page Not Found",
        ],
        nxdomain=False,
        status_codes=[404],
        severity="critical",
        discussion="Netlify site is deleted or domain unclaimed.",
    ),
]


def find_signature_by_cname(cname: str) -> List[TakeoverSignature]:
    """Finds all signatures that match the given CNAME string."""
    return [sig for sig in TAKEOVER_SIGNATURES if sig.matches_cname(cname)]


def find_signature_by_service(service: str) -> Optional[TakeoverSignature]:
    """Finds a signature by service name."""
    service_lower = service.lower()
    for sig in TAKEOVER_SIGNATURES:
        if sig.service.lower() == service_lower:
            return sig
    return None


def get_all_signatures() -> List[TakeoverSignature]:
    """Returns all configured takeover signatures."""
    return list(TAKEOVER_SIGNATURES)
