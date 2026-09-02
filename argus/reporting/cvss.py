from __future__ import annotations

import math
from typing import Any, Optional, Union

from argus.reporting.models import CVSSData, CWEInfo, ReportSeverity


def cvss_roundup(val: float) -> float:
    """Official FIRST CVSS v3.1 roundup function.
    
    Rounds up to 1 decimal place with floating-point precision correction.
    """
    int_val = round(val * 100000)
    if int_val % 10000 == 0:
        return int_val / 100000.0
    else:
        return (math.floor(int_val / 10000) + 1) / 10.0


class CVSSCalculator:
    """Official FIRST CVSS v3.1 base score calculator, vector parser, and heuristic engine."""

    # Metric weight tables conforming strictly to FIRST CVSS v3.1 specification
    AV_WEIGHTS = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
    AC_WEIGHTS = {"L": 0.77, "H": 0.44}
    PR_WEIGHTS_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
    PR_WEIGHTS_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
    UI_WEIGHTS = {"N": 0.85, "R": 0.62}
    CIA_WEIGHTS = {"N": 0.0, "L": 0.22, "H": 0.56}

    # Common CWE mappings
    CWE_DATABASE = {
        "sql_injection": CWEInfo("CWE-89", "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"),
        "sqli": CWEInfo("CWE-89", "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"),
        "command_injection": CWEInfo("CWE-78", "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')"),
        "rce": CWEInfo("CWE-78", "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')"),
        "code_execution": CWEInfo("CWE-94", "Improper Control of Generation of Code ('Code Injection')"),
        "deserialization": CWEInfo("CWE-502", "Deserialization of Untrusted Data"),
        "insecure_deserialization": CWEInfo("CWE-502", "Deserialization of Untrusted Data"),
        "unsafe_deserialization": CWEInfo("CWE-502", "Deserialization of Untrusted Data"),
        "java_deserialization": CWEInfo("CWE-502", "Deserialization of Untrusted Data"),
        "python_pickle": CWEInfo("CWE-502", "Deserialization of Untrusted Data"),
        "php_unserialize": CWEInfo("CWE-502", "Deserialization of Untrusted Data"),
        "ruby_marshal": CWEInfo("CWE-502", "Deserialization of Untrusted Data"),
        "dotnet_viewstate": CWEInfo("CWE-502", "Deserialization of Untrusted Data"),
        "dotnet_binary_formatter": CWEInfo("CWE-502", "Deserialization of Untrusted Data"),
        "xss": CWEInfo("CWE-79", "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"),
        "cross_site_scripting": CWEInfo("CWE-79", "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"),
        "reflected_xss": CWEInfo("CWE-79", "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"),
        "stored_xss": CWEInfo("CWE-79", "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"),
        "dom_xss": CWEInfo("CWE-79", "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"),
        "dom_clobbering": CWEInfo("CWE-79", "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"),
        "dom_clobbering_xss": CWEInfo("CWE-79", "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"),
        "dom_clobbering_logic": CWEInfo("CWE-79", "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"),
        "html_clobbering": CWEInfo("CWE-79", "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"),
        "ssrf": CWEInfo("CWE-918", "Server-Side Request Forgery (SSRF)"),
        "server_side_request_forgery": CWEInfo("CWE-918", "Server-Side Request Forgery (SSRF)"),
        "xxe": CWEInfo("CWE-611", "Improper Restriction of XML External Entity Reference"),
        "xml_parser_validation": CWEInfo("CWE-611", "Improper Restriction of XML External Entity Reference"),
        "xml_external_entity": CWEInfo("CWE-611", "Improper Restriction of XML External Entity Reference"),
        "xml_injection": CWEInfo("CWE-91", "XML Injection (aka Blind XPath Injection)"),
        "broken_access_control": CWEInfo("CWE-284", "Improper Access Control"),
        "bac": CWEInfo("CWE-284", "Improper Access Control"),
        "authorization": CWEInfo("CWE-285", "Improper Authorization"),
        "idor": CWEInfo("CWE-639", "Authorization Bypass Through User-Controlled Key"),
        "bola": CWEInfo("CWE-639", "Authorization Bypass Through User-Controlled Key"),
        "authentication": CWEInfo("CWE-287", "Improper Authentication"),
        "auth_bypass": CWEInfo("CWE-287", "Improper Authentication"),
        "authentication_bypass": CWEInfo("CWE-287", "Improper Authentication"),
        "broken_authentication": CWEInfo("CWE-287", "Improper Authentication"),
        "mfa_bypass": CWEInfo("CWE-287", "Improper Authentication"),
        "cwe_287": CWEInfo("CWE-287", "Improper Authentication"),
        "cwe-287": CWEInfo("CWE-287", "Improper Authentication"),
        "brute_force": CWEInfo("CWE-307", "Improper Restriction of Excessive Authentication Attempts"),
        "account_lockout_missing": CWEInfo("CWE-307", "Improper Restriction of Excessive Authentication Attempts"),
        "credential_stuffing": CWEInfo("CWE-307", "Improper Restriction of Excessive Authentication Attempts"),
        "unthrottled_otp_brute_force": CWEInfo("CWE-307", "Improper Restriction of Excessive Authentication Attempts"),
        "cwe_307": CWEInfo("CWE-307", "Improper Restriction of Excessive Authentication Attempts"),
        "cwe-307": CWEInfo("CWE-307", "Improper Restriction of Excessive Authentication Attempts"),
        "session_fixation": CWEInfo("CWE-384", "Session Fixation"),
        "cwe_384": CWEInfo("CWE-384", "Session Fixation"),
        "cwe-384": CWEInfo("CWE-384", "Session Fixation"),
        "password_reset": CWEInfo("CWE-640", "Weak Password Recovery Mechanism for Forgotten Password"),
        "password_reset_abuse": CWEInfo("CWE-640", "Weak Password Recovery Mechanism for Forgotten Password"),
        "password_reset_host_injection": CWEInfo("CWE-640", "Weak Password Recovery Mechanism for Forgotten Password"),
        "reset_token_reuse": CWEInfo("CWE-640", "Weak Password Recovery Mechanism for Forgotten Password"),
        "weak_password_recovery": CWEInfo("CWE-640", "Weak Password Recovery Mechanism for Forgotten Password"),
        "cwe_640": CWEInfo("CWE-640", "Weak Password Recovery Mechanism for Forgotten Password"),
        "cwe-640": CWEInfo("CWE-640", "Weak Password Recovery Mechanism for Forgotten Password"),
        "alternate_path_auth": CWEInfo("CWE-288", "Authentication Bypass Using an Alternate Path or Channel"),
        "mfa_forced_browsing": CWEInfo("CWE-288", "Authentication Bypass Using an Alternate Path or Channel"),
        "cwe_288": CWEInfo("CWE-288", "Authentication Bypass Using an Alternate Path or Channel"),
        "cwe-288": CWEInfo("CWE-288", "Authentication Bypass Using an Alternate Path or Channel"),
        "jwt": CWEInfo("CWE-345", "Insufficient Verification of Data Authenticity"),
        "jwt_manipulation": CWEInfo("CWE-345", "Insufficient Verification of Data Authenticity"),
        "jwt_token_weakness": CWEInfo("CWE-1390", "Weak Authentication Token"),
        "weak_authentication_token": CWEInfo("CWE-1390", "Weak Authentication Token"),
        "cwe_1390": CWEInfo("CWE-1390", "Weak Authentication Token"),
        "cwe-1390": CWEInfo("CWE-1390", "Weak Authentication Token"),
        "default_credentials": CWEInfo("CWE-798", "Use of Hard-coded Credentials"),
        "hardcoded_credentials": CWEInfo("CWE-798", "Use of Hard-coded Credentials"),
        "cwe_798": CWEInfo("CWE-798", "Use of Hard-coded Credentials"),
        "cwe-798": CWEInfo("CWE-798", "Use of Hard-coded Credentials"),
        "use_of_default_credentials": CWEInfo("CWE-1392", "Use of Default Credentials"),
        "cwe_1392": CWEInfo("CWE-1392", "Use of Default Credentials"),
        "cwe-1392": CWEInfo("CWE-1392", "Use of Default Credentials"),
        "insufficiently_protected_credentials": CWEInfo("CWE-522", "Insufficiently Protected Credentials"),
        "auth_credential_leakage": CWEInfo("CWE-522", "Insufficiently Protected Credentials"),
        "cwe_522": CWEInfo("CWE-522", "Insufficiently Protected Credentials"),
        "cwe-522": CWEInfo("CWE-522", "Insufficiently Protected Credentials"),
        "insufficient_session_expiration": CWEInfo("CWE-613", "Insufficient Session Expiration"),
        "session_expiration": CWEInfo("CWE-613", "Insufficient Session Expiration"),
        "cwe_613": CWEInfo("CWE-613", "Insufficient Session Expiration"),
        "cwe-613": CWEInfo("CWE-613", "Insufficient Session Expiration"),
        "predictable_reset_token": CWEInfo("CWE-330", "Use of Insufficiently Random Values"),
        "low_session_entropy": CWEInfo("CWE-330", "Use of Insufficiently Random Values"),
        "cwe_330": CWEInfo("CWE-330", "Use of Insufficiently Random Values"),
        "cwe-330": CWEInfo("CWE-330", "Use of Insufficiently Random Values"),
        "insecure_cookie_attributes": CWEInfo("CWE-614", "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute"),
        "cookie_missing_secure": CWEInfo("CWE-614", "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute"),
        "cwe_614": CWEInfo("CWE-614", "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute"),
        "cwe-614": CWEInfo("CWE-614", "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute"),
        "cookie_missing_httponly": CWEInfo("CWE-1004", "Sensitive Cookie Without 'HttpOnly' Flag"),
        "cwe_1004": CWEInfo("CWE-1004", "Sensitive Cookie Without 'HttpOnly' Flag"),
        "cwe-1004": CWEInfo("CWE-1004", "Sensitive Cookie Without 'HttpOnly' Flag"),
        "cookie_missing_samesite": CWEInfo("CWE-1275", "Sensitive Cookie with Improper SameSite Attribute"),
        "cwe_1275": CWEInfo("CWE-1275", "Sensitive Cookie with Improper SameSite Attribute"),
        "cwe-1275": CWEInfo("CWE-1275", "Sensitive Cookie with Improper SameSite Attribute"),
        "information_disclosure": CWEInfo("CWE-200", "Exposure of Sensitive Information to an Unauthorized Actor"),
        "info_disclosure": CWEInfo("CWE-200", "Exposure of Sensitive Information to an Unauthorized Actor"),
        "sensitive_data_exposure": CWEInfo("CWE-200", "Exposure of Sensitive Information to an Unauthorized Actor"),
        "path_traversal": CWEInfo("CWE-22", "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')"),
        "directory_traversal": CWEInfo("CWE-22", "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')"),
        "lfi": CWEInfo("CWE-22", "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')"),
        "rfi": CWEInfo("CWE-98", "Improper Control of Generation of Code ('PHP Remote File Inclusion')"),
        "csrf": CWEInfo("CWE-352", "Cross-Site Request Forgery (CSRF)"),
        "cross_site_request_forgery": CWEInfo("CWE-352", "Cross-Site Request Forgery (CSRF)"),
        "open_redirect": CWEInfo("CWE-601", "URL Redirection to Untrusted Site ('Open Redirect')"),
        "open_redirect_chain": CWEInfo("CWE-601", "URL Redirection to Untrusted Site ('Open Redirect')"),
        "unvalidated_redirect": CWEInfo("CWE-601", "URL Redirection to Untrusted Site ('Open Redirect')"),
        "redirect": CWEInfo("CWE-601", "URL Redirection to Untrusted Site ('Open Redirect')"),
        "cwe_601": CWEInfo("CWE-601", "URL Redirection to Untrusted Site ('Open Redirect')"),
        "cwe-601": CWEInfo("CWE-601", "URL Redirection to Untrusted Site ('Open Redirect')"),
        "file_upload": CWEInfo("CWE-434", "Unrestricted Upload of File with Dangerous Type"),
        "arbitrary_file_upload": CWEInfo("CWE-434", "Unrestricted Upload of File with Dangerous Type"),
        "unrestricted_file_upload": CWEInfo("CWE-434", "Unrestricted Upload of File with Dangerous Type"),
        "unrestricted_upload": CWEInfo("CWE-434", "Unrestricted Upload of File with Dangerous Type"),
        "mime_type_bypass": CWEInfo("CWE-436", "Interpretation Conflict"),
        "double_extension_bypass": CWEInfo("CWE-436", "Interpretation Conflict"),
        "polyglot_magic_bytes": CWEInfo("CWE-436", "Interpretation Conflict"),
        "polyglot_upload": CWEInfo("CWE-436", "Interpretation Conflict"),
        "null_byte_injection": CWEInfo("CWE-434", "Unrestricted Upload of File with Dangerous Type"),
        "web_shell_execution": CWEInfo("CWE-434", "Unrestricted Upload of File with Dangerous Type"),
        "interpretation_conflict": CWEInfo("CWE-436", "Interpretation Conflict"),
        "cwe-434": CWEInfo("CWE-434", "Unrestricted Upload of File with Dangerous Type"),
        "cwe_434": CWEInfo("CWE-434", "Unrestricted Upload of File with Dangerous Type"),
        "cwe-436": CWEInfo("CWE-436", "Interpretation Conflict"),
        "cwe_436": CWEInfo("CWE-436", "Interpretation Conflict"),
        "graphql": CWEInfo("CWE-200", "Exposure of Sensitive Information to an Unauthorized Actor"),
        "graphql_introspection": CWEInfo("CWE-200", "Exposure of Sensitive Information to an Unauthorized Actor"),
        "graphql_security": CWEInfo("CWE-200", "Exposure of Sensitive Information to an Unauthorized Actor"),
        "graphql_dos": CWEInfo("CWE-400", "Uncontrolled Resource Consumption"),
        "graphql_depth_dos": CWEInfo("CWE-400", "Uncontrolled Resource Consumption"),
        "graphql_batching": CWEInfo("CWE-799", "Improper Control of Interaction Frequency"),
        "graphql_batching_bypass": CWEInfo("CWE-799", "Improper Control of Interaction Frequency"),
        "graphql_access_control": CWEInfo("CWE-285", "Improper Authorization"),
        "websocket": CWEInfo("CWE-1385", "Missing Origin Validation in WebSockets"),
        "websocket_security": CWEInfo("CWE-1385", "Missing Origin Validation in WebSockets"),
        "cswsh": CWEInfo("CWE-1385", "Missing Origin Validation in WebSockets"),
        "cross_site_websocket_hijacking": CWEInfo("CWE-1385", "Missing Origin Validation in WebSockets"),
        "websocket_auth": CWEInfo("CWE-306", "Missing Authentication for Critical Function"),
        "websocket_unauthenticated": CWEInfo("CWE-306", "Missing Authentication for Critical Function"),
        "websocket_injection": CWEInfo("CWE-74", "Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')"),
        "websocket_sqli": CWEInfo("CWE-89", "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"),
        "websocket_cmdi": CWEInfo("CWE-78", "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')"),
        "websocket_xss": CWEInfo("CWE-79", "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"),
        "websocket_prototype_pollution": CWEInfo("CWE-1321", "Improperly Controlled Modification of Dynamically-Determined Object Attributes"),
        "prototype_pollution": CWEInfo("CWE-1321", "Improperly Controlled Modification of Dynamically-Determined Object Attributes"),
        "server_side_prototype_pollution": CWEInfo("CWE-1321", "Improperly Controlled Modification of Dynamically-Determined Object Attributes"),
        "client_side_prototype_pollution": CWEInfo("CWE-1321", "Improperly Controlled Modification of Dynamically-Determined Object Attributes"),
        "dom_prototype_pollution": CWEInfo("CWE-1321", "Improperly Controlled Modification of Dynamically-Determined Object Attributes"),
        "prototype_pollution_gadget": CWEInfo("CWE-1321", "Improperly Controlled Modification of Dynamically-Determined Object Attributes"),
        "express_prototype_pollution": CWEInfo("CWE-1321", "Improperly Controlled Modification of Dynamically-Determined Object Attributes"),
        "lodash_prototype_pollution": CWEInfo("CWE-1321", "Improperly Controlled Modification of Dynamically-Determined Object Attributes"),
        "cwe_1321": CWEInfo("CWE-1321", "Improperly Controlled Modification of Dynamically-Determined Object Attributes"),
        "cwe-1321": CWEInfo("CWE-1321", "Improperly Controlled Modification of Dynamically-Determined Object Attributes"),
        "websocket_dos": CWEInfo("CWE-400", "Uncontrolled Resource Consumption"),
        "websocket_rate_limit": CWEInfo("CWE-799", "Improper Control of Interaction Frequency"),
        "request_smuggling": CWEInfo("CWE-444", "Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling')"),
        "http_request_smuggling": CWEInfo("CWE-444", "Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling')"),
        "cl_te": CWEInfo("CWE-444", "Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling')"),
        "te_cl": CWEInfo("CWE-444", "Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling')"),
        "te_te": CWEInfo("CWE-444", "Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling')"),
        "h2_smuggling": CWEInfo("CWE-444", "Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling')"),
        "http2_smuggling": CWEInfo("CWE-444", "Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling')"),
        "h2_cl": CWEInfo("CWE-444", "Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling')"),
        "h2_te": CWEInfo("CWE-444", "Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling')"),
        "http_desync": CWEInfo("CWE-444", "Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling')"),
        "smuggling": CWEInfo("CWE-444", "Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling')"),
        "cors": CWEInfo("CWE-942", "Permissive Cross-domain Policy with Untrusted Domains"),
        "cors_headers": CWEInfo("CWE-942", "Permissive Cross-domain Policy with Untrusted Domains"),
        "cors_security": CWEInfo("CWE-942", "Permissive Cross-domain Policy with Untrusted Domains"),
        "cors_misconfiguration": CWEInfo("CWE-942", "Permissive Cross-domain Policy with Untrusted Domains"),
        "origin_reflection": CWEInfo("CWE-942", "Permissive Cross-domain Policy with Untrusted Domains"),
        "null_origin_allowed": CWEInfo("CWE-942", "Permissive Cross-domain Policy with Untrusted Domains"),
        "wildcard_with_credentials": CWEInfo("CWE-942", "Permissive Cross-domain Policy with Untrusted Domains"),
        "subdomain_trust_abuse": CWEInfo("CWE-942", "Permissive Cross-domain Policy with Untrusted Domains"),
        "preflight_bypass": CWEInfo("CWE-942", "Permissive Cross-domain Policy with Untrusted Domains"),
        "origin_parser_differential": CWEInfo("CWE-942", "Permissive Cross-domain Policy with Untrusted Domains"),
        "cwe_942": CWEInfo("CWE-942", "Permissive Cross-domain Policy with Untrusted Domains"),
        "cwe-942": CWEInfo("CWE-942", "Permissive Cross-domain Policy with Untrusted Domains"),
        "header_security": CWEInfo("CWE-693", "Protection Mechanism Failure"),
        "missing_security_headers": CWEInfo("CWE-693", "Protection Mechanism Failure"),
        "clickjacking": CWEInfo("CWE-1021", "Improper Restriction of Rendered UI Layers or Frames"),
        "security_headers": CWEInfo("CWE-693", "Protection Mechanism Failure"),
        "http_security_headers": CWEInfo("CWE-693", "Protection Mechanism Failure"),
        "security_header": CWEInfo("CWE-693", "Protection Mechanism Failure"),
        "http_headers": CWEInfo("CWE-693", "Protection Mechanism Failure"),
        "csp": CWEInfo("CWE-693", "Protection Mechanism Failure"),
        "csp_missing": CWEInfo("CWE-693", "Protection Mechanism Failure"),
        "csp_weak_directive": CWEInfo("CWE-693", "Protection Mechanism Failure"),
        "cwe_693": CWEInfo("CWE-693", "Protection Mechanism Failure"),
        "cwe-693": CWEInfo("CWE-693", "Protection Mechanism Failure"),
        "hsts": CWEInfo("CWE-319", "Cleartext Transmission of Sensitive Information"),
        "hsts_missing": CWEInfo("CWE-319", "Cleartext Transmission of Sensitive Information"),
        "hsts_weak_directive": CWEInfo("CWE-319", "Cleartext Transmission of Sensitive Information"),
        "x_frame_options": CWEInfo("CWE-1021", "Improper Restriction of Rendered UI Layers or Frames"),
        "x_frame_options_missing": CWEInfo("CWE-1021", "Improper Restriction of Rendered UI Layers or Frames"),
        "x_frame_options_misconfigured": CWEInfo("CWE-1021", "Improper Restriction of Rendered UI Layers or Frames"),
        "clickjacking": CWEInfo("CWE-1021", "Improper Restriction of Rendered UI Layers or Frames"),
        "ui_redressing": CWEInfo("CWE-1021", "Improper Restriction of Rendered UI Layers or Frames"),
        "missing_frame_ancestors": CWEInfo("CWE-1021", "Improper Restriction of Rendered UI Layers or Frames"),
        "frame_busting_bypass": CWEInfo("CWE-1021", "Improper Restriction of Rendered UI Layers or Frames"),
        "xfo": CWEInfo("CWE-1021", "Improper Restriction of Rendered UI Layers or Frames"),
        "cwe_1021": CWEInfo("CWE-1021", "Improper Restriction of Rendered UI Layers or Frames"),
        "cwe-1021": CWEInfo("CWE-1021", "Improper Restriction of Rendered UI Layers or Frames"),
        "x_content_type_options": CWEInfo("CWE-693", "Protection Mechanism Failure"),
        "x_content_type_options_missing": CWEInfo("CWE-693", "Protection Mechanism Failure"),
        "nosniff": CWEInfo("CWE-693", "Protection Mechanism Failure"),
        "referrer_policy": CWEInfo("CWE-693", "Protection Mechanism Failure"),
        "referrer_policy_weak": CWEInfo("CWE-693", "Protection Mechanism Failure"),
        "permissions_policy": CWEInfo("CWE-693", "Protection Mechanism Failure"),
        "permissions_policy_weak": CWEInfo("CWE-693", "Protection Mechanism Failure"),
        "x_xss_protection": CWEInfo("CWE-693", "Protection Mechanism Failure"),
        "x_xss_protection_disabled": CWEInfo("CWE-693", "Protection Mechanism Failure"),
        "cache_control_sensitive_leak": CWEInfo("CWE-525", "Use of Web Browser Cache Containing Sensitive Information"),
        "cache_control_sensitive": CWEInfo("CWE-525", "Use of Web Browser Cache Containing Sensitive Information"),
        "cwe_525": CWEInfo("CWE-525", "Use of Web Browser Cache Containing Sensitive Information"),
        "cwe-525": CWEInfo("CWE-525", "Use of Web Browser Cache Containing Sensitive Information"),
        "rate_limit": CWEInfo("CWE-799", "Improper Control of Interaction Frequency"),
        "race_conditions": CWEInfo("CWE-362", "Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')"),
        "race_condition": CWEInfo("CWE-362", "Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')"),
        "concurrency": CWEInfo("CWE-362", "Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')"),
        "toctou": CWEInfo("CWE-367", "Time-of-check Time-of-use (TOCTOU) Race Condition"),
        "time_of_check_time_of_use": CWEInfo("CWE-367", "Time-of-check Time-of-use (TOCTOU) Race Condition"),
        "limit_overrun": CWEInfo("CWE-799", "Improper Control of Interaction Frequency"),
        "multi_redemption": CWEInfo("CWE-799", "Improper Control of Interaction Frequency"),
        "session_concurrency": CWEInfo("CWE-362", "Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')"),
        "business_logic": CWEInfo("CWE-840", "Business Logic Errors"),
        "business_logic_flaws": CWEInfo("CWE-840", "Business Logic Errors"),
        "business_logic_security": CWEInfo("CWE-840", "Business Logic Errors"),
        "business_logic_errors": CWEInfo("CWE-840", "Business Logic Errors"),
        "state_machine": CWEInfo("CWE-840", "Business Logic Errors"),
        "state_machine_security": CWEInfo("CWE-840", "Business Logic Errors"),
        "workflow_bypass": CWEInfo("CWE-840", "Business Logic Errors"),
        "step_skipping": CWEInfo("CWE-840", "Business Logic Errors"),
        "workflow_step_skip": CWEInfo("CWE-840", "Business Logic Errors"),
        "price_tampering": CWEInfo("CWE-602", "Client-Side Enforcement of Server-Side Security"),
        "quantity_tampering": CWEInfo("CWE-602", "Client-Side Enforcement of Server-Side Security"),
        "parameter_tampering": CWEInfo("CWE-602", "Client-Side Enforcement of Server-Side Security"),
        "zero_amount_checkout": CWEInfo("CWE-602", "Client-Side Enforcement of Server-Side Security"),
        "currency_tampering": CWEInfo("CWE-602", "Client-Side Enforcement of Server-Side Security"),
        "mass_assignment": CWEInfo("CWE-915", "Improperly Controlled Modification of Dynamically-Determined Object Attributes"),
        "parameter_injection": CWEInfo("CWE-915", "Improperly Controlled Modification of Dynamically-Determined Object Attributes"),
        "coupon_stacking": CWEInfo("CWE-799", "Improper Control of Interaction Frequency"),
        "voucher_stacking": CWEInfo("CWE-799", "Improper Control of Interaction Frequency"),
        "idempotency_abuse": CWEInfo("CWE-799", "Improper Control of Interaction Frequency"),
        "differential_state_verification": CWEInfo("CWE-840", "Business Logic Errors"),
        "differential_state": CWEInfo("CWE-840", "Business Logic Errors"),
        "ssti": CWEInfo("CWE-1336", "Improper Neutralization of Special Elements Used in a Template Engine"),
        "server_side_template_injection": CWEInfo("CWE-1336", "Improper Neutralization of Special Elements Used in a Template Engine"),
        "template_injection": CWEInfo("CWE-1336", "Improper Neutralization of Special Elements Used in a Template Engine"),
        "ssti_rce": CWEInfo("CWE-94", "Improper Control of Generation of Code ('Code Injection')"),
        "ssti_blind": CWEInfo("CWE-1336", "Improper Neutralization of Special Elements Used in a Template Engine"),
        "ssti_error": CWEInfo("CWE-1336", "Improper Neutralization of Special Elements Used in a Template Engine"),
        "jinja": CWEInfo("CWE-1336", "Improper Neutralization of Special Elements Used in a Template Engine"),
        "jinja2": CWEInfo("CWE-1336", "Improper Neutralization of Special Elements Used in a Template Engine"),
        "twig": CWEInfo("CWE-1336", "Improper Neutralization of Special Elements Used in a Template Engine"),
        "freemarker": CWEInfo("CWE-1336", "Improper Neutralization of Special Elements Used in a Template Engine"),
        "velocity": CWEInfo("CWE-1336", "Improper Neutralization of Special Elements Used in a Template Engine"),
        "mako": CWEInfo("CWE-1336", "Improper Neutralization of Special Elements Used in a Template Engine"),
        "spel": CWEInfo("CWE-94", "Improper Control of Generation of Code ('Code Injection')"),
        "spring_expression_language": CWEInfo("CWE-94", "Improper Control of Generation of Code ('Code Injection')"),
        "thymeleaf": CWEInfo("CWE-1336", "Improper Neutralization of Special Elements Used in a Template Engine"),
        "erb": CWEInfo("CWE-1336", "Improper Neutralization of Special Elements Used in a Template Engine"),
        "pug": CWEInfo("CWE-1336", "Improper Neutralization of Special Elements Used in a Template Engine"),
        "handlebars": CWEInfo("CWE-1336", "Improper Neutralization of Special Elements Used in a Template Engine"),
        "ejs": CWEInfo("CWE-1336", "Improper Neutralization of Special Elements Used in a Template Engine"),
        "smarty": CWEInfo("CWE-1336", "Improper Neutralization of Special Elements Used in a Template Engine"),
        "cache_security": CWEInfo("CWE-444", "Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling / Cache Poisoning')"),
        "web_cache_poisoning": CWEInfo("CWE-444", "Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling / Cache Poisoning')"),
        "cache_poisoning": CWEInfo("CWE-444", "Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling / Cache Poisoning')"),
        "unkeyed_header_poisoning": CWEInfo("CWE-444", "Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling / Cache Poisoning')"),
        "unkeyed_param_poisoning": CWEInfo("CWE-444", "Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling / Cache Poisoning')"),
        "parameter_cloaking": CWEInfo("CWE-444", "Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling / Cache Poisoning')"),
        "cache_key_normalization": CWEInfo("CWE-444", "Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling / Cache Poisoning')"),
        "fat_get_poisoning": CWEInfo("CWE-444", "Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling / Cache Poisoning')"),
        "method_override_poisoning": CWEInfo("CWE-444", "Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling / Cache Poisoning')"),
        "web_cache_deception": CWEInfo("CWE-524", "Use of Cache Containing Sensitive Information"),
        "cache_deception": CWEInfo("CWE-524", "Use of Cache Containing Sensitive Information"),
        "wcd": CWEInfo("CWE-524", "Use of Cache Containing Sensitive Information"),
        "broken_object_level_authorization": CWEInfo("CWE-639", "Authorization Bypass Through User-Controlled Key"),
        "bola_idor": CWEInfo("CWE-639", "Authorization Bypass Through User-Controlled Key"),
        "cwe_639": CWEInfo("CWE-639", "Authorization Bypass Through User-Controlled Key"),
        "cwe-639": CWEInfo("CWE-639", "Authorization Bypass Through User-Controlled Key"),
        "cwe_915": CWEInfo("CWE-915", "Improperly Controlled Modification of Dynamically-Determined Object Attributes"),
        "cwe-915": CWEInfo("CWE-915", "Improperly Controlled Modification of Dynamically-Determined Object Attributes"),
        "rate_limiting": CWEInfo("CWE-770", "Allocation of Resources Without Limits or Throttling"),
        "rate_limiting_bypass": CWEInfo("CWE-770", "Allocation of Resources Without Limits or Throttling"),
        "rate_limit_bypass": CWEInfo("CWE-770", "Allocation of Resources Without Limits or Throttling"),
        "missing_rate_limit": CWEInfo("CWE-770", "Allocation of Resources Without Limits or Throttling"),
        "allocation_of_resources": CWEInfo("CWE-770", "Allocation of Resources Without Limits or Throttling"),
        "cwe_770": CWEInfo("CWE-770", "Allocation of Resources Without Limits or Throttling"),
        "cwe-770": CWEInfo("CWE-770", "Allocation of Resources Without Limits or Throttling"),
        "excessive_data_exposure": CWEInfo("CWE-200", "Exposure of Sensitive Information to an Unauthorized Actor"),
        "api_excessive_data": CWEInfo("CWE-200", "Exposure of Sensitive Information to an Unauthorized Actor"),
        "method_tampering": CWEInfo("CWE-650", "Trusting HTTP Permission Methods on the Server Side"),
        "http_method_tampering": CWEInfo("CWE-650", "Trusting HTTP Permission Methods on the Server Side"),
        "api_security": CWEInfo("CWE-639", "Authorization Bypass Through User-Controlled Key"),
        "rest_api_security": CWEInfo("CWE-639", "Authorization Bypass Through User-Controlled Key"),
        "grpc_security": CWEInfo("CWE-284", "Improper Access Control"),
        "cwe_650": CWEInfo("CWE-650", "Trusting HTTP Permission Methods on the Server Side"),
        "cwe-650": CWEInfo("CWE-650", "Trusting HTTP Permission Methods on the Server Side"),
        "cwe_602": CWEInfo("CWE-602", "Client-Side Enforcement of Server-Side Security"),
        "cwe-602": CWEInfo("CWE-602", "Client-Side Enforcement of Server-Side Security"),
        "cwe_200": CWEInfo("CWE-200", "Exposure of Sensitive Information to an Unauthorized Actor"),
        "cwe-200": CWEInfo("CWE-200", "Exposure of Sensitive Information to an Unauthorized Actor"),
        "cve": CWEInfo("CWE-937", "Using Components with Known Vulnerabilities"),
        "general": CWEInfo("CWE-699", "Software Development Security Issue"),
    }

    @staticmethod
    def parse_vector(vector: str) -> dict[str, str]:
        """Parses a CVSS v3.1 vector string into a metric dictionary."""
        metrics: dict[str, str] = {}
        if not vector:
            return metrics

        clean_vec = vector.strip()
        if clean_vec.startswith("CVSS:3.1/"):
            clean_vec = clean_vec[9:]
        elif clean_vec.startswith("CVSS:3.0/"):
            clean_vec = clean_vec[9:]
        elif clean_vec.startswith("/"):
            clean_vec = clean_vec[1:]

        parts = clean_vec.split("/")
        for part in parts:
            if ":" in part:
                k, v = part.split(":", 1)
                metrics[k.strip().upper()] = v.strip().upper()
        return metrics

    @staticmethod
    def format_vector(metrics: dict[str, str]) -> str:
        """Formats a metric dictionary into a canonical CVSS v3.1 vector string."""
        av = metrics.get("AV", "N").upper()
        ac = metrics.get("AC", "L").upper()
        pr = metrics.get("PR", "N").upper()
        ui = metrics.get("UI", "N").upper()
        s = metrics.get("S", "U").upper()
        c = metrics.get("C", "N").upper()
        i = metrics.get("I", "N").upper()
        a = metrics.get("A", "N").upper()

        return f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"

    @classmethod
    def calculate_base_score(cls, vector_or_metrics: Union[str, dict[str, str]]) -> float:
        """Computes the CVSS v3.1 base score from a vector string or metrics dictionary."""
        if isinstance(vector_or_metrics, str):
            metrics = cls.parse_vector(vector_or_metrics)
        else:
            metrics = {k.upper(): v.upper() for k, v in vector_or_metrics.items()}

        av = metrics.get("AV", "N")
        ac = metrics.get("AC", "L")
        pr = metrics.get("PR", "N")
        ui = metrics.get("UI", "N")
        s = metrics.get("S", "U")
        c = metrics.get("C", "N")
        i = metrics.get("I", "N")
        a = metrics.get("A", "N")

        av_val = cls.AV_WEIGHTS.get(av, 0.85)
        ac_val = cls.AC_WEIGHTS.get(ac, 0.77)
        ui_val = cls.UI_WEIGHTS.get(ui, 0.85)
        c_val = cls.CIA_WEIGHTS.get(c, 0.0)
        i_val = cls.CIA_WEIGHTS.get(i, 0.0)
        a_val = cls.CIA_WEIGHTS.get(a, 0.0)

        is_scope_changed = (s == "C")
        if is_scope_changed:
            pr_val = cls.PR_WEIGHTS_CHANGED.get(pr, 0.85)
        else:
            pr_val = cls.PR_WEIGHTS_UNCHANGED.get(pr, 0.85)

        # 1. ISS (Impact Sub-Score multiplier)
        iss = 1.0 - ((1.0 - c_val) * (1.0 - i_val) * (1.0 - a_val))

        # 2. Impact
        if iss <= 0:
            impact = 0.0
        elif not is_scope_changed:
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

        # 3. Exploitability
        exploitability = 8.22 * av_val * ac_val * pr_val * ui_val

        # 4. Base Score
        if impact <= 0.0:
            return 0.0

        if not is_scope_changed:
            raw_score = min(impact + exploitability, 10.0)
        else:
            raw_score = min(1.08 * (impact + exploitability), 10.0)

        return cvss_roundup(raw_score)

    @staticmethod
    def score_to_severity(score: float) -> ReportSeverity:
        """Maps a numeric CVSS score to standard FIRST severity rating bands."""
        if score <= 0.0:
            return ReportSeverity.INFO
        elif score < 4.0:
            return ReportSeverity.LOW
        elif score < 7.0:
            return ReportSeverity.MEDIUM
        elif score < 9.0:
            return ReportSeverity.HIGH
        else:
            return ReportSeverity.CRITICAL

    @classmethod
    def get_cwe_for_category(cls, category: str, metadata: Optional[dict[str, Any]] = None) -> Optional[CWEInfo]:
        """Resolves CWE details from metadata or standard category lookup."""
        if metadata:
            if "cwe_id" in metadata and "cwe_name" in metadata:
                return CWEInfo(id=str(metadata["cwe_id"]), name=str(metadata["cwe_name"]))
            if "cwe" in metadata and isinstance(metadata["cwe"], dict):
                return CWEInfo(id=str(metadata["cwe"].get("id", "CWE-699")), name=str(metadata["cwe"].get("name", "Security Issue")))
            if "cwe" in metadata and isinstance(metadata["cwe"], str) and metadata["cwe"].startswith("CWE-"):
                cwe_id = metadata["cwe"].strip()
                # Find matching name in database if available
                for info in cls.CWE_DATABASE.values():
                    if info.id.lower() == cwe_id.lower():
                        return info
                return CWEInfo(id=cwe_id, name="Security Issue")

        norm_cat = str(category).strip().lower().replace("-", "_").replace(" ", "_")
        if norm_cat in cls.CWE_DATABASE:
            return cls.CWE_DATABASE[norm_cat]

        for key, info in cls.CWE_DATABASE.items():
            if key in norm_cat or norm_cat in key:
                return info

        return cls.CWE_DATABASE["general"]

    @classmethod
    def get_approximate_cvss(
        cls,
        category: str,
        severity: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> CVSSData:
        """Determines approximate CVSS v3.1 data ensuring correct score ranges per severity."""
        meta = metadata or {}

        # 1. Direct vector provided in metadata
        direct_vector = meta.get("cvss_vector") or meta.get("vector")
        if direct_vector and isinstance(direct_vector, str) and "AV:" in direct_vector:
            score = cls.calculate_base_score(direct_vector)
            sev = cls.score_to_severity(score)
            rating = sev.value.title() if score > 0 else "None"
            return CVSSData(
                score=score,
                vector=direct_vector if direct_vector.startswith("CVSS:3.1/") else f"CVSS:3.1/{direct_vector}",
                severity_rating=rating,
                metrics=cls.parse_vector(direct_vector),
            )

        # 2. Direct score provided in metadata
        direct_score = meta.get("cvss_score") or meta.get("cvss")
        if direct_score is not None and isinstance(direct_score, (int, float)):
            score = float(direct_score)
            sev = cls.score_to_severity(score)
            rating = sev.value.title() if score > 0 else "None"
            # Synthesize realistic vector for given score
            vector = cls._synthesize_vector_for_score(score)
            return CVSSData(
                score=score,
                vector=vector,
                severity_rating=rating,
                metrics=cls.parse_vector(vector),
            )

        # 3. Derive based on severity and category heuristics
        target_sev = ReportSeverity.from_string(severity)
        norm_cat = str(category).strip().lower().replace("-", "_").replace(" ", "_")

        # Preset vectors tailored to vulnerability classes and calibrated for exact severity bands
        vector = cls._get_preset_vector(norm_cat, target_sev)
        score = cls.calculate_base_score(vector)
        sev_enum = cls.score_to_severity(score)
        rating = sev_enum.value.title() if score > 0 else "None"

        return CVSSData(
            score=score,
            vector=vector,
            severity_rating=rating,
            metrics=cls.parse_vector(vector),
        )

    # Aliases for backwards compatibility and specialized lookups
    get_cwe_info = get_cwe_for_category
    derive_cvss_for_vulnerability = get_approximate_cvss

    @classmethod
    def _get_preset_vector(cls, category: str, severity: ReportSeverity) -> str:
        """Returns standard calibrated CVSS 3.1 vectors by severity and category."""
        if severity == ReportSeverity.CRITICAL:
            # Critical Band: 9.0 – 10.0
            if "ssrf" in category:
                # SSRF with Cloud Metadata / Internal takeover -> Score 9.3 or 10.0
                return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N" # Score 10.0 / 9.3
            elif any(k in category for k in ("rce", "command", "code", "deserialization", "upload", "smuggl", "cl_te", "te_cl", "te_te", "desync", "h2", "race", "toctou", "concurrency", "limit_overrun", "business_logic", "price_tampering", "workflow_step_skip", "mass_assignment", "coupon_stacking", "ssti", "template_injection", "jinja", "twig", "freemarker", "velocity", "mako", "spel", "cache", "cache_security", "web_cache_poisoning", "cache_poisoning", "jwt_manipulation", "default_credentials", "mfa_bypass", "prototype_pollution_rce", "rce_gadget")):
                # Full Network RCE / Request Smuggling / Critical Race Condition / Business Logic / SSTI RCE / Critical Cache Poisoning / JWT Manipulation / Default Credentials -> Score 9.8
                return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" # Score 9.8
            elif "sql" in category:
                # Full SQL Injection (DB Admin takeover) -> Score 9.8
                return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" # Score 9.8
            else:
                return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" # Score 9.8

        elif severity == ReportSeverity.HIGH:
            # High Band: 7.0 – 8.9
            if any(k in category for k in ("idor", "bola", "bola_idor", "broken_access", "bac", "authorization", "mass_assignment", "cache_deception", "web_cache_deception", "wcd")):
                # Authenticated BOLA / IDOR / Mass Assignment / Web Cache Deception -> Score 8.1 / 8.5
                return "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N" # Score 8.1
            elif any(k in category for k in ("auth", "authentication", "auth_bypass", "credential_attack", "brute_force", "password_reset", "session_fixation", "jwt", "upload", "file_upload", "mime_type_bypass", "double_extension", "polyglot", "path_traversal_filename", "smuggl", "cl_te", "te_cl", "te_te", "desync", "h2", "race", "toctou", "concurrency", "limit_overrun", "session_concurrency", "business_logic", "price_tampering", "parameter_tampering", "workflow_step_skip", "coupon_stacking", "ssti", "template_injection", "jinja", "twig", "freemarker", "velocity", "mako", "spel", "cache", "cache_security", "web_cache_poisoning", "cache_poisoning", "unkeyed_header", "unkeyed_param", "cache_normalization", "api_security", "rest_api_security", "grpc_security", "method_tampering", "prototype_pollution", "server_side_prototype_pollution", "client_side_prototype_pollution", "dom_clobbering_xss", "prototype_pollution_gadget")):
                # Unauthenticated Auth Bypass / Request Smuggling / Race Conditions / Business Logic / SSTI / Web Cache Poisoning / File Upload Bypasses (High) -> Score 8.2
                return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N" # Score 8.2
            elif "ssrf" in category:
                # Internal Port Pivoting SSRF -> Score 7.2
                return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N" # Score 7.2
            elif any(k in category for k in ("cswsh", "websocket", "ws", "cors", "cors_security", "cors_headers", "cors_misconfiguration", "origin_reflection", "null_origin", "subdomain_trust")):
                # Cross-Site WebSocket Hijacking / CORS Reflection with Credentials -> Score 8.1
                return "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N" # Score 8.1
            elif "sql" in category:
                # Read-only or Blind SQLi -> Score 7.5
                return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" # Score 7.5
            else:
                # Default High -> Score 7.5
                return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" # Score 7.5

        elif severity == ReportSeverity.MEDIUM:
            # Medium Band: 4.0 – 6.9
            if any(k in category for k in ("reflected_xss", "xss", "cross_site_scripting")):
                # Reflected XSS -> Score 6.1
                return "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" # Score 6.1
            elif "stored_xss" in category:
                # Stored XSS -> Score 5.4
                return "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" # Score 5.4
            elif "csrf" in category:
                # CSRF -> Score 6.5
                return "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N" # Score 6.5
            elif any(k in category for k in ("info", "leak", "sensitive_data", "excessive_data", "excessive_data_exposure", "graphql", "traversal", "path", "lfi", "websocket", "ws", "session_token_analysis", "credential_stuffing", "predictable_reset_token", "low_session_entropy", "insecure_cookie_attributes")):
                # Information Disclosure (Sensitive config/tokens/WS) / Session entropy / Cookie security -> Score 5.3
                return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" # Score 5.3
            elif any(k in category for k in ("cors", "security_headers", "csp", "xfo", "clickjacking", "ui_redressing", "x_frame_options", "rate_limit", "rate_limiting", "rate_limiting_bypass", "rate_limit_bypass", "open_redirect", "open_redirect_chain", "dom_clobbering", "dom_clobbering_logic")):
                # CORS / Security Headers (CSP, XFO, Clickjacking) / Open Redirect / DOM Clobbering Logic / Rate Limiting -> Score 5.3
                return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" # Score 5.3
            else:
                # Default Medium -> Score 5.3
                return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" # Score 5.3

        elif severity == ReportSeverity.LOW:
            # Low Band: 0.1 – 3.9
            if any(k in category for k in ("redirect", "open_redirect")):
                # Open Redirect (Low Impact with user interaction) -> Score 3.1
                return "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N" # Score 3.1
            elif any(k in category for k in ("header", "cookie", "banner", "version", "security_headers", "hsts", "xcto", "referrer_policy", "permissions_policy")):
                # Missing Security Headers / Server Banner Disclosure -> Score 2.7
                return "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N" # Score 2.7
            else:
                # Default Low -> Score 3.1
                return "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N" # Score 3.1

        else: # INFO / None
            return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N" # Score 0.0

    @classmethod
    def _synthesize_vector_for_score(cls, score: float) -> str:
        """Synthesizes a representative CVSS v3.1 vector matching the target score band."""
        if score >= 9.0:
            return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        elif score >= 7.0:
            return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        elif score >= 4.0:
            return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
        elif score > 0.0:
            return "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"
        else:
            return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
