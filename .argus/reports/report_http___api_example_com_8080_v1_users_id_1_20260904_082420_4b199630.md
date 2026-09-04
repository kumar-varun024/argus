# Vulnerability Assessment Report — http://api.example.com:8080/v1/users?id=1

> **Mission ID:** `fc7f07b1-6aeb-415c-9f10-6b09746490c8`  
> **Generated At:** `2026-09-04T08:24:20.244231+00:00`  
> **Engine:** `ARGUS Vulnerability Reporting Engine v1.0.0`  
> **Total Deduplicated Findings:** `11` (from `11` evidence items)

---

## 1. Executive Summary

An authorized defensive security assessment was conducted against **http://api.example.com:8080/v1/users?id=1**. The assessment identified a total of **11** unique vulnerabilities after consolidating **11** evidence observations.

### Severity Distribution

| Severity Rating | Finding Count |
| :--- | :---: |
| 🔴 **Critical** | 1 |
| 🟠 **High** | 4 |
| 🟡 **Medium** | 3 |
| 🔵 **Low** | 0 |
| ⚪ **Info** | 3 |
| **Total Findings** | **11** |

### Category Breakdown

| Category | Findings |
| :--- | :---: |
| `prototype_pollution` | 6 |
| `api_security` | 2 |
| `endpoint` | 1 |
| `subdomain` | 1 |
| `live_host` | 1 |

---

## 2. Findings Scorecard

| # | Title | Severity | CVSS v3.1 | CWE | Target Host | Endpoint |
| :-: | :--- | :---: | :---: | :---: | :--- | :--- |
| 1 | [Client-Side Vulnerability: nodejs_child_process_rce_gadget on http://api.example.com:8080/v1/users](#finding-1) | **CRITICAL** | **9.8** | CWE-1321 | `http://api.example.com:8080` | `/v1/users` |
| 2 | [Client-Side Vulnerability: express_framework_gadget_pollution on http://api.example.com:8080/v1/users](#finding-2) | **HIGH** | **8.2** | CWE-1321 | `http://api.example.com:8080` | `/v1/users` |
| 3 | [Client-Side Vulnerability: handlebars_framework_gadget_pollution on http://api.example.com:8080/v1/users](#finding-3) | **HIGH** | **8.2** | CWE-1321 | `http://api.example.com:8080` | `/v1/users` |
| 4 | [Client-Side Vulnerability: jquery_framework_gadget_pollution on http://api.example.com:8080/v1/users](#finding-4) | **HIGH** | **8.2** | CWE-1321 | `http://api.example.com:8080` | `/v1/users` |
| 5 | [Client-Side Vulnerability: lodash_framework_gadget_pollution on http://api.example.com:8080/v1/users](#finding-5) | **HIGH** | **8.2** | CWE-1321 | `http://api.example.com:8080` | `/v1/users` |
| 6 | [API Security Vulnerability: rate_limiting_bypass on http://api.example.com:8080/v1/users](#finding-6) | **MEDIUM** | **5.3** | CWE-639 | `http://api.example.com:8080` | `/v1/users` |
| 7 | [API Security Vulnerability: rate_limiting_bypass on http://api.example.com:8080/v1/users](#finding-7) | **MEDIUM** | **5.3** | CWE-639 | `http://api.example.com:8080` | `/v1/users` |
| 8 | [Client-Side Vulnerability: missing_anti_framing_protection on http://api.example.com:8080/v1/users](#finding-8) | **MEDIUM** | **5.3** | CWE-1321 | `http://api.example.com:8080` | `/v1/users` |
| 9 | [Discovered Endpoint: http://api.example.com:8080/v1/users](#finding-9) | **INFO** | **0.0** | CWE-699 | `http://api.example.com:8080` | `/v1/users` |
| 10 | [Discovered Subdomain: api.example.com](#finding-10) | **INFO** | **0.0** | CWE-942 | `api.example.com:8080` | `/` |
| 11 | [Live Host: http://api.example.com:8080](#finding-11) | **INFO** | **0.0** | CWE-699 | `api.example.com` | `/` |

---

## 3. Detailed Vulnerability Findings

<a id="finding-1"></a>
### Finding 1: Client-Side Vulnerability: nodejs_child_process_rce_gadget on http://api.example.com:8080/v1/users

| Property | Detail |
| :--- | :--- |
| **Severity** | **CRITICAL** |
| **CVSS v3.1 Score** | **9.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) |
| **Weakness (CWE)** | **CWE-1321**: Improperly Controlled Modification of Dynamically-Determined Object Attributes |
| **Target Host** | `http://api.example.com:8080` |
| **Vulnerable Endpoint** | `/v1/users` |
| **Vulnerable Parameter** | `child_process.exec` |
| **Confidence** | 98% (CONFIRMED) |
| **Consolidated Evidence** | 1 occurrence(s) |

#### Summary & Description

Critical RCE Prototype Pollution Gadget confirmed on http://api.example.com:8080/v1/users. Pollution of child_process options allows arbitrary OS command execution. Parameter: child_process.exec, Strategy: standard, CWE: CWE-1321

#### Steps to Reproduce

1. Navigate to the target endpoint `/v1/users` on host `http://api.example.com:8080`.
2. Send a crafted HTTP request to `/v1/users`.
3. Observe the anomalous response behavior confirming prototype pollution.

#### Impact Analysis

Successful exploitation could compromise the confidentiality, integrity, or availability of the application with critical impact.

#### Recommended Remediation

Apply input validation, output encoding, and principle of least privilege to remediate the underlying flaw (CWE-1321).

#### Supporting Evidence & References

- **Evidence IDs:** `73b455fa-d237-4d5e-8000-f0d27b46d919`

---

<a id="finding-2"></a>
### Finding 2: Client-Side Vulnerability: express_framework_gadget_pollution on http://api.example.com:8080/v1/users

| Property | Detail |
| :--- | :--- |
| **Severity** | **HIGH** |
| **CVSS v3.1 Score** | **8.2** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`) |
| **Weakness (CWE)** | **CWE-1321**: Improperly Controlled Modification of Dynamically-Determined Object Attributes |
| **Target Host** | `http://api.example.com:8080` |
| **Vulnerable Endpoint** | `/v1/users` |
| **Vulnerable Parameter** | `express_view_options` |
| **Confidence** | 93% (CONFIRMED) |
| **Consolidated Evidence** | 1 occurrence(s) |

#### Summary & Description

Prototype Pollution Framework Gadget confirmed on http://api.example.com:8080/v1/users targeting EXPRESS. Injected gadget property express_view_options modifies framework configuration. Parameter: express_view_options, Strategy: standard, CWE: CWE-1321

#### Steps to Reproduce

1. Navigate to the target endpoint `/v1/users` on host `http://api.example.com:8080`.
2. Send a crafted HTTP request to `/v1/users`.
3. Observe the anomalous response behavior confirming prototype pollution.

#### Impact Analysis

Successful exploitation could compromise the confidentiality, integrity, or availability of the application with high impact.

#### Recommended Remediation

Apply input validation, output encoding, and principle of least privilege to remediate the underlying flaw (CWE-1321).

#### Supporting Evidence & References

- **Evidence IDs:** `3ec4a12d-a8a9-413e-a1ab-3938d28f4d44`

---

<a id="finding-3"></a>
### Finding 3: Client-Side Vulnerability: handlebars_framework_gadget_pollution on http://api.example.com:8080/v1/users

| Property | Detail |
| :--- | :--- |
| **Severity** | **HIGH** |
| **CVSS v3.1 Score** | **8.2** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`) |
| **Weakness (CWE)** | **CWE-1321**: Improperly Controlled Modification of Dynamically-Determined Object Attributes |
| **Target Host** | `http://api.example.com:8080` |
| **Vulnerable Endpoint** | `/v1/users` |
| **Vulnerable Parameter** | `handlebars_compiler` |
| **Confidence** | 93% (CONFIRMED) |
| **Consolidated Evidence** | 1 occurrence(s) |

#### Summary & Description

Prototype Pollution Framework Gadget confirmed on http://api.example.com:8080/v1/users targeting HANDLEBARS. Injected gadget property handlebars_compiler modifies framework configuration. Parameter: handlebars_compiler, Strategy: standard, CWE: CWE-1321

#### Steps to Reproduce

1. Navigate to the target endpoint `/v1/users` on host `http://api.example.com:8080`.
2. Send a crafted HTTP request to `/v1/users`.
3. Observe the anomalous response behavior confirming prototype pollution.

#### Impact Analysis

Successful exploitation could compromise the confidentiality, integrity, or availability of the application with high impact.

#### Recommended Remediation

Apply input validation, output encoding, and principle of least privilege to remediate the underlying flaw (CWE-1321).

#### Supporting Evidence & References

- **Evidence IDs:** `e1e82e51-1b3d-410e-b236-5a1cde28e7c8`

---

<a id="finding-4"></a>
### Finding 4: Client-Side Vulnerability: jquery_framework_gadget_pollution on http://api.example.com:8080/v1/users

| Property | Detail |
| :--- | :--- |
| **Severity** | **HIGH** |
| **CVSS v3.1 Score** | **8.2** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`) |
| **Weakness (CWE)** | **CWE-1321**: Improperly Controlled Modification of Dynamically-Determined Object Attributes |
| **Target Host** | `http://api.example.com:8080` |
| **Vulnerable Endpoint** | `/v1/users` |
| **Vulnerable Parameter** | `jquery_htmlPrefilter` |
| **Confidence** | 93% (CONFIRMED) |
| **Consolidated Evidence** | 1 occurrence(s) |

#### Summary & Description

Prototype Pollution Framework Gadget confirmed on http://api.example.com:8080/v1/users targeting JQUERY. Injected gadget property jquery_htmlPrefilter modifies framework configuration. Parameter: jquery_htmlPrefilter, Strategy: standard, CWE: CWE-1321

#### Steps to Reproduce

1. Navigate to the target endpoint `/v1/users` on host `http://api.example.com:8080`.
2. Send a crafted HTTP request to `/v1/users`.
3. Observe the anomalous response behavior confirming prototype pollution.

#### Impact Analysis

Successful exploitation could compromise the confidentiality, integrity, or availability of the application with high impact.

#### Recommended Remediation

Apply input validation, output encoding, and principle of least privilege to remediate the underlying flaw (CWE-1321).

#### Supporting Evidence & References

- **Evidence IDs:** `7af105fd-ac02-4446-8200-0cdf59d4966e`

---

<a id="finding-5"></a>
### Finding 5: Client-Side Vulnerability: lodash_framework_gadget_pollution on http://api.example.com:8080/v1/users

| Property | Detail |
| :--- | :--- |
| **Severity** | **HIGH** |
| **CVSS v3.1 Score** | **8.2** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`) |
| **Weakness (CWE)** | **CWE-1321**: Improperly Controlled Modification of Dynamically-Determined Object Attributes |
| **Target Host** | `http://api.example.com:8080` |
| **Vulnerable Endpoint** | `/v1/users` |
| **Vulnerable Parameter** | `lodash_templateSettings` |
| **Confidence** | 93% (CONFIRMED) |
| **Consolidated Evidence** | 1 occurrence(s) |

#### Summary & Description

Prototype Pollution Framework Gadget confirmed on http://api.example.com:8080/v1/users targeting LODASH. Injected gadget property lodash_templateSettings modifies framework configuration. Parameter: lodash_templateSettings, Strategy: standard, CWE: CWE-1321

#### Steps to Reproduce

1. Navigate to the target endpoint `/v1/users` on host `http://api.example.com:8080`.
2. Send a crafted HTTP request to `/v1/users`.
3. Observe the anomalous response behavior confirming prototype pollution.

#### Impact Analysis

Successful exploitation could compromise the confidentiality, integrity, or availability of the application with high impact.

#### Recommended Remediation

Apply input validation, output encoding, and principle of least privilege to remediate the underlying flaw (CWE-1321).

#### Supporting Evidence & References

- **Evidence IDs:** `2d1e3f4b-8fb1-4be3-9ee5-01cd54eea40b`

---

<a id="finding-6"></a>
### Finding 6: API Security Vulnerability: rate_limiting_bypass on http://api.example.com:8080/v1/users

| Property | Detail |
| :--- | :--- |
| **Severity** | **MEDIUM** |
| **CVSS v3.1 Score** | **5.3** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) |
| **Weakness (CWE)** | **CWE-639**: Authorization Bypass Through User-Controlled Key |
| **Target Host** | `http://api.example.com:8080` |
| **Vulnerable Endpoint** | `/v1/users` |
| **Vulnerable Parameter** | `rate_limiting` |
| **Confidence** | 95% (CONFIRMED) |
| **Consolidated Evidence** | 1 occurrence(s) |

#### Summary & Description

Missing API Rate Limiting detected on http://api.example.com:8080/v1/users. API allowed rapid burst sequence of 15 requests without throttling or rate limit headers. Parameter: rate_limiting, Strategy: standard, CWE: CWE-770

#### Steps to Reproduce

1. Navigate to the target endpoint `/v1/users` on host `http://api.example.com:8080`.
2. Send a crafted HTTP request to `/v1/users`.
3. Observe the anomalous response behavior confirming api security.

#### Impact Analysis

Successful exploitation could compromise the confidentiality, integrity, or availability of the application with medium impact.

#### Recommended Remediation

Apply input validation, output encoding, and principle of least privilege to remediate the underlying flaw (CWE-639).

#### Supporting Evidence & References

- **Evidence IDs:** `ebddbcef-910d-40c7-8e4e-a1e861ee1fec`

---

<a id="finding-7"></a>
### Finding 7: API Security Vulnerability: rate_limiting_bypass on http://api.example.com:8080/v1/users

| Property | Detail |
| :--- | :--- |
| **Severity** | **MEDIUM** |
| **CVSS v3.1 Score** | **5.3** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) |
| **Weakness (CWE)** | **CWE-639**: Authorization Bypass Through User-Controlled Key |
| **Target Host** | `http://api.example.com:8080` |
| **Vulnerable Endpoint** | `/v1/users` |
| **Vulnerable Parameter** | `X-Forwarded-For` |
| **Confidence** | 95% (CONFIRMED) |
| **Consolidated Evidence** | 1 occurrence(s) |

#### Summary & Description

Rate Limiting Header Bypass detected on http://api.example.com:8080/v1/users. Throttling was bypassed by rotating client IP headers (X-Forwarded-For) during burst requests. Parameter: X-Forwarded-For, Strategy: header_auth_bypass, CWE: CWE-770

#### Steps to Reproduce

1. Navigate to the target endpoint `/v1/users` on host `http://api.example.com:8080`.
2. Send a crafted HTTP request to `/v1/users`.
3. Observe the anomalous response behavior confirming api security.

#### Impact Analysis

Successful exploitation could compromise the confidentiality, integrity, or availability of the application with medium impact.

#### Recommended Remediation

Apply input validation, output encoding, and principle of least privilege to remediate the underlying flaw (CWE-639).

#### Supporting Evidence & References

- **Evidence IDs:** `4a6bc1e8-d71a-4e53-a697-6e9c93cd067f`

---

<a id="finding-8"></a>
### Finding 8: Client-Side Vulnerability: missing_anti_framing_protection on http://api.example.com:8080/v1/users

| Property | Detail |
| :--- | :--- |
| **Severity** | **MEDIUM** |
| **CVSS v3.1 Score** | **5.3** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) |
| **Weakness (CWE)** | **CWE-1321**: Improperly Controlled Modification of Dynamically-Determined Object Attributes |
| **Target Host** | `http://api.example.com:8080` |
| **Vulnerable Endpoint** | `/v1/users` |
| **Vulnerable Parameter** | `X-Frame-Options / frame-ancestors` |
| **Confidence** | 90% (CONFIRMED) |
| **Consolidated Evidence** | 1 occurrence(s) |

#### Summary & Description

Clickjacking / UI Redressing vulnerability detected on http://api.example.com:8080/v1/users. The sensitive page lacks X-Frame-Options and Content-Security-Policy frame-ancestors defenses, allowing external iframe embedding. Parameter: X-Frame-Options / frame-ancestors, Strategy: frame_busting_bypass, CWE: CWE-1021

#### Steps to Reproduce

1. Navigate to the target endpoint `/v1/users` on host `http://api.example.com:8080`.
2. Send a crafted HTTP request to `/v1/users`.
3. Observe the anomalous response behavior confirming prototype pollution.

#### Impact Analysis

Successful exploitation could compromise the confidentiality, integrity, or availability of the application with medium impact.

#### Recommended Remediation

Apply input validation, output encoding, and principle of least privilege to remediate the underlying flaw (CWE-1321).

#### Supporting Evidence & References

- **Evidence IDs:** `0a97d85c-40f4-4f71-8e21-82e0f20bc6c7`

---

<a id="finding-9"></a>
### Finding 9: Discovered Endpoint: http://api.example.com:8080/v1/users

| Property | Detail |
| :--- | :--- |
| **Severity** | **INFO** |
| **CVSS v3.1 Score** | **0.0** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N`) |
| **Weakness (CWE)** | **CWE-699**: Software Development Security Issue |
| **Target Host** | `http://api.example.com:8080` |
| **Vulnerable Endpoint** | `/v1/users` |
| **Confidence** | 100% (UNVERIFIED) |
| **Consolidated Evidence** | 1 occurrence(s) |

#### Summary & Description

Discovered endpoint /v1/users on http://api.example.com:8080

#### Steps to Reproduce

1. Navigate to the target endpoint `/v1/users` on host `http://api.example.com:8080`.
2. Send a crafted HTTP request to `/v1/users`.
3. Observe the anomalous response behavior confirming endpoint.

#### Impact Analysis

Successful exploitation could compromise the confidentiality, integrity, or availability of the application with info impact.

#### Recommended Remediation

Apply input validation, output encoding, and principle of least privilege to remediate the underlying flaw (CWE-699).

#### Supporting Evidence & References

- **Evidence IDs:** `d1b47a5c-9433-4720-86b7-4664141fb50c`

---

<a id="finding-10"></a>
### Finding 10: Discovered Subdomain: api.example.com

| Property | Detail |
| :--- | :--- |
| **Severity** | **INFO** |
| **CVSS v3.1 Score** | **0.0** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N`) |
| **Weakness (CWE)** | **CWE-942**: Permissive Cross-domain Policy with Untrusted Domains |
| **Target Host** | `api.example.com:8080` |
| **Vulnerable Endpoint** | `/` |
| **Confidence** | 100% (UNVERIFIED) |
| **Consolidated Evidence** | 1 occurrence(s) |

#### Summary & Description

Subdomain api.example.com identified for target http://api.example.com:8080/v1/users?id=1

#### Steps to Reproduce

1. Navigate to the target endpoint `/` on host `api.example.com:8080`.
2. Send a crafted HTTP request to `/`.
3. Observe the anomalous response behavior confirming subdomain.

#### Impact Analysis

Successful exploitation could compromise the confidentiality, integrity, or availability of the application with info impact.

#### Recommended Remediation

Apply input validation, output encoding, and principle of least privilege to remediate the underlying flaw (CWE-942).

#### Supporting Evidence & References

- **Evidence IDs:** `caee7baf-e9d6-4b18-9c9b-827b8c4f39c9`

---

<a id="finding-11"></a>
### Finding 11: Live Host: http://api.example.com:8080

| Property | Detail |
| :--- | :--- |
| **Severity** | **INFO** |
| **CVSS v3.1 Score** | **0.0** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N`) |
| **Weakness (CWE)** | **CWE-699**: Software Development Security Issue |
| **Target Host** | `api.example.com` |
| **Vulnerable Endpoint** | `/` |
| **Confidence** | 100% (UNVERIFIED) |
| **Consolidated Evidence** | 1 occurrence(s) |

#### Summary & Description

Live host detected at http://api.example.com:8080 (status: 200)

#### Steps to Reproduce

1. Navigate to the target endpoint `/` on host `api.example.com`.
2. Send a crafted HTTP request to `/`.
3. Observe the anomalous response behavior confirming live host.

#### Impact Analysis

Successful exploitation could compromise the confidentiality, integrity, or availability of the application with info impact.

#### Recommended Remediation

Apply input validation, output encoding, and principle of least privilege to remediate the underlying flaw (CWE-699).

#### Supporting Evidence & References

- **Evidence IDs:** `bcccc6ae-5ffd-4d9d-b7b5-57d3e6ba6198`

---
