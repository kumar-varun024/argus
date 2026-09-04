# Vulnerability Assessment Report — http://api.example.com:8080/v1/users?id=1

> **Mission ID:** `7c0139db-f5c7-418f-a073-0a7470c930e0`  
> **Generated At:** `2026-09-03T20:32:43.928364+00:00`  
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

- **Evidence IDs:** `51777f48-a210-47ed-a3d4-131ec243d643`

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

- **Evidence IDs:** `1d80a47f-29bd-47fb-b137-bc436dee4bd7`

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

- **Evidence IDs:** `52882d2a-6b30-422c-80bd-15579fffdc1f`

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

- **Evidence IDs:** `ec347e72-a17c-4000-8c3a-d5fa4092528a`

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

- **Evidence IDs:** `788a6b81-29b5-430e-a1be-73f3cd38bfc4`

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

- **Evidence IDs:** `a2fd3550-30d4-463f-be0f-5fd25d89adab`

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

- **Evidence IDs:** `37d5de68-50d7-4db8-9aa8-bf55e7546cc8`

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

- **Evidence IDs:** `367611ef-e41f-4b92-a7b6-88e18193e60c`

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

- **Evidence IDs:** `2eb0582c-726c-4ed0-97d8-d16d604bda55`

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

- **Evidence IDs:** `4de2a60b-e763-40bd-8d28-bc7584b97595`

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

- **Evidence IDs:** `aafeb5dd-74a8-47d6-ac78-02354beb89db`

---
