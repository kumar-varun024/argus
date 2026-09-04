# Vulnerability Assessment Report — http://api.example.com:8080/v1/users?id=1

> **Mission ID:** `0ab2fe71-342b-44c1-9c97-2e7593d03c57`  
> **Generated At:** `2026-09-03T10:00:33.615631+00:00`  
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

- **Evidence IDs:** `49d0533a-b346-4fb9-a2ae-cdee238344a3`

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

- **Evidence IDs:** `24a2e581-1c06-4789-ae6f-d666e30fef96`

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

- **Evidence IDs:** `a39a1942-b770-4db9-9d40-d4b7f0057d61`

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

- **Evidence IDs:** `ac1af297-5846-414a-8524-74674315133b`

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

- **Evidence IDs:** `13b9bfb5-a556-4f17-9c46-821635bcd7bd`

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

- **Evidence IDs:** `f974b705-a634-42be-8b01-23ba379fc20c`

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

- **Evidence IDs:** `5cd3c608-6a66-4983-8414-9993bcf7e6de`

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

- **Evidence IDs:** `59d2018f-ea00-44c4-ae2a-9e6defeb9965`

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

- **Evidence IDs:** `2e609d3a-d2e1-4446-9d52-82be74b2f949`

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

- **Evidence IDs:** `b9c9dcdd-3809-4600-b7a3-008722420c24`

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

- **Evidence IDs:** `049ee480-853e-4046-814c-01b827304321`

---
