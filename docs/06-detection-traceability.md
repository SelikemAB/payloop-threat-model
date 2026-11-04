# Threat to detection traceability

_Generated from `data/threats.yaml` and `detections/payloop_rules.xml`. Do not edit by hand._

**18 of 25** threats have at least one detection. Every referenced custom rule id was verified to exist in the ruleset on each build.

## Threat to rules

| Threat | Risk | Rules (level) | If it fails |
|---|---|---|---|
| TM-07 SQL injection reads or modifies ledger data | Critical | 110120 (L10) | Regex on query strings misses obfuscated payloads and JSON bodies. |
| TM-11 Spending from another customer's wallet | Critical | 110105 (L4), 110141 (L9) | Holds only while every new handler calls the guard; the sandbox attack simulation includes a transfer-from-victim scenario to catch a regression. |
| TM-01 Online password guessing and spraying against /login | High | 110101 (L5), 110111 (L10), 110112 (L12), 110103 (L7), 110113 (L10) | No MFA; low-and-slow or botnet-distributed guessing stays under the thresholds. |
| TM-02 Credential stuffing with breached passwords | High | 110112 (L12) | Throttling does not stop valid credentials. MFA for money movement is the real control. |
| TM-05 Duplicate or replayed payment request | High | 110151 (L8), 110152 (L5) | Key reuse with a different payload is rejected (409) but not alerted. |
| TM-10 Object-level authorisation failure exposes other customers' wallets | High | 110140 (L8), 110141 (L9) | A single guessed id is indistinguishable from normal traffic; prevention is the control. |
| TM-03 Forged session token | High | 110160 (L8), 110161 (L11), 110170 (L6) | A token forged with the real secret is cryptographically valid and invisible to token rules. Only behaviour (110170) remains, so secret handling is the control. |
| TM-04 Transfer amount manipulation (negative, zero, oversized) | High | 110150 (L12), 110153 (L10) | On an unpatched build detection fires after funds moved; reconciliation is the backstop. |
| TM-15 Server-side request forgery through partner webhook tests | High | 110130 (L10), 110131 (L12), 110132 (L14) | Network-layer egress filtering is a documented requirement, not part of the sandbox. |
| TM-18 Admin function reached with a stolen or forged token | High | 110170 (L6) | No step-up authentication or source allow-listing for admin; detection depends on spotting an unusual source. |
| TM-24 Administrator account phished or credentials reused | High | 110170 (L6), 110112 (L12) | Open until MFA and a source allow-list exist; detection relies on noticing an unusual source or time. |
| TM-12 Arbitrary file read through the receipt endpoint | High | 110121 (L10), 110122 (L8) | Double-encoded sequences can evade the request-line rule; the application-level path_blocked event covers them. |
| TM-25 SIEM ingestion fails or is flooded, so attacks go unseen | High | stock:504, stock:506 | No end-to-end canary event proving the log path works; a synthetic heartbeat log line would close this. |
| TM-09 Cannot attribute a money movement to a person and request | Medium | 110106 (L2), 110107 (L0) | Source IP is only as trustworthy as the configured proxy chain. |
| TM-16 Request flooding and expensive-endpoint exhaustion | Medium | 110123 (L4), 110124 (L9) | Volumetric attacks need upstream scrubbing; not in scope. |
| TM-17 Lockout abuse against a victim account | Medium | 110113 (L10) | Accepted trade-off: a 5 minute nuisance lockout in exchange for brute-force resistance. |
| TM-08 Security log tampering or deletion | Medium | stock:550, stock:553 | Between write and shipment there is a short window; tamper-evident chaining is not implemented. |
| TM-13 Internal details leak through error responses | Medium | 110123 (L4), 110124 (L9), 110180 (L7) | None significant. |

## Threats without a detection, and why

| Threat | Risk | Reason |
|---|---|---|
| TM-20 Secrets committed to the repository or printed in CI logs | Critical | Pipeline control (secret scanning gate). Rotation after any leak is mandatory because history keeps the value. |
| TM-06 Concurrent requests cause double spend | High | Preventive control. A nightly ledger-versus-balance reconciliation would detect drift; it is documented as a gap, not built. |
| TM-19 Malicious dependency or compromised CI action | High | Pipeline control. Enforced by the gate in the secure-pipeline repository; no runtime signal exists in the application. |
| TM-14 Offline cracking of stolen password hashes | High | Offline activity produces no events on our side. Detection is upstream: database access monitoring and credential-stuffing rules (TM-02). |
| TM-22 Spoofed or unsigned partner callbacks | High | Open design gap recorded for honesty; no callback receiver exists in the sandbox to instrument. |
| TM-21 Vulnerable or backdoored container image, container escape | Medium | Preventive hardening plus image scanning. Runtime container telemetry is out of scope for the sandbox. |
| TM-23 Traffic interception or downgrade between client and proxy | Medium | Preventive control; the sandbox deliberately omits TLS and this is stated openly. |

## Rule to threats

| Rule | Level | What it detects | Threats |
|---|---|---|---|
| 110101 | 5 | failed login for $(username) from $(srcip). | TM-01 |
| 110103 | 7 | login throttled for $(username) from $(srcip). | TM-01 |
| 110105 | 4 | authorisation denied for $(user) on $(resource). | TM-11 |
| 110106 | 2 | transfer of $(amount) from wallet $(from_wallet) by $(user). | TM-09 |
| 110107 | 0 | HTTP request log line. | TM-09 |
| 110111 | 10 | possible brute force or password spraying, 8+ failed logins in 60s from $(srcip). | TM-01 |
| 110112 | 12 | successful login after repeated failures from $(srcip), possible credential compromise. | TM-01, TM-02, TM-24 |
| 110113 | 10 | sustained login attempts despite throttling from $(srcip). | TM-01, TM-17 |
| 110120 | 10 | SQL injection pattern in request to $(path) from $(srcip). | TM-07 |
| 110121 | 10 | path traversal pattern in request to $(path) from $(srcip). | TM-12 |
| 110122 | 8 | file access blocked by validation ($(file)) from $(srcip). | TM-12 |
| 110123 | 4 | HTTP $(status) returned for $(path) to $(srcip). | TM-13, TM-16 |
| 110124 | 9 | repeated server errors triggered by $(srcip), possible fuzzing or exploitation. | TM-13, TM-16 |
| 110130 | 10 | outbound request to $(target_host) blocked ($(reason)) for $(user). | TM-15 |
| 110131 | 12 | server fetched an internal address ($(target_host)) on behalf of $(user), SSRF succeeded. | TM-15 |
| 110132 | 14 | server fetched the cloud instance metadata endpoint on behalf of $(user). | TM-15 |
| 110140 | 8 | $(user) viewed 5+ different wallets in 60s, possible object-ID enumeration (IDOR). | TM-10 |
| 110141 | 9 | repeated authorisation failures by $(user), possible access-control probing. | TM-10, TM-11 |
| 110150 | 12 | transfer ACCEPTED with zero or negative amount ($(amount)) by $(user), balance manipulation. | TM-04 |
| 110151 | 8 | two transfers accepted with the same idempotency key ($(idem_key)), duplicate payment. | TM-05 |
| 110152 | 5 | duplicate transfer submission absorbed by idempotency key $(idem_key). | TM-05 |
| 110153 | 10 | transfer REJECTED with zero or negative amount ($(amount)) by $(user), manipulation attempt. | TM-04 |
| 110160 | 8 | invalid session token presented ($(reason)) from $(srcip). | TM-03 |
| 110161 | 11 | repeated forged or invalid tokens from $(srcip). | TM-03 |
| 110170 | 6 | admin function $(resource) accessed by $(user) from $(srcip). | TM-03, TM-18, TM-24 |
| 110180 | 7 | unhandled application error $(type) at $(where). | TM-13 |

Rules not tied to a threat (3): 110100, 110102, 110104. These are infrastructure rules (event parents or informational), kept below level 5.
