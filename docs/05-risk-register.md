# Risk register

_Generated from `data/threats.yaml`. Do not edit by hand._

Score = likelihood x impact (1-5 each). Bands: Critical >= 20, High >= 12, Medium >= 6, otherwise Low.

| Threat | Title | L | I | Score | Band | Status | Residual risk |
|---|---|---|---|---|---|---|---|
| TM-07 | SQL injection reads or modifies ledger data | 4 | 5 | 20 | Critical | mitigated | Regex on query strings misses obfuscated payloads and JSON bodies. |
| TM-11 | Spending from another customer's wallet | 4 | 5 | 20 | Critical | mitigated | Holds only while every new handler calls the guard; the sandbox attack simulation includes a transfer-from-victim scenario to catch a regression. |
| TM-20 | Secrets committed to the repository or printed in CI logs | 4 | 5 | 20 | Critical | mitigated | Scanners miss novel formats; keep patterns tuned. |
| TM-01 | Online password guessing and spraying against /login | 4 | 4 | 16 | High | partial | No MFA; low-and-slow or botnet-distributed guessing stays under the thresholds. |
| TM-02 | Credential stuffing with breached passwords | 4 | 4 | 16 | High | open | Throttling does not stop valid credentials. MFA for money movement is the real control. |
| TM-05 | Duplicate or replayed payment request | 4 | 4 | 16 | High | mitigated | Key reuse with a different payload is rejected (409) but not alerted. |
| TM-10 | Object-level authorisation failure exposes other customers' wallets | 4 | 4 | 16 | High | mitigated | A single guessed id is indistinguishable from normal traffic; prevention is the control. |
| TM-03 | Forged session token | 3 | 5 | 15 | High | mitigated | A token forged with the real secret is cryptographically valid and invisible to token rules. Only behaviour (110170) remains, so secret handling is the control. |
| TM-04 | Transfer amount manipulation (negative, zero, oversized) | 3 | 5 | 15 | High | mitigated | On an unpatched build detection fires after funds moved; reconciliation is the backstop. |
| TM-06 | Concurrent requests cause double spend | 3 | 5 | 15 | High | mitigated | Single-node SQLite only; a multi-node database needs row-level locking or serialisable isolation. |
| TM-15 | Server-side request forgery through partner webhook tests | 3 | 5 | 15 | High | partial | Network-layer egress filtering is a documented requirement, not part of the sandbox. |
| TM-18 | Admin function reached with a stolen or forged token | 3 | 5 | 15 | High | partial | No step-up authentication or source allow-listing for admin; detection depends on spotting an unusual source. |
| TM-19 | Malicious dependency or compromised CI action | 3 | 5 | 15 | High | partial | Pinning and review have to be maintained; a compromised maintainer of a pinned version is out of scope. |
| TM-24 | Administrator account phished or credentials reused | 3 | 5 | 15 | High | open | Open until MFA and a source allow-list exist; detection relies on noticing an unusual source or time. |
| TM-12 | Arbitrary file read through the receipt endpoint | 3 | 4 | 12 | High | mitigated | Double-encoded sequences can evade the request-line rule; the application-level path_blocked event covers them. |
| TM-14 | Offline cracking of stolen password hashes | 3 | 4 | 12 | High | mitigated | Existing hashes need a rehash-on-login migration; until done the legacy tail is weak. |
| TM-22 | Spoofed or unsigned partner callbacks | 3 | 4 | 12 | High | open | Open until a signed-callback receiver is built. |
| TM-25 | SIEM ingestion fails or is flooded, so attacks go unseen | 3 | 4 | 12 | High | partial | No end-to-end canary event proving the log path works; a synthetic heartbeat log line would close this. |
| TM-21 | Vulnerable or backdoored container image, container escape | 2 | 5 | 10 | Medium | partial | No runtime syscall monitoring. |
| TM-09 | Cannot attribute a money movement to a person and request | 3 | 3 | 9 | Medium | mitigated | Source IP is only as trustworthy as the configured proxy chain. |
| TM-16 | Request flooding and expensive-endpoint exhaustion | 3 | 3 | 9 | Medium | partial | Volumetric attacks need upstream scrubbing; not in scope. |
| TM-17 | Lockout abuse against a victim account | 3 | 3 | 9 | Medium | accepted | Accepted trade-off: a 5 minute nuisance lockout in exchange for brute-force resistance. |
| TM-08 | Security log tampering or deletion | 2 | 4 | 8 | Medium | partial | Between write and shipment there is a short window; tamper-evident chaining is not implemented. |
| TM-23 | Traffic interception or downgrade between client and proxy | 2 | 4 | 8 | Medium | partial | Production deployment must add TLS; not demonstrated here. |
| TM-13 | Internal details leak through error responses | 3 | 2 | 6 | Medium | mitigated | None significant. |

## Heat map (inherent risk, threat numbers)

| Impact \ Likelihood | 1 | 2 | 3 | 4 | 5 |
|---|---|---|---|---|---|
| **5** | · | 21 | 03, 04, 06, 15, 18, 19, 24 | 07, 11, 20 | · |
| **4** | · | 08, 23 | 12, 14, 22, 25 | 01, 02, 05, 10 | · |
| **3** | · | · | 09, 16, 17 | · | · |
| **2** | · | · | 13 | · | · |
| **1** | · | · | · | · | · |

## Status summary

- **accepted** (1): TM-17
- **mitigated** (12): TM-03, TM-04, TM-05, TM-06, TM-07, TM-09, TM-10, TM-11, TM-12, TM-13, TM-14, TM-20
- **open** (3): TM-02, TM-22, TM-24
- **partial** (9): TM-01, TM-08, TM-15, TM-16, TM-18, TM-19, TM-21, TM-23, TM-25

Scores are inherent (before the listed controls). Residual risk is described in words rather than re-scored, because re-scoring without evidence invites optimism.
