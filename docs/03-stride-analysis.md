# STRIDE analysis

_Generated from `data/threats.yaml`. Do not edit by hand._

STRIDE: **S** Spoofing, **T** Tampering, **R** Repudiation, **I** Information disclosure, **D** Denial of service, **E** Elevation of privilege

## Coverage matrix (threat count per element and category)

| Element | S | T | R | I | D | E |
|---|---|---|---|---|---|---|
| E1 Customer client (mobile app / USSD gateway) | 1 | · | · | · | · | · |
| E2 Partner system (merchant / aggregator) | 1 | · | · | · | · | · |
| E3 Ops administrator | 1 | · | · | · | · | · |
| P1 Reverse proxy and TLS termination | · | 1 | · | · | 1 | · |
| P2 PayLoop API (PHP) | 2 | 3 | 1 | 2 | 1 | 2 |
| P3 Webhook dispatcher (outbound) | · | · | · | 1 | · | · |
| P4 CI/CD pipeline and image build | · | 2 | · | · | · | 1 |
| D1 Wallet database (users | · | 1 | · | 1 | · | · |
| D2 Receipt file store | · | · | · | 1 | · | · |
| D3 Security log (JSON lines) | · | · | 1 | · | · | · |
| X1 SIEM (Wazuh) | · | · | · | · | 1 | · |

A dot means no threat was identified for that category on that element. For externals and stores some categories do not apply under classic STRIDE-per-element rules; the matrix is a prompt to ask, not a quota.

## E1: Customer client (mobile app / USSD gateway)

Type: external  |  Trust boundary: TB1

| Threat | STRIDE | Scenario | Risk | Status | Detections |
|---|---|---|---|---|---|
| TM-02 Credential stuffing with breached passwords | S | Valid username and password pairs from other breaches are replayed; each attempt looks like a normal login. | High (16) | open | 110112 |

## E2: Partner system (merchant / aggregator)

Type: external  |  Trust boundary: TB1

| Threat | STRIDE | Scenario | Risk | Status | Detections |
|---|---|---|---|---|---|
| TM-22 Spoofed or unsigned partner callbacks | S | An attacker posts forged callbacks pretending to be a trusted partner. | High (12) | open | none |

## E3: Ops administrator

Type: external  |  Trust boundary: TB1

| Threat | STRIDE | Scenario | Risk | Status | Detections |
|---|---|---|---|---|---|
| TM-24 Administrator account phished or credentials reused | S | An attacker obtains an operator's password or session and uses the admin console as that person. | High (15) | open | 110170, 110112 |

## P1: Reverse proxy and TLS termination

Type: process  |  Trust boundary: TB2

| Threat | STRIDE | Scenario | Risk | Status | Detections |
|---|---|---|---|---|---|
| TM-16 Request flooding and expensive-endpoint exhaustion | D | High request volume, or repeated login attempts that each cost a memory-hard hash, exhaust the service. | Medium (9) | partial | 110123, 110124 |
| TM-23 Traffic interception or downgrade between client and proxy | T | An on-path attacker reads or alters traffic if TLS is missing, weak or strippable. | Medium (8) | partial | none |

## P2: PayLoop API (PHP)

Type: process  |  Trust boundary: TB3

| Threat | STRIDE | Scenario | Risk | Status | Detections |
|---|---|---|---|---|---|
| TM-01 Online password guessing and spraying against /login | S | An attacker sends many passwords for one account, or one password across many accounts, from one or many addresses. | High (16) | partial | 110101, 110111, 110112, 110103, 110113 |
| TM-03 Forged session token | S | An attacker who learns the HMAC signing secret mints a valid admin token. | High (15) | mitigated | 110160, 110161, 110170 |
| TM-04 Transfer amount manipulation (negative, zero, oversized) | T | A customer submits a negative amount to reverse the direction of a transfer, or an amount larger than their balance. | High (15) | mitigated | 110150, 110153 |
| TM-05 Duplicate or replayed payment request | T | A network retry or a malicious replay submits the same transfer twice and it is paid twice. | High (16) | mitigated | 110151, 110152 |
| TM-06 Concurrent requests cause double spend | T | Two simultaneous transfers both pass the balance check before either debit is applied. | High (15) | mitigated | none |
| TM-09 Cannot attribute a money movement to a person and request | R | After a disputed transfer the operator cannot show who initiated it, from where, or which request. | Medium (9) | mitigated | 110106, 110107 |
| TM-10 Object-level authorisation failure exposes other customers' wallets | I | A logged-in customer changes an id in the URL and reads another customer's balance and identity. | High (16) | mitigated | 110140, 110141 |
| TM-11 Spending from another customer's wallet | E | A customer sets from_wallet to a wallet they do not own in a transfer request. | Critical (20) | mitigated | 110105, 110141 |
| TM-13 Internal details leak through error responses | I | Unhandled exceptions return stack traces and file paths that help an attacker refine other attacks. | Medium (6) | mitigated | 110123, 110124, 110180 |
| TM-17 Lockout abuse against a victim account | D | An attacker deliberately fails logins for a victim's username to lock them out. | Medium (9) | accepted | 110113 |
| TM-18 Admin function reached with a stolen or forged token | E | An attacker presents an admin token to list all users and other privileged data. | High (15) | partial | 110170 |

## P3: Webhook dispatcher (outbound)

Type: process  |  Trust boundary: TB4

| Threat | STRIDE | Scenario | Risk | Status | Detections |
|---|---|---|---|---|---|
| TM-15 Server-side request forgery through partner webhook tests | I | A caller supplies an internal or metadata URL and the server fetches it on their behalf. | High (15) | partial | 110130, 110131, 110132 |

## P4: CI/CD pipeline and image build

Type: process  |  Trust boundary: TB5

| Threat | STRIDE | Scenario | Risk | Status | Detections |
|---|---|---|---|---|---|
| TM-19 Malicious dependency or compromised CI action | E | A tampered package or third-party GitHub Action runs in the pipeline with access to secrets and the build output. | High (15) | partial | none |
| TM-20 Secrets committed to the repository or printed in CI logs | T | A signing key, password or token enters git history or a build log and is harvested. | Critical (20) | mitigated | none |
| TM-21 Vulnerable or backdoored container image, container escape | T | A bad base image or an over-privileged container gives an attacker code execution and a path to the host. | Medium (10) | partial | none |

## D1: Wallet database (users

Type: store  |  Trust boundary: TB3

| Threat | STRIDE | Scenario | Risk | Status | Detections |
|---|---|---|---|---|---|
| TM-07 SQL injection reads or modifies ledger data | T | Untrusted input reaches a SQL string, letting an attacker read other tables or alter balances. | Critical (20) | mitigated | 110120 |
| TM-14 Offline cracking of stolen password hashes | I | After any database read the attacker cracks the stored hashes on their own hardware. | High (12) | mitigated | none |

## D2: Receipt file store

Type: store  |  Trust boundary: TB3

| Threat | STRIDE | Scenario | Risk | Status | Detections |
|---|---|---|---|---|---|
| TM-12 Arbitrary file read through the receipt endpoint | I | Path traversal sequences in the file parameter read files outside the receipts directory. | High (12) | mitigated | 110121, 110122 |

## D3: Security log (JSON lines)

Type: store  |  Trust boundary: TB3

| Threat | STRIDE | Scenario | Risk | Status | Detections |
|---|---|---|---|---|---|
| TM-08 Security log tampering or deletion | R | An attacker with host access edits or removes log lines to hide activity. | Medium (8) | partial | stock:550, stock:553 |

## X1: SIEM (Wazuh)

Type: process  |  Trust boundary: TB3

| Threat | STRIDE | Scenario | Risk | Status | Detections |
|---|---|---|---|---|---|
| TM-25 SIEM ingestion fails or is flooded, so attacks go unseen | D | The agent stops, the log path is misconfigured, or a flood of noise hides real alerts. | High (12) | partial | stock:504, stock:506 |
