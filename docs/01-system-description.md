# 1. System description and scope

PayLoop is a **fictional** mobile-money wallet platform used to practise threat modelling. It mirrors the shape of real payments and
telecom systems (customer channel, partner integrations, admin console, outbound webhooks, CI/CD) without being any real system.

## Security objectives
1. **Funds integrity.** Money moves only when the owner authorises it, exactly once, in the amount stated.
2. **Account integrity.** Only the genuine customer or an authorised operator can act as that identity.
3. **Confidentiality** of balances, identities, credentials and the token-signing secret.
4. **Accountability.** Every money movement and privileged action is attributable to a person, a source and a request.
5. **Availability** of the payment path during normal and hostile load.
6. **Detectability.** Attacks against 1 to 5 leave evidence the SOC can act on.

## Assets
| ID | Asset | Why it matters |
|---|---|---|
| A1 | Customer funds (wallet balances, transfer ledger) | Direct financial loss |
| A2 | Credentials and sessions (password hashes, tokens, signing secret) | Gateway to every other asset |
| A3 | Customer identity and PII | Privacy and regulatory exposure |
| A4 | Security log and audit trail | Evidence; target for anti-forensics |
| A5 | Partner trust (callbacks, webhook endpoints) | Business continuity and fraud surface |
| A6 | Build pipeline and images | A compromise ships to production |

## Actors
- **Customer:** authenticated, may be malicious toward other customers.
- **Partner:** semi-trusted third party that registers webhook URLs and sends callbacks.
- **Operator:** privileged staff using the admin console.
- **External attacker:** unauthenticated, internet-facing.
- **Malicious or compromised insider:** valid access abused, or a stolen laptop or session.
- **Supply-chain attacker:** tampers with a dependency, action or base image.

## Trust boundaries
| ID | Boundary | Crossing |
|---|---|---|
| TB1 | Internet / DMZ | Every inbound request, untrusted |
| TB2 | DMZ / application network | Proxy to API |
| TB3 | Application / data | API to database, file store, log, SIEM |
| TB4 | Application / partner egress | Outbound webhook requests |
| TB5 | Build / run | Images and configuration promoted to production |

## Assumptions
- TLS is terminated at the proxy in production; the sandbox uses plain HTTP on localhost and says so.
- The proxy overwrites `X-Forwarded-For`; the application trusts it only from the configured proxy address.
- The database account used by the API is least-privilege (no DDL) in production.
- Secrets are injected by the orchestrator or a secret manager, never baked into images or committed.

## Out of scope (stated so reviewers do not assume otherwise)
Volumetric DDoS, physical security, mobile-app client hardening, USSD carrier-network protocols, regulatory mapping, and the
internals of the partner systems. These are real concerns; they are excluded to keep the model reviewable.

## How this model is used
Every threat in `data/threats.yaml` is traced to controls, to Wazuh detections, and where applicable to a concrete finding that was
found and fixed in the companion **payloop-vuln-lab** repository. The companion **payloop-secure-sandbox** repository runs
attack scenarios against the hardened build and shows the detections firing.
