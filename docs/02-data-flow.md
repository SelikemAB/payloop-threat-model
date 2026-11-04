# 2. Data flow diagrams and attack tree

## Level 1 data-flow diagram

```mermaid
flowchart LR
  subgraph TB1["TB1 Internet (untrusted)"]
    E1(["E1 Customer client"])
    E2(["E2 Partner system"])
    E3(["E3 Ops administrator"])
  end
  subgraph TB2["TB2 DMZ"]
    P1["P1 Reverse proxy + TLS"]
  end
  subgraph TB3["TB3 Application and data"]
    P2["P2 PayLoop API"]
    D1[("D1 Wallet database")]
    D2[("D2 Receipt store")]
    D3[("D3 Security log")]
    X1["X1 SIEM (Wazuh)"]
  end
  subgraph TB4["TB4 Partner egress"]
    P3["P3 Webhook dispatcher"]
  end
  subgraph TB5["TB5 Build"]
    P4["P4 CI/CD + image build"]
  end
  E1 -- "F1 HTTPS requests" --> P1
  E3 -- "F2 admin requests" --> P1
  E2 -- "F3 callbacks" --> P1
  P1 -- "F4 proxied, X-Forwarded-For" --> P2
  P2 -- "F5 SQL" --> D1
  P2 -- "F6 file read" --> D2
  P2 -- "F7 JSON log lines" --> D3
  D3 -- "F8 agent ships logs" --> X1
  P2 -- "F9 webhook test" --> P3
  P3 -- "F10 outbound HTTP" --> E2
  P4 -- "F11 image + config" --> P2
```

### Flows
| Flow | From | To | Data | Protocol | Crosses |
|---|---|---|---|---|---|
| F1 | E1 | P1 | credentials, transfer requests | HTTPS | TB1 to TB2 |
| F2 | E3 | P1 | admin actions | HTTPS | TB1 to TB2 |
| F3 | E2 | P1 | partner callbacks | HTTPS | TB1 to TB2 |
| F4 | P1 | P2 | proxied requests | HTTP | TB2 to TB3 |
| F5 | P2 | D1 | SQL, balances, hashes | local socket / file | inside TB3 |
| F6 | P2 | D2 | receipt files | filesystem | inside TB3 |
| F7 | P2 | D3 | security events (never bodies or secrets) | file append | inside TB3 |
| F8 | D3 | X1 | log lines | agent over TLS | inside TB3 |
| F9 | P2 | P3 | URL to test | in process | TB3 to TB4 |
| F10 | P3 | E2 | webhook request | HTTPS | TB4 to TB1 |
| F11 | P4 | P2 | images, configuration | registry / deploy | TB5 to TB3 |

## Attack tree: steal funds from a customer wallet

Leaves carry the threat id (TM-nn) and the detection that would see it.

```mermaid
flowchart TD
  G["GOAL: move money out of a victim wallet"]
  G --> A["Take over the victim's identity"]
  G --> B["Abuse transfer logic"]
  G --> C["Abuse access control"]
  G --> D["Compromise a privileged path"]
  A --> A1["Guess or spray passwords<br/>TM-01 | 110111, 110113"]
  A --> A2["Credential stuffing<br/>TM-02 | 110112"]
  A --> A3["Read hashes via SQLi, crack offline<br/>TM-07 + TM-14 | 110120"]
  A --> A4["Forge a session token<br/>TM-03 | 110160, 110170"]
  B --> B1["Negative or oversized amount<br/>TM-04 | 110150, 110153"]
  B --> B2["Replay the same request<br/>TM-05 | 110151, 110152"]
  B --> B3["Race two requests<br/>TM-06 | none, reconcile"]
  C --> C1["Set from_wallet to the victim<br/>TM-11 | 110105, 110141"]
  C --> C2["Enumerate wallets by id<br/>TM-10 | 110140"]
  D --> D1["Phish or reuse an admin login<br/>TM-24 | 110170"]
  D --> D2["Poison the pipeline or an image<br/>TM-19, TM-21 | gate, none at runtime"]
  D --> D3["SSRF to metadata, steal cloud credentials<br/>TM-15 | 110130-110132"]
```

Reading the tree: the branches where the detection column says "none" are exactly the ones that need preventive controls or
reconciliation, which is why the traceability report lists them with the reason.
