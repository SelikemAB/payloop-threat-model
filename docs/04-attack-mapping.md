# MITRE ATT&CK mapping

_Generated from `data/threats.yaml`. Do not edit by hand._

Mapped against ATT&CK Enterprise v18. Import `attack-navigator-layer.json` into ATT&CK Navigator to see the heat map.

| Technique | Name | Threats | Highest risk | Detection rules |
|---|---|---|---|---|
| T1005 | Data from Local System | TM-12 | High | 110121, 110122 |
| T1070 | Indicator Removal | TM-08 | Medium | stock:550, stock:553 |
| T1078 | Valid Accounts | TM-18, TM-24 | High | 110112, 110170 |
| T1110 | Brute Force | TM-01 | High | 110101, 110103, 110111, 110112, 110113 |
| T1110.002 | Password Cracking | TM-14 | High | none |
| T1110.004 | Credential Stuffing | TM-02 | High | 110112 |
| T1190 | Exploit Public-Facing Application | TM-07, TM-13, TM-15 | Critical | 110120, 110123, 110124, 110130, 110131, 110132, 110180 |
| T1195.001 | Compromise Software Dependencies and Development Tools | TM-19 | High | none |
| T1199 | Trusted Relationship | TM-22 | High | none |
| T1213 | Data from Information Repositories | TM-10 | High | 110140, 110141 |
| T1499 | Endpoint Denial of Service | TM-16 | Medium | 110123, 110124 |
| T1525 | Implant Internal Image | TM-21 | Medium | none |
| T1531 | Account Access Removal | TM-17 | Medium | 110113 |
| T1552.001 | Credentials In Files | TM-03, TM-20 | Critical | 110160, 110161, 110170 |
| T1552.005 | Cloud Instance Metadata API | TM-15 | High | 110130, 110131, 110132 |
| T1557 | Adversary-in-the-Middle | TM-23 | Medium | none |
| T1562.006 | Indicator Blocking | TM-25 | High | stock:504, stock:506 |
| T1606 | Forge Web Credentials | TM-03 | High | 110160, 110161, 110170 |
| T1611 | Escape to Host | TM-21 | Medium | none |
| T1657 | Financial Theft | TM-04, TM-05, TM-06, TM-11 | Critical | 110105, 110141, 110150, 110151, 110152, 110153 |

Threats with no ATT&CK technique (design or accountability gaps rather than adversary behaviour): TM-09.
