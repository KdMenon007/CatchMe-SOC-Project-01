# Project 03 — SSH Authorized-Key Backdoor Threat Hunt

**CatchMe | Linux Security Operations Center (SOC) Portfolio**

A defensive lab case study investigating SSH authentication, post-access discovery, SSH authorized-key persistence, and possible public-key re-entry using Linux audit telemetry and Elastic SIEM.

![Project](https://img.shields.io/badge/Project-03-blue)
![Platform](https://img.shields.io/badge/Platform-Linux-informational)
![SIEM](https://img.shields.io/badge/SIEM-Elastic-005571)
![ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-T1098.004-red)

> **Rendering note:** This README includes GitHub-compatible Mermaid diagrams. Because rendering has previously failed in the target repository, key workflows also have plain-text fallbacks. If Mermaid fails, the surrounding content remains readable.

---

## Contents

1. [Project Overview](#1-project-overview)
2. [Project Objectives](#2-project-objectives)
3. [Lab Environment and Fixed IP Mapping](#3-lab-environment-and-fixed-ip-mapping)
4. [Scope, Authorization and Safety](#4-scope-authorization-and-safety)
5. [Threat Scenario](#5-threat-scenario)
6. [Threat-Hunting Hypothesis](#6-threat-hunting-hypothesis)
7. [Initial Triage Model](#7-initial-triage-model)
8. [Expected Attack Chain](#8-expected-attack-chain)
9. [Expected Telemetry and Log Sources](#9-expected-telemetry-and-log-sources)
10. [Threat-Hunting Methodology](#10-threat-hunting-methodology)
11. [KQL Investigation Strategy](#11-kql-investigation-strategy)
12. [Detection Strategy](#12-detection-strategy)
13. [Sigma and YARA Strategy](#13-sigma-and-yara-strategy)
14. [Investigation Strategy and Findings](#14-investigation-strategy-and-findings)
15. [MITRE ATT&CK Mapping](#15-mitre-attck-mapping)
16. [Cyber Kill Chain Mapping](#16-cyber-kill-chain-mapping)
17. [Incident Response Strategy](#17-incident-response-strategy)
18. [Evidence and Screenshot Strategy](#18-evidence-and-screenshot-strategy)
19. [Diagrams and Attack Timeline](#19-diagrams-and-attack-timeline)
20. [Success Criteria, Validation and Project Status](#20-success-criteria-validation-and-project-status)

---

## 1. Project Overview

This project investigates a Linux SSH persistence scenario in which an account is accessed over SSH, host and account discovery follows, a public key is added to the account's `authorized_keys` file, and a later SSH connection may use that key to re-enter the host.

The case study follows a defensive SOC workflow: establish a hypothesis, define expected telemetry, hunt and correlate events, assess detection logic, map behavior to ATT&CK, and document response and recovery.

**Evidence standard:** a planned action, historical note, screenshot filename, or expected event is not by itself proof of a finding. Specific conclusions must be tied to reviewed evidence. Historical details are labelled where underlying raw events have not been independently reconciled in this repository.

## 2. Project Objectives

- Investigate SSH authentication activity from the designated lab attacker.
- Correlate initial access with post-login discovery.
- Investigate changes to a Linux account's SSH `authorized_keys` file.
- Correlate file activity with later SSH public-key authentication.
- Use auditd and Elastic Defend telemetry where available.
- Validate KQL hunting and detection logic against the intended data view and time range.
- Document investigation, evidence, containment, eradication, recovery, and validation.
- Publish a sanitized, reproducible case study without exposing passwords or SSH private-key material.

## 3. Lab Environment and Fixed IP Mapping

### Fixed lab map

| Role | Hostname | IPv4 address |
|---|---|---|
| Kali attacker | `kiran` | `192.168.1.10` |
| Linux endpoint | `soc-linux` | `192.168.1.16` |
| Elastic SIEM | `elastic-siem` | `192.168.1.11` |
| Default gateway | — | `192.168.1.1` |
| Lab subnet | — | `192.168.1.0/24` |

**Addressing constraint:** use `192.168.1.10` as the Kali lab address. Do not substitute the Kali Wi-Fi address `192.168.1.9` in this project's attack narrative or source-IP queries. Lab boot order is Elastic SIEM, Linux endpoint, then Kali.

### Telemetry architecture

```mermaid
flowchart LR
    A["Kali attacker<br/>kiran<br/>192.168.1.10"]
    B["Linux endpoint<br/>soc-linux<br/>192.168.1.16"]
    C["Native auditd<br/>/var/log/audit/audit.log"]
    D["Elastic Agent<br/>auditd logfile + Defend"]
    E["Elastic SIEM<br/>elastic-siem<br/>192.168.1.11"]
    F["SOC analyst<br/>Discover / KQL / alerts"]
    A -->|"SSH activity"| B
    B --> C
    B --> D
    C --> D
    D -->|"Audit and endpoint events"| E
    E --> F
```

**Text fallback**

```text
Kali (192.168.1.10) --SSH--> soc-linux (192.168.1.16)
                                  |              |
                               auditd       Elastic Defend
                                  \              /
                                   Elastic Agent
                                         |
                                         v
                              elastic-siem (192.168.1.11)
                                         |
                                         v
                               SOC analyst / Kibana
```

## 4. Scope, Authorization and Safety

This is a controlled defensive lab and portfolio exercise. Run tests only on systems owned by the operator or explicitly authorized for testing.

- Keep activity within the documented lab and fixed hosts.
- Never publish passwords, private keys, tokens, or unredacted authentication material.
- Review screenshots and exports for sensitive data before committing or uploading.
- Preserve relevant evidence before containment or cleanup.
- Do not claim an action succeeded unless reviewed evidence supports the result.
- The example queries are for defensive investigation and do not authorize activity against third-party systems.

## 5. Threat Scenario

The scenario models an actor who obtains access to a Linux account and attempts to preserve access by adding an SSH public key to that account's `authorized_keys` file. A later successful public-key login may connect the persistence action to re-entry.

```mermaid
flowchart TD
    A["SSH password attempts"] --> B["Initial SSH access"]
    B --> C["Post-login discovery"]
    C --> D["Modify authorized_keys"]
    D --> E["Public-key re-entry"]
    E --> F["SOC correlation and investigation"]
    F --> G["Containment, eradication, recovery"]
    style D fill:#fce8e6,stroke:#b3261e,color:#202124
    style E fill:#fce8e6,stroke:#b3261e,color:#202124
```

**Text fallback:** SSH attempts → initial access → discovery → authorized-key modification → possible public-key re-entry → SOC investigation → response and recovery.

The sequence is a scenario model. Mark a stage as observed only when supporting evidence has been reviewed.

## 6. Threat-Hunting Hypothesis

**Hypothesis:** if a Linux account's `authorized_keys` file is modified to establish persistence, auditd and/or endpoint file telemetry may record the operation. A subsequent SSH public-key authentication from a related source and account, within a relevant time window, may support a persistence hypothesis.

### Questions to answer

1. Were authentication failures observed before a successful SSH session?
2. What source IP, target account, and authentication method are recorded?
3. Is there evidence of a change to `/home/socadmin/.ssh/authorized_keys`?
4. Which actor, process, syscall, file path, and timestamp appear in the raw event?
5. Does a later public-key login correlate by host, account, source, and time?
6. Is there related process, sudo, or discovery activity?
7. Are there benign explanations, missing telemetry, or field-mapping limitations?

A query returning no results is not proof of absence. Check the time picker, selected data view, field availability, raw event JSON, and neighboring event types.

## 7. Initial Triage Model

1. Confirm the target host and time range.
2. Search SSH activity from `192.168.1.10`.
3. Separate failed authentication, successful authentication, and session lifecycle events.
4. Search auditd `PATH` and `SYSCALL` records for the authorized-key path.
5. Inspect raw events and correlate record identifiers or timestamps where available.
6. Search for a later successful public-key login.
7. Review endpoint process, file, network, and sudo activity.
8. Record query, time window, result count, evidence reference, confidence, and gaps.

```mermaid
flowchart TD
    A["Scope host and time"] --> B["Search SSH activity"]
    B --> C["Separate failures and success"]
    C --> D["Inspect authorized_keys events"]
    D --> E["Correlate public-key re-entry"]
    E --> F["Review process and sudo context"]
    F --> G["Record evidence and gaps"]
```

**Text fallback:** Scope → Search SSH → Separate failure/success → Inspect authorized-key events → Correlate re-entry → Review process/sudo → Document evidence and gaps.

## 8. Expected Attack Chain

| Stage | Behavior to investigate | Evidence to seek |
|---|---|---|
| Authentication attempts | SSH password attempts | Authentication failure events and source IP |
| Initial access | Successful SSH login | Authentication success and session opening |
| Discovery | User, host, process, network, or session enumeration | Endpoint process/audit events or captured session evidence |
| Persistence | Add or modify authorized SSH key | Auditd path/syscall records and/or endpoint file events |
| Re-entry | Authenticate using public key | Successful SSH authentication with method `publickey` |
| Post-re-entry activity | Commands or privilege use | Process, auditd, sudo, and session events |
| Response | Remove unauthorized persistence and validate | Before/after evidence, file metadata, and telemetry checks |

The table lists evidence to seek; it does not imply every item has been independently verified.

## 9. Expected Telemetry and Log Sources

| Source | Investigation value | Caveat |
|---|---|---|
| OpenSSH / Linux authentication logs | Source, user, authentication result, method, and session lifecycle where parsed | Exact fields depend on event type and integration |
| auditd | Syscall and path records for audited operations | One file operation may produce multiple related audit records |
| Elastic Defend process events | Process execution and command context | Normalized field availability varies |
| Elastic Defend file events | File operations and file metadata | Confirm actual path and operation in raw event |
| Elastic Defend network events | Endpoint network context | Not every SSH event maps to every network field |
| Kibana Discover and alerts | Search, correlation, and detection review | Confirm time range and data view |

Recorded lab architecture: kernel audit → native `auditd` → `/var/log/audit/audit.log` → Elastic Agent logfile integration → Elasticsearch. Elastic Defend provides endpoint process, file, and network event datasets. Treat these as previously reported configuration details and recheck live health only when the current phase requires it.

## 10. Threat-Hunting Methodology

1. **Scope:** fix host, time range, source, and account.
2. **Discover:** find SSH events and determine which fields exist.
3. **Correlate:** compare authentication, auditd, and endpoint timelines.
4. **Enrich:** inspect raw event JSON, actor, process, file path, syscall, outcome, and session context.
5. **Test alternatives:** account for legitimate key administration, automation, and repeated syscall records.
6. **Assess confidence:** distinguish direct observations from inference.
7. **Preserve:** record query, time window, result count, event timestamp, and evidence reference.
8. **Report:** state conclusion, limitations, and next action.

```mermaid
flowchart LR
    A["Scope"] --> B["Discover"]
    B --> C["Correlate"]
    C --> D["Enrich"]
    D --> E["Test alternatives"]
    E --> F["Assess confidence"]
    F --> G["Preserve evidence"]
    G --> H["Report"]
```

**Text fallback:** Scope → Discover → Correlate → Enrich → Test alternatives → Assess confidence → Preserve evidence → Report.

## 11. KQL Investigation Strategy

Run queries in Kibana against the correct data view and time window. These are starting points, not a guarantee that every field is populated. If a query returns no events, inspect the raw event and broaden the query carefully.

### SSH activity from the Kali lab host

```kql
host.name:"soc-linux" AND
process.name:"sshd" AND
source.ip:"192.168.1.10"
```

### Authentication failures or logins from Kali

```kql
host.name:"soc-linux" AND
process.name:"sshd" AND
source.ip:"192.168.1.10" AND
(event.action:"authentication_failure" OR event.action:"ssh_login")
```

### Public-key authentication success

```kql
host.name:"soc-linux" AND
process.name:"sshd" AND
source.ip:"192.168.1.10" AND
system.auth.ssh.method:"publickey" AND
event.outcome:"success"
```

### Authorized-key auditd path events

```kql
host.name:"soc-linux" AND
data_stream.dataset:"auditd.log" AND
auditd.log.record_type:"PATH" AND
auditd.log.name:"/home/socadmin/.ssh/authorized_keys"
```

### Broader fallback search

```kql
host.name:"soc-linux" AND
(file.path:"/home/socadmin/.ssh/authorized_keys" OR message:"*authorized_keys*")
```

Prefer structured auditd fields when present. A broad text query is an exploration fallback, not a replacement for raw-event review.

### Historical auditd window

This time window is based on earlier notes for the October 3, 2026 exercise and uses the IST offset `+05:30`. Apply it only when searching that historical period.

```kql
host.name:"soc-linux" AND
(event.module:"auditd" OR data_stream.dataset:"auditd.*") AND
@timestamp >= "2026-10-03T14:35:00+05:30" AND
@timestamp <= "2026-10-03T14:47:00+05:30"
```

### SSH session lifecycle

```kql
host.name:"soc-linux" AND
user.name:"socadmin" AND
source.ip:"192.168.1.10" AND
process.executable:"/usr/sbin/sshd" AND
event.action:("authenticated" OR "was-authorized" OR "acquired-credentials" OR "started-session" OR "ended-session")
```

### Endpoint process, file, and network events

```kql
host.name:"soc-linux" AND data_stream.dataset:"endpoint.events.process"
```

```kql
host.name:"soc-linux" AND data_stream.dataset:"endpoint.events.file"
```

```kql
host.name:"soc-linux" AND data_stream.dataset:"endpoint.events.network"
```

### Sudo activity

```kql
host.name:"soc-linux" AND
process.name:"sudo" AND
event.action:(ran-command OR was-authorized OR started-session OR ended-session OR authenticated OR authentication_failure)
```

### Query workflow

```mermaid
flowchart TD
    A["Select data view and time range"] --> B["Run broad SSH query"]
    B --> C["Inspect actual event fields"]
    C --> D["Narrow by source, user, and method"]
    D --> E["Search authorized_keys activity"]
    E --> F["Correlate and preserve evidence"]
```

**Text fallback:** Select data view/time → broad SSH query → inspect fields → narrow scope → search authorized_keys → correlate and preserve.

## 12. Detection Strategy

### Existing lab detection rule

The following KQL is the rule definition recorded for the lab. Verify the current rule and corresponding alert evidence before claiming current end-to-end validation.

```kql
host.name:"soc-linux" AND
data_stream.dataset:"auditd.log" AND
auditd.log.key:"ssh_authorized_keys" AND
auditd.log.record_type:"SYSCALL" AND
NOT event.action:"changed-audit-configuration"
```

| Setting | Recorded value |
|---|---|
| Rule name | `CatchMe - Linux SSH Authorized Keys Modification` |
| Severity | High |
| Risk score | 73 |
| ATT&CK mapping | T1098.004 — SSH Authorized Keys |
| Query type | KQL |

The lab previously reported five high-severity alerts from one controlled file operation. Because a single file operation can generate multiple syscall-level records, review the underlying alert records and assess deduplication; do not equate alert count with incident count.

### Detection logic

```mermaid
flowchart TD
    A["Auditd / endpoint event"] --> B{"Authorized-key activity?"}
    B -->|No| C["Continue monitoring"]
    B -->|Yes| D["Inspect raw records and alert context"]
    D --> E["Correlate actor, path, source, and time"]
    E --> F{"Related public-key login?"}
    F -->|Yes| G["Escalate suspected persistence"]
    F -->|No or unknown| H["Continue investigation"]
```

**Text fallback:** Event → check authorized-key activity → inspect raw records → correlate actor/path/source/time → assess related public-key login → escalate or continue hunting.

## 13. Sigma and YARA Strategy

The project tree contains Sigma and YARA rule files with analysis documents. Their presence alone does not prove that the rules are correct, portable, or validated.

### Sigma

Review log-source assumptions, field names, event selection, exclusions, and conversion behavior. Compare resulting behavior with the Elastic KQL rule and record actual test results.

### YARA

YARA is primarily intended to identify content or byte patterns. A YARA rule alone does not replace behavioral detection of an `authorized_keys` modification or correlation with SSH authentication. Document the rule's actual target and test results; do not claim behavioral detection without evidence.

### Files to review

- `04-detection/sigma/sigma-rule.yml`
- `04-detection/sigma/sigma-analysis.md`
- `04-detection/yara/yara-rule.yar`
- `04-detection/yara/yara-analysis.md`

Record test tools, sample inputs, results, limitations, and false positives before marking either rule validated.

## 14. Investigation Strategy and Findings

### Correlation fields

Use the fields present in the actual event. Potentially useful attributes include:

- `host.name`
- `@timestamp`
- `user.name`
- `source.ip`
- `process.name` and `process.executable`
- `event.action` and `event.outcome`
- `system.auth.ssh.method`
- `auditd.log.record_type`
- `auditd.log.name`
- `auditd.log.key`
- `process.args` and endpoint process command-line fields, when available

### Historical details requiring reconciliation

Earlier lab notes report the following for October 3, 2026. Treat them as historical leads until checked against screenshots and available original event data:

- Reported SSH source and target: `192.168.1.10` and `192.168.1.16`.
- Account recorded in the notes: `socadmin`.
- Reported path: `/home/socadmin/.ssh/authorized_keys`.
- Notes report the entry count changing from one to two and a modification time of `2026-10-03 14:40:56 IST`.
- Notes report public-key re-entry at `2026-10-03 14:45:53.827 IST`, from `192.168.1.10`.
- The recorded sequence includes password-based SSH access, discovery, authorized-key persistence, and key-based re-entry.

Do not publish passwords, private-key content, or full key lines. If original raw events cannot be recovered, retain the historical qualifier and state the evidence limitation.

### Findings template

For each finding, document:

1. Finding ID and title.
2. Hypothesis tested.
3. Query and data view.
4. Time range and timezone.
5. Observed event details and evidence reference.
6. Interpretation and confidence.
7. Alternative explanations and limitations.
8. Recommended response or next investigative step.

## 15. MITRE ATT&CK Mapping

| Technique | Scenario relevance | Evidence required |
|---|---|---|
| [T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/) | Repeated SSH authentication attempts | Authentication failure events with source and target context |
| [T1021.004 — SSH](https://attack.mitre.org/techniques/T1021/004/) | SSH remote access | SSH authentication/session evidence |
| [T1082 — System Information Discovery](https://attack.mitre.org/techniques/T1082/) | Host and OS discovery | Relevant process/audit evidence or documented session output |
| [T1033 — System Owner/User Discovery](https://attack.mitre.org/techniques/T1033/) | Account and user-context discovery | Relevant command or audit evidence |
| [T1057 — Process Discovery](https://attack.mitre.org/techniques/T1057/) | Process enumeration | Endpoint process or audit evidence |
| [T1098.004 — SSH Authorized Keys](https://attack.mitre.org/techniques/T1098/004/) | SSH public-key persistence | Authorized-key file activity and supporting context |

```mermaid
flowchart TD
    A["T1110<br/>Brute Force"] --> B["T1021.004<br/>SSH"]
    B --> C["T1082 / T1033 / T1057<br/>Discovery"]
    C --> D["T1098.004<br/>SSH Authorized Keys"]
    D --> E["T1021.004<br/>Potential key-based re-entry"]
```

**Text fallback:** T1110 → T1021.004 → discovery (T1082/T1033/T1057) → T1098.004 → potential key-based re-entry.

Technique mapping should reflect observed behavior, not only the planned scenario.

## 16. Cyber Kill Chain Mapping

| Stage | Scenario interpretation | Validation requirement |
|---|---|---|
| Reconnaissance | Identify target and SSH service | Include only if supported by evidence |
| Weaponization | May not apply to this credential/persistence scenario | Do not force a mapping |
| Delivery | SSH authentication traffic reaches the endpoint | SSH/network evidence |
| Exploitation | Account access is obtained | Successful authentication/session evidence |
| Installation | Authorized-key persistence is introduced | Audited or endpoint file change |
| Command and Control | SSH may provide a remote interactive channel | Session evidence; do not infer additional C2 |
| Actions on Objectives | Post-access discovery or privilege activity | Process/audit/sudo evidence |

```mermaid
flowchart LR
    A["Reconnaissance<br/>(if observed)"] --> B["Delivery: SSH"]
    B --> C["Access established"]
    C --> D["Installation: authorized key"]
    D --> E["Remote re-entry"]
    E --> F["Post-access activity"]
```

**Text fallback:** Reconnaissance (if observed) → SSH delivery → access → authorized-key persistence → remote re-entry → post-access activity.

The Cyber Kill Chain is a conceptual lens. Not every stage is necessarily present or independently observable.

## 17. Incident Response Strategy

### Triage

1. Confirm host, account, path, and time range.
2. Inspect raw auditd or endpoint events and identify actor, operation, and outcome.
3. Correlate SSH authentication and session lifecycle by source, account, method, and time.
4. Review adjacent process, sudo, and discovery activity.
5. Preserve event references and file metadata before cleanup.

### Containment

- Follow the approved lab response procedure before disabling accounts or terminating sessions.
- Restrict suspicious SSH access where appropriate.
- Preserve logs and file metadata before changing the affected file.
- If unauthorized access is confirmed, revoke the unauthorized key and assess whether credentials require rotation.

### Eradication and recovery

- Preserve the current authorized-key file and relevant metadata.
- Remove only the confirmed unauthorized key.
- Review SSH configuration, account access, and other plausible persistence paths.
- Rotate exposed credentials where warranted.
- Verify ownership and permissions of the home directory, `.ssh` directory, and `authorized_keys`.
- Confirm legitimate access still works and telemetry remains healthy.

### Validation

- Re-query the relevant time window and confirm the unauthorized persistence artifact is absent.
- Confirm auditd and endpoint telemetry continue to arrive.
- Use only approved controlled tests.
- Record actual results; do not claim successful recovery until verified.

```mermaid
flowchart TD
    A["Triage and scope"] --> B["Preserve evidence"]
    B --> C["Contain suspicious access"]
    C --> D["Remove confirmed unauthorized key"]
    D --> E["Review credentials and other persistence"]
    E --> F["Validate legitimate access and telemetry"]
    F --> G{"Validation passed?"}
    G -->|Yes| H["Document recovery and lessons"]
    G -->|No| I["Continue remediation"]
    I --> F
```

**Text fallback:** Triage → preserve evidence → contain → remove confirmed unauthorized key → review credentials and persistence → validate access and telemetry → document recovery or continue remediation.

## 18. Evidence and Screenshot Strategy

### Existing screenshot inventory

Screenshots are present in:

- `09-Screenshots/Attack/`
- `09-Screenshots/Telemetry/`
- `09-Screenshots/Hunting/`

Attack screenshot filenames:

- `P03-ATT-01-credential-discovery.png`
- `P03-ATT-02-ssh-initial-access.png`
- `P03-ATT-03-post-compromise-discovery.png`
- `P03-ATT-04-authorized-key-persistence.png`
- `P03-ATT-05-authorized-key-verification.png`
- `P03-ATT-06-key-based-reentry.png`

Telemetry screenshot filenames:

- `P03-TEL-01-ssh-password-attack.png`
- `P03-TEL-02-ssh-initial-access.png`
- `P03-TEL-03-post-compromise-discovery.png`
- `P03-TEL-04-authorized-key-persistence.png`
- `P03-TEL-05-key-based-reentry.png`

The Hunting folder contains screenshots whose filenames refer to the SSH timeline, authentication correlation/methods, public-key re-entry, authorized-key activity, auditd persistence telemetry, SSH session lifecycle, and sudo activity.

**Evidence limitation:** filenames describe intended topics, not verified contents. Inspect each image before using it to support a conclusion. Correlate screenshots with original events where available.

### Evidence handling

- Preserve original evidence unchanged.
- Store sanitized copies separately from raw evidence.
- Redact credentials, tokens, private keys, personal information, and unrelated host details.
- Record acquisition context, timestamp, timezone, query, and event identifiers.
- Generate SHA-256 hashes for evidence selected for preservation and publication.
- Do not publish raw logs or telemetry exports without sensitivity review.

## 19. Diagrams and Attack Timeline

### Historical timeline — October 3, 2026

Earlier notes record this sequence. Reconcile it with screenshots and original event data before treating it as a fully verified timeline.

| Approximate time (IST) | Reported activity | Evidence status |
|---|---|---|
| Before 14:40 | SSH password attempts and initial access | Historical note; review attack/telemetry evidence |
| 14:40:56 | `authorized_keys` modification time | Historical note; corroborate file/audit evidence |
| 14:45:53.827 | Public-key SSH re-entry | Historical note; corroborate authentication event |
| After re-entry | Session, auditd, or sudo activity | Review individual hunting screenshots and raw events |

### End-to-end SOC workflow

```mermaid
flowchart TD
    A["Environment and baseline"] --> B["Controlled attack"]
    B --> C["Collect auditd and endpoint telemetry"]
    C --> D["Threat hunt and correlate"]
    D --> E["Evaluate detection"]
    E --> F["Investigate and map ATT&CK"]
    F --> G["Contain and eradicate"]
    G --> H["Recover and validate"]
    H --> I["Sanitize evidence, hash, and QA"]
    I --> J["Publish verified report"]
```

**Text fallback:** Environment/baseline → controlled attack → telemetry collection → hunting/correlation → detection evaluation → investigation/mapping → containment/eradication → recovery/validation → evidence sanitization/hash/QA → publication.

### Evidence-to-claim rule

Every published claim about a specific attack event should reference at least one reviewed screenshot, event record, or sanitized artifact. Keep expected behavior, historical notes, current observations, and conclusions clearly separated.

## 20. Success Criteria, Validation and Project Status

### Success criteria

- [ ] Lab host mapping and timezone are recorded correctly.
- [ ] Attack steps are supported by reviewed evidence.
- [ ] SSH authentication events are correlated by source, account, and time.
- [ ] Authorized-key file activity is supported by auditd and/or endpoint evidence.
- [ ] Key-based re-entry is verified from actual authentication telemetry.
- [ ] Detection logic is checked against the current rule and actual alerts.
- [ ] Duplicate syscall-level alerts are assessed without equating alert count to incident count.
- [ ] Investigation conclusions state evidence, confidence, and limitations.
- [ ] ATT&CK and Kill Chain mappings are evidence-based.
- [ ] Response and recovery are reported complete only after validation.
- [ ] Screenshots and files are sanitized.
- [ ] Evidence hashes are generated and checked.
- [ ] Links, Markdown, and diagrams are tested in the target GitHub repository.

### Project status

This README is a consolidated project guide; it does not certify that every phase is complete. The project directory contains attack, telemetry, and hunting screenshots, and earlier notes report activity on October 3, 2026. Review and reconcile these artifacts before making stronger claims.

| Workstream | Current reporting position |
|---|---|
| README | Rebuilt with 20 numbered sections, Mermaid diagrams, and text fallbacks |
| Lab architecture | Fixed mapping documented |
| Attack | Screenshots exist; verify contents and reconcile historical notes |
| Telemetry | Screenshots exist; correlate with actual events where available |
| Threat hunting | Screenshots exist; tie findings to query results and evidence |
| Detection | Rule definition recorded; verify current rule and alert evidence |
| Sigma/YARA | Rule files exist; validation and portability must be documented |
| Investigation | Confirm completion only after findings and timeline are evidence-linked |
| Incident response | Plans documented; claim completion only when demonstrated |
| Evidence integrity | Hashing and publication sanitization remain pending until performed |
| Git/GitHub | Paused; no repository initialization or publication is implied |

---

## References

- MITRE ATT&CK — [Brute Force (T1110)](https://attack.mitre.org/techniques/T1110/)
- MITRE ATT&CK — [SSH (T1021.004)](https://attack.mitre.org/techniques/T1021/004/)
- MITRE ATT&CK — [System Information Discovery (T1082)](https://attack.mitre.org/techniques/T1082/)
- MITRE ATT&CK — [System Owner/User Discovery (T1033)](https://attack.mitre.org/techniques/T1033/)
- MITRE ATT&CK — [Process Discovery (T1057)](https://attack.mitre.org/techniques/T1057/)
- MITRE ATT&CK — [SSH Authorized Keys (T1098.004)](https://attack.mitre.org/techniques/T1098/004/)
- Elastic — [Kibana Query Language](https://www.elastic.co/guide/en/kibana/current/kuery-query.html)
- Elastic — [Auditd Manager integration](https://www.elastic.co/guide/en/integrations/current/auditd_manager.html)

## Disclaimer

This is a controlled defensive lab and portfolio project. Hostnames and IP addresses above are the fixed lab mapping, not public targets. Test only systems you own or are explicitly authorized to assess. Never include passwords, private SSH keys, tokens, or other sensitive authentication material in public evidence.
