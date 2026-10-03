# Pre-Attack Control Matrix

## Project

Project 03 — SSH Authorized-Key Backdoor

## Purpose

Track all controls required before controlled attack execution.

## Lab Controls

| Control | Requirement |
|---|---|
| Elastic SIEM | `elastic-siem` — `192.168.1.11` |
| Linux Endpoint | `soc-linux` — `192.168.1.16` |
| Kali Attacker | `192.168.1.10` |
| Network | `192.168.1.0/24` |
| Gateway | `192.168.1.1` |
| Timezone | Asia/Kolkata / IST |

## Control Matrix

| Control | Planned | Executed | Evidence | Screenshot | Documentation | Verified |
|---|---|---|---|---|---|---|
| Environment verification | Yes | Pending | Pending | Pending | Planned | Pending |
| Hostname verification | Yes | Pending | Pending | Pending | Planned | Pending |
| IP verification | Yes | Pending | Pending | Pending | Planned | Pending |
| Timezone verification | Yes | Pending | Pending | Pending | Planned | Pending |
| Elastic Agent verification | Yes | Pending | Pending | Pending | Planned | Pending |
| Elastic Agent health | Yes | Pending | Pending | Pending | Planned | Pending |
| Auditd service | Yes | Pending | Pending | Pending | Planned | Pending |
| Auditd enabled state | Yes | Pending | Pending | Pending | Planned | Pending |
| Auditd lost events | Yes | Pending | Pending | Planned | Planned | Pending |
| SSH service | Yes | Pending | Pending | Pending | Planned | Pending |
| SSH authentication configuration | Yes | Pending | Pending | Pending | Planned | Pending |
| SSH baseline | Yes | Pending | Pending | Pending | Planned | Pending |
| Hunt hypothesis | Yes | Planned | N/A | N/A | Planned | Pending |
| Attack objectives | Yes | Planned | N/A | N/A | Planned | Pending |
| Telemetry requirements | Yes | Planned | N/A | N/A | Planned | Pending |
| Evidence directories | Yes | Pending | Pending | N/A | Planned | Pending |
| Screenshot directories | Yes | Pending | Pending | N/A | Planned | Pending |
| Fixed lab mapping | Yes | Pending | Pending | Pending | Planned | Pending |
| Safety controls | Yes | Pending | Pending | N/A | Planned | Pending |
| Attack authorization scope | Yes | Pending | N/A | N/A | Planned | Pending |
| Baseline evidence preserved | Yes | Pending | Pending | Pending | Planned | Pending |
| Pre-attack review | Yes | Pending | Pending | Pending | Planned | Pending |

## Required Pre-Attack Verification

The following must be verified before attack execution:

```text
Lab Mapping
    ↓
Hostname / IP
    ↓
Timezone
    ↓
Elastic Agent
    ↓
Auditd
    ↓
SSH
    ↓
Baseline
    ↓
Telemetry Availability
    ↓
Evidence Readiness
    ↓
Safety Review
    ↓
Attack Authorization
```

## Evidence Rules

Evidence must be collected from the actual lab.

The project must not contain fabricated:

- Events
- Alerts
- Timestamps
- Screenshots
- Query results
- Detection results
- Attack outcomes

## Safety Controls

Attack activity is restricted to:

- Kali `192.168.1.10`
- `soc-linux` `192.168.1.16`
- `elastic-siem` `192.168.1.11`

Production and third-party systems are excluded.

Destructive activity is excluded.

## Completion Criteria

Pre-attack controls are complete only when:

- Environment is verified
- Fixed IP mapping is confirmed
- Timezone is confirmed
- Elastic Agent is healthy
- Auditd is active
- Auditd enabled state is verified
- Auditd lost events are checked
- SSH is active
- SSH configuration baseline is captured
- Telemetry availability is confirmed
- Evidence directories are ready
- Screenshot directories are ready
- Safety scope is confirmed
- Pre-attack review is completed

## Status

Project 03 remains in the pre-attack phase until all required controls are verified with actual evidence.
