# Telemetry Requirements

## Project

Project 03 — SSH Authorized-Key Backdoor

## Purpose

Define the telemetry required to detect, hunt, investigate, and validate SSH authorized-key persistence on the Linux endpoint.

## Primary Telemetry Objective

The investigation must provide enough telemetry to correlate:

```text
SSH Authentication
    ↓
SSH Session
    ↓
Process / Shell Activity
    ↓
SSH Configuration Discovery
    ↓
authorized_keys Access
    ↓
authorized_keys Modification
    ↓
Persistence
    ↓
Subsequent SSH Authentication
```

## Authentication Telemetry

Required or preferred fields include:

| Field | Purpose |
|---|---|
| `@timestamp` | Event timing |
| `host.name` | Affected endpoint |
| `user.name` | Account involved |
| `source.ip` | Connection source |
| `source.port` | Source connection port |
| `destination.ip` | Destination endpoint |
| `destination.port` | SSH destination port |
| `process.name` | SSH-related process |
| `event.action` | Authentication/session action |
| `event.category` | Event classification |
| `message` | Supporting authentication detail |

Potential sources:

- SSH authentication logs
- System authentication logs
- system journal
- Elastic `system.auth` events

## Process Telemetry

Process telemetry should support identification of:

- SSH daemon activity
- Shell creation
- Command execution
- Parent process
- Child process
- Executing user
- Process arguments
- Process start time

The exact available fields will be verified during environment validation.

## File Telemetry

File telemetry should support investigation of:

- `authorized_keys` access
- `authorized_keys` modification
- File path
- File owner
- File permissions
- File timestamps
- Process responsible for the activity
- User responsible for the activity

Auditd telemetry is expected to be an important source for this investigation.

## Network Telemetry

Network telemetry should support:

- Source IP
- Destination IP
- Source port
- Destination port
- SSH connection timing
- Repeated SSH connections
- Subsequent SSH re-entry

The primary controlled relationship is:

```text
192.168.1.10
     │
     │ SSH / TCP 22
     ▼
192.168.1.16
soc-linux
```

## Endpoint Health Requirements

Before attack execution, verify:

| Component | Requirement |
|---|---|
| Elastic Agent | Active and healthy |
| Auditd | Active |
| Auditd enabled state | Enabled |
| Auditd lost events | `0` |
| SSH | Active |
| SSH authentication | Enabled as required for scenario |
| Hostname | `soc-linux` |
| Endpoint IP | `192.168.1.16` |
| Timezone | Asia/Kolkata / IST |

## Elastic Telemetry Requirements

The Elastic environment should be able to receive and search endpoint telemetry from `soc-linux`.

The following areas should be checked where available:

- Authentication events
- Process events
- File events
- Auditd events
- Network events
- Host metadata
- User metadata

No telemetry source will be assumed to exist until verified.

## Required Correlation

The telemetry should allow investigation across these relationships:

```text
Source IP
    ↓
User
    ↓
Authentication
    ↓
Session
    ↓
Process
    ↓
File
    ↓
authorized_keys
    ↓
Modification
    ↓
Subsequent Authentication
```

## Telemetry Gaps

Any missing telemetry must be documented during validation.

Potential gaps include:

- Command-line visibility
- Process ancestry
- File access visibility
- File modification attribution
- Network session visibility
- Exact SSH session correlation

A telemetry gap must not be treated as evidence that an activity did not occur.

## Evidence Requirements

Relevant telemetry should be preserved through:

- Elastic screenshots
- Query results
- Raw endpoint outputs
- Authentication logs
- Auditd evidence
- File metadata
- Process evidence

Evidence will be stored under:

```text
11-Evidence/
├── Raw/
├── Sanitized/
└── Hashes/
```

## Validation Requirement

Telemetry requirements will be considered satisfied only after the actual environment has been verified and the required data sources have demonstrated usable events.

## Project Constraint

Only telemetry actually available from the CatchMe Linux SOC laboratory will be used for the final investigation.
