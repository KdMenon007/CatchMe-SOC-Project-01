# Attack Objectives

## Project

Project 03 — SSH Authorized-Key Backdoor

## Primary Objective

Simulate a controlled SSH persistence scenario in which an authenticated session discovers and modifies the user's `authorized_keys` file, establishes persistence, terminates the original session, and performs controlled re-entry.

## Attack Objectives

### Objective 1 — Establish Controlled SSH Access

Establish a controlled SSH session from Kali `192.168.1.10` to `soc-linux` `192.168.1.16`.

Record:

- Source IP
- Destination IP
- Username
- Authentication method
- Authentication result
- Session creation
- Session termination
- Relevant timestamps

### Objective 2 — Perform Controlled Discovery

Perform limited discovery required to identify the host, user, SSH configuration, and SSH key location.

### Objective 3 — Identify authorized_keys

Identify the designated user's SSH authorization file.

```text
~/.ssh/authorized_keys
```

### Objective 4 — Establish Controlled Persistence

Modify the designated user's `authorized_keys` file using a lab-generated SSH public key.

The persistence mechanism must be:

- Lab-specific
- Reversible
- Limited to `soc-linux`
- Documented before removal

### Objective 5 — Preserve Persistence Evidence

Capture relevant evidence before remediation, including:

- File metadata
- Ownership
- Permissions
- Modification time
- Key entry
- Auditd events
- Process activity
- SSH authentication telemetry
- Elastic evidence

### Objective 6 — Validate Persistence

Terminate the initial session and perform controlled SSH re-entry using the lab-generated key.

Persistence must be demonstrated through actual evidence.

### Objective 7 — Correlate the Attack Chain

Correlate:

```text
SSH Authentication
    ↓
Session
    ↓
Discovery
    ↓
authorized_keys Access
    ↓
File Modification
    ↓
Persistence
    ↓
Subsequent Authentication
```

### Objective 8 — Perform Initial Triage

Evaluate:

- Identity
- Behavior
- Source context
- Traffic
- Timeline

### Objective 9 — Develop Threat-Hunting Queries

Create KQL queries based on actual investigation questions and observed telemetry.

### Objective 10 — Develop Detection Logic

Develop Elastic detection logic for suspicious SSH persistence behavior based on actual telemetry.

### Objective 11 — Evaluate Sigma

Create or evaluate a Sigma rule when the observed telemetry supports portable detection.

### Objective 12 — Evaluate YARA

Determine whether a suitable artifact exists for YARA analysis.

If no suitable artifact exists, document YARA as not applicable.

### Objective 13 — Investigate the Endpoint

Investigate:

- Authentication
- Processes
- Shell activity
- Files
- `authorized_keys`
- SSH configuration
- Persistence
- Network activity

### Objective 14 — Determine Scope

Determine affected:

- Host
- Account
- Source
- Persistence mechanism
- Related sessions

### Objective 15 — Map MITRE ATT&CK

Map observed behavior to applicable ATT&CK techniques and sub-techniques.

### Objective 16 — Map Cyber Kill Chain

Map only applicable and evidence-supported stages.

### Objective 17 — Contain

Stop further unauthorized access while preserving relevant evidence.

### Objective 18 — Eradicate

Remove the controlled persistence mechanism and verify that no unauthorized key remains.

### Objective 19 — Recover

Return the endpoint to the intended lab baseline.

### Objective 20 — Validate

Verify that persistence is removed and legitimate monitoring and SSH functionality remain operational.

## Safety Constraints

Attack activity is limited to:

| System | Role | IP |
|---|---|---|
| Kali | Attacker | `192.168.1.10` |
| `soc-linux` | Linux endpoint | `192.168.1.16` |
| `elastic-siem` | Elastic SIEM | `192.168.1.11` |

Production and third-party systems are excluded.

Destructive activity is excluded.

## Completion Standard

An objective is complete only when supported by actual evidence.

Expected behavior must not be recorded as an observed result until the scenario has been executed.
