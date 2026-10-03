# CatchMe Linux SOC — Project 03
# SSH Authorized-Key Backdoor Threat Hunt

## Attack Objectives

### Project Objective

Simulate a controlled SSH authorized-key persistence scenario against the CatchMe Linux SOC lab endpoint and validate the complete SOC workflow:

1. Introduce a controlled SSH public key into the target user's `authorized_keys`.
2. Establish SSH access using the newly introduced key.
3. Generate realistic endpoint authentication, file, process, and network telemetry.
4. Hunt for evidence of unauthorized SSH key persistence.
5. Detect the persistence activity using Elastic SIEM.
6. Correlate authentication activity with changes to the SSH key file.
7. Investigate the account, file, process, and network activity.
8. Map confirmed activity to MITRE ATT&CK.
9. Execute containment, eradication, remediation, and recovery.
10. Preserve evidence and document the complete investigation.

## Fixed Lab Scope

| Component | Hostname | IP | Role |
|---|---|---:|---|
| Elastic SIEM | `elastic-siem` | `192.168.1.11` | Elasticsearch, Kibana, Fleet |
| Linux Endpoint | `soc-linux` | `192.168.1.16` | Target endpoint |
| Kali | `kiran` | `192.168.1.10` (`eth0`) | Controlled attacker |
| Gateway | — | `192.168.1.1` | Network gateway |

The fixed attacker address for this project is `192.168.1.10`. The Kali `wlan0` address `192.168.1.9` is not used as the fixed attacker identity.

## Observed Pre-Attack State

The following state was verified immediately before attack preparation:

- Target hostname: `soc-linux`
- Target user: `socadmin`
- User home: `/home/socadmin`
- SSH service: active
- SSH port: TCP/22
- Password authentication: enabled
- Public-key authentication: enabled
- X11 forwarding: enabled
- `PermitUserEnvironment`: disabled
- `MaxAuthTries`: 6
- `LoginGraceTime`: 120 seconds
- Auditd: active and enabled
- Auditd lost events: 0
- Elastic Agent: healthy and running
- Fleet: healthy and connected
- `/home/socadmin/.ssh` permissions: `0700`
- `authorized_keys` permissions: `0600`
- `authorized_keys` owner: `socadmin:socadmin`
- Existing `authorized_keys` entries: 1 legitimate `ssh-ed25519` key

The existing legitimate key must remain untouched throughout the controlled attack.

## Commands Used for Attack-Objective Baseline Validation

```bash
id
whoami
echo "$HOME"
ls -la ~/.ssh
sudo stat ~/.ssh/authorized_keys 2>/dev/null || true
sudo sed -n '1,20p' ~/.ssh/authorized_keys 2>/dev/null || true

sudo sshd -T | grep -E '^(permitrootlogin|pubkeyauthentication|passwordauthentication|x11forwarding|permituserenvironment|maxauthtries|logingracetime)'
systemctl is-active ssh
systemctl is-active auditd
systemctl is-enabled auditd
sudo auditctl -s | grep -E 'enabled|lost'
systemctl is-active elastic-agent
sudo elastic-agent status
ss -lntp | grep ':22'
```

## Safety Objectives

- Use only the isolated CatchMe lab systems.
- Do not use external hosts.
- Do not delete the legitimate baseline SSH key.
- Do not perform destructive activity.
- Do not escalate privileges unless explicitly required by the scenario.
- Preserve original evidence before remediation.
- Record actual observations rather than expected or fabricated results.

## Success Criteria

The attack phase is successful only when the controlled key-persistence scenario produces sufficient real telemetry to support:

- authentication correlation,
- SSH key-file investigation,
- process and network investigation,
- persistence identification,
- detection validation,
- MITRE ATT&CK mapping,
- incident-response documentation,
- evidence preservation and hashing.
