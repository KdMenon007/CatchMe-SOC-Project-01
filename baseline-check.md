# CatchMe Linux SOC — Project 03
# SSH Authorized-Key Backdoor Threat Hunt

## Baseline Check

## Purpose

Capture the target endpoint's SSH, account, service, telemetry, and authorized-key state before introducing the Project 03 persistence artifact.

## Account Baseline

Commands:

```bash
id
whoami
echo "$HOME"
```

Observed:

```text
uid=1000(socadmin) gid=1000(socadmin)
User: socadmin
Home: /home/socadmin
```

The `socadmin` account is the controlled target account for the scenario.

## SSH Directory Baseline

Command:

```bash
ls -la ~/.ssh
```

Observed:

```text
.ssh permissions: 0700
authorized_keys permissions: 0600
known_hosts present
known_hosts.old present
```

## Authorized-Keys Baseline

Commands:

```bash
sudo stat ~/.ssh/authorized_keys 2>/dev/null || true
sudo sed -n '1,20p' ~/.ssh/authorized_keys 2>/dev/null || true
```

Observed:

```text
Path: /home/socadmin/.ssh/authorized_keys
Size: 93 bytes
Permissions: 0600
Owner: socadmin:socadmin
Existing entries: 1
Key type: ssh-ed25519
Comment: kiran@kiran
```

The public-key material itself is treated as baseline evidence. The existing key must remain unchanged during the attack.

## SSH Configuration Baseline

Command:

```bash
sudo sshd -T | grep -E '^(permitrootlogin|pubkeyauthentication|passwordauthentication|x11forwarding|permituserenvironment|maxauthtries|logingracetime)'
```

Observed:

```text
logingracetime 120
maxauthtries 6
permitrootlogin without-password
pubkeyauthentication yes
passwordauthentication yes
x11forwarding yes
permituserenvironment no
```

## Service Baseline

Commands:

```bash
systemctl is-active ssh
systemctl is-active auditd
systemctl is-enabled auditd
systemctl is-active elastic-agent
sudo elastic-agent status
```

Observed:

```text
ssh: active
auditd: active
auditd: enabled
elastic-agent: active
Fleet: HEALTHY / Connected
elastic-agent: HEALTHY / Running
```

## Audit Baseline

Command:

```bash
sudo auditctl -s | grep -E 'enabled|lost'
```

Observed:

```text
enabled 1
lost 0
```

This establishes that auditd was enabled and had no reported lost events at baseline capture.

## SSH Listener Baseline

Command:

```bash
ss -lntp | grep ':22'
```

Observed:

```text
0.0.0.0:22
[::]:22
```

SSH is listening on IPv4 and IPv6 wildcard addresses.

## Baseline Integrity Requirements

The following values must be compared after the attack:

| Baseline Artifact | Pre-Attack State | Post-Attack Comparison |
|---|---|---|
| `authorized_keys` size | 93 bytes | Identify change |
| `authorized_keys` entry count | 1 | Identify added entry |
| `authorized_keys` permissions | 0600 | Detect permission change |
| `authorized_keys` owner | `socadmin:socadmin` | Detect ownership change |
| `.ssh` permissions | 0700 | Detect permission change |
| SSH authentication | Password + public key enabled | Correlate with attack |
| Auditd | Enabled, lost 0 | Check telemetry continuity |
| Elastic Agent | Healthy | Confirm telemetry ingestion |
| SSH listener | TCP/22 IPv4 + IPv6 | Confirm service continuity |

## Baseline Conclusion

The target endpoint is instrumented and operational. A single pre-existing legitimate SSH public key was identified. This key is the primary baseline reference for distinguishing the controlled persistence artifact from normal SSH configuration.
