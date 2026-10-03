# CatchMe Linux SOC — Project 03
# SSH Authorized-Key Backdoor Threat Hunt

## Environment Verification

## Purpose

Verify that the fixed CatchMe Linux SOC lab is operational and that the target endpoint can generate the telemetry required for the SSH authorized-key persistence scenario.

## Fixed Lab Mapping

| System | Hostname | Fixed IP | Role |
|---|---|---:|---|
| Elastic SIEM | `elastic-siem` | `192.168.1.11` | SIEM / Fleet |
| Linux Endpoint | `soc-linux` | `192.168.1.16` | Target |
| Kali | `kiran` | `192.168.1.10` (`eth0`) | Attacker |
| Gateway | — | `192.168.1.1` | Gateway |

## Time and Identity Verification

### Kali

Commands used:

```bash
hostname
date
timedatectl | grep -E 'Time zone|zone'
ip -br addr
```

Observed:

- Hostname: `kiran`
- Timezone: `Asia/Kolkata`
- Fixed attacker interface: `eth0`
- Fixed attacker IP: `192.168.1.10`
- Kali also has `wlan0` at `192.168.1.9`; this address is not used as the fixed attacker identity.

### Target

Commands used:

```bash
hostname
date
timedatectl | grep -E 'Time zone|zone'
ip -br addr
```

Observed:

- Hostname: `soc-linux`
- Timezone: `Asia/Kolkata`
- Target interface: `enp2s0`
- Target IP: `192.168.1.16`

## Network Connectivity Verification

From Kali:

```bash
ping -c 2 192.168.1.16
nc -vz 192.168.1.16 22
```

Observed:

- ICMP connectivity to `192.168.1.16`: successful
- TCP/22 connectivity: successful

## SSH Configuration Verification

On `soc-linux`:

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

## Service and Telemetry Verification

Commands used:

```bash
systemctl is-active ssh
systemctl is-active auditd
systemctl is-enabled auditd
sudo auditctl -s | grep -E 'enabled|lost'
systemctl is-active elastic-agent
sudo elastic-agent status
ss -lntp | grep ':22'
```

Observed:

```text
ssh        active
auditd     active
auditd     enabled
auditd     enabled 1
auditd     lost 0
elastic-agent active
Fleet      HEALTHY Connected
elastic-agent HEALTHY Running
TCP/22     LISTEN on 0.0.0.0 and [::]
```

## Authorized-Key Baseline Verification

Commands used:

```bash
id
whoami
echo "$HOME"
ls -la ~/.ssh
sudo stat ~/.ssh/authorized_keys 2>/dev/null || true
sudo sed -n '1,20p' ~/.ssh/authorized_keys 2>/dev/null || true
```

Observed:

- User: `socadmin`
- UID/GID: `1000/1000`
- Home: `/home/socadmin`
- `.ssh` directory permissions: `0700`
- `authorized_keys` permissions: `0600`
- Owner: `socadmin:socadmin`
- File size: 93 bytes
- Existing entries: 1
- Existing key type: `ssh-ed25519`
- Existing key comment: `kiran@kiran`

The existing key is baseline data and must not be removed or modified.

## Verification Result

The Project 03 environment is ready for controlled attack preparation.

No attack activity is included in this verification section. The observations above represent the pre-attack state only.
