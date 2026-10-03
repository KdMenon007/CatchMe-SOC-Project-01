# CatchMe Linux SOC — Project 03
# SSH Authorized-Key Backdoor Threat Hunt

## Pre-Attack Control Matrix

## Purpose

Confirm that the CatchMe Linux SOC lab is safe, reachable, instrumented, and correctly baselined before introducing controlled SSH authorized-key persistence.

| Control ID | Control | Verification | Actual Result | Status |
|---|---|---|---|---|
| PRE-01 | Fixed attacker identity | `hostname`, `ip -br addr` | Kali `kiran`, fixed `eth0` `192.168.1.10` | PASS |
| PRE-02 | Target identity | `hostname`, `ip -br addr` | `soc-linux`, `192.168.1.16` | PASS |
| PRE-03 | Time synchronization/context | `date`, timezone check | `Asia/Kolkata` / IST | PASS |
| PRE-04 | Target reachability | `ping -c 2 192.168.1.16` | 0% packet loss | PASS |
| PRE-05 | SSH reachability | `nc -vz 192.168.1.16 22` | TCP/22 reachable | PASS |
| PRE-06 | SSH service | `systemctl is-active ssh` | `active` | PASS |
| PRE-07 | Auditd service | `systemctl is-active auditd` | `active` | PASS |
| PRE-08 | Auditd enabled | `systemctl is-enabled auditd` | `enabled` | PASS |
| PRE-09 | Auditd event loss | `sudo auditctl -s` | `enabled 1`, `lost 0` | PASS |
| PRE-10 | Elastic Agent | `systemctl is-active elastic-agent` | `active` | PASS |
| PRE-11 | Fleet health | `sudo elastic-agent status` | HEALTHY / Connected | PASS |
| PRE-12 | SSH configuration | `sudo sshd -T ...` | Baseline configuration captured | PASS |
| PRE-13 | SSH listener | `ss -lntp \| grep ':22'` | `0.0.0.0:22`, `[::]:22` | PASS |
| PRE-14 | Target account | `id`, `whoami`, `$HOME` | `socadmin`, `/home/socadmin` | PASS |
| PRE-15 | SSH directory | `ls -la ~/.ssh` | `0700`, owner `socadmin` | PASS |
| PRE-16 | Authorized-key baseline | `stat`, `sed` | One existing legitimate key | PASS |
| PRE-17 | Existing key preservation | Baseline recorded before attack | Existing key identified | PASS |
| PRE-18 | External targeting control | Fixed lab scope | No external target included | PASS |
| PRE-19 | Destructive-action control | Attack plan | No destructive activity planned | PASS |
| PRE-20 | Evidence control | Raw/sanitized/hash structure | Evidence workflow established | PASS |

## Commands Used

### Kali

```bash
hostname
date
timedatectl | grep -E 'Time zone|zone'
ip -br addr
ping -c 2 192.168.1.16
nc -vz 192.168.1.16 22
```

### `soc-linux`

```bash
hostname
date
timedatectl | grep -E 'Time zone|zone'
ip -br addr

sudo sshd -T | grep -E '^(permitrootlogin|pubkeyauthentication|passwordauthentication|x11forwarding|permituserenvironment|maxauthtries|logingracetime)'
systemctl is-active ssh
systemctl is-active auditd
systemctl is-enabled auditd
sudo auditctl -s | grep -E 'enabled|lost'
systemctl is-active elastic-agent
sudo elastic-agent status
ss -lntp | grep ':22'

id
whoami
echo "$HOME"
ls -la ~/.ssh
sudo stat ~/.ssh/authorized_keys 2>/dev/null || true
sudo sed -n '1,20p' ~/.ssh/authorized_keys 2>/dev/null || true
```

## Safety Gates

Attack execution must not begin unless all of the following remain true:

- Fixed target is `192.168.1.16`.
- Fixed attacker is `192.168.1.10` on Kali `eth0`.
- Time context is IST.
- SSH is active.
- Auditd is active and `lost 0`.
- Elastic Agent and Fleet are healthy.
- Baseline `authorized_keys` state is preserved.
- Existing legitimate key is not modified.
- Evidence directories are available.
- Attack remains inside the CatchMe lab.

## Gate Result

All observed pre-attack controls passed.

The environment is approved for the next controlled attack-preparation stage.
