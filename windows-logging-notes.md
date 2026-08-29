
# Core idea

- OSs record events (who did what, when). Those records are the raw material for incident response, threat hunting, and alerting. Treat logs like a timeline you can rewind and inspect.
    

# Log anatomy (what a log entry gives you)

- Timestamp (usually system local time).
    
- Event identifier (an Event ID that maps to a specific action).
    
- Actor (which account acted).
    
- Target/object (what was changed or accessed).
    
- Details/payload (fields that explain the action: IP, process name, command line, group membership, etc.).
    
- Correlation keys (e.g., Logon ID) to link related events together.
    

# Where Windows keeps them

- Native logs are EVTX files (binary) in `C:\Windows\System32\winevt\Logs`. Use Event Viewer or a parser to read them.
    

# Most valuable default log: Security log

- Best single source for detecting account compromise and the start of intrusions.
    
- Two focal Event IDs:
    
    - Successful auth events (e.g., typical: 4624) — shows logins; noisy on busy servers.
        
    - Failed auth events (e.g., typical: 4625) — useful for brute-force/password-spray detection; format has caveats so interpret carefully.
        

# Quick fields to check in auth events

- Logon type (interactive, remote, network, service, etc.).
    
- Account name and domain.
    
- Source IP / hostname.
    
- Logon ID (crucial for stitching events).
    
- Success/failure reason codes.
    

# User/account management events — what to watch

- Account creation / enable / modify (e.g., 4720 / 4722 / 4738): look for new backdoors or re-enabled dormant accounts.
    
- Account disable / delete (e.g., 4725 / 4726): attackers sometimes disable defender accounts.
    
- Password changes / resets (e.g., 4723 / 4724): suspicious if done by unexpected services or at odd times.
    
- Group membership changes (e.g., 4732 / 4733): adding to privileged groups is a big red flag.
    

# How to read user-management events

- Break each event into: Subject (who performed it), Object (who/what was targeted), Details (what changed).
    
- Use Logon ID on the Subject to connect back to the authentication event that created that session.
    

# Process activity monitoring — why it matters

- Many attacks boil down to processes executing malicious commands or tools. Seeing process launches + context lets you map the attack chain.
    

# Two approaches to process logs

- Native Process Creation (4688): logs process starts and commandlines but is noisy and less feature-rich.
    
- Sysmon (recommended): lightweight agent that logs richer metadata (hashes, signatures, parent process, network connections, file/registry events). Much easier to hunt with.
    

# Important Sysmon event basics

- Event ID 1 = Process creation (full context: image path, cmdline, PID, parent PID, hashes).
    
- Other Sysmon events: file creation/modify, registry set, network connections, DNS queries. Use these to extend the process story.
    

# Correlation pattern

- Use ProcessID + LogonID to join: Security auth → Sysmon process creation → Sysmon network/file/registry events → subsequent user-management events.
    

# PowerShell telemetry — special case

- A single `powershell.exe` process can run many commands without spawning new processes, so process creation logs alone miss the commands.
    
- Useful approaches:
    
    - PSReadline history file: `C:\Users\<USER>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt` — records entered commands (persistent across reboots unless deleted).
        
    - (Better) Enable advanced PowerShell logging (transcripts, module logging, ScriptBlock logging, AMSI) for command-level visibility — but even the history file is a low-effort win.
        

# Limitations & caveats

- Default Windows logging can be noisy and incomplete; not everything is enabled by default.
    
- Timestamps are system local time (watch timezones).
    
- Some events lack fields (e.g., many Sysmon events don’t include LogonID — you must join on ProcessID).
    
- Attackers may delete/alter logs; centralize logs to reduce that risk.
    

# Practical detection rules / hunting heuristics

- Look for unusual combination: new admin-group membership + prior distant-source successful login + account password reset.
    
- Spike in failed auths from one source → check for password-spray / brute force.
    
- Processes spawned by unusual parents (e.g., `cmd.exe` spawned by `explorer.exe` with odd args).
    
- PowerShell with remote download commands (Invoke-WebRequest, Start-BitsTransfer) — check PS history/transcripts.
    
- Unknown service or system account suddenly active or renamed — hunt account creation/change events.
    

# Quick “do this now” SOC checklist

1. Ensure Security logs are collected centrally (SIEM / log server).
    
2. Enable/process-creation logs; if possible, install Sysmon with a well-curated config.
    
3. Enable PowerShell advanced logging (transcripts, scriptblock/module logging) and ensure PSReadline history is retained.
    
4. Create alerts for: abnormal admin group adds, mass failed logins, new local admin accounts, process launches from network-facing services, and suspicious PowerShell downloads.
    
5. Use LogonID and ProcessID as primary correlation keys.
    
6. Periodically hunt for stale accounts, changes to privileged groups, and unexpected service account activity.
    

