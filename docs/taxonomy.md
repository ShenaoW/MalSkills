# SkillGuard Taxonomy

## Layering

1. `evidence taxonomy`
2. `primitive taxonomy`
3. `reasoning taxonomy`

Rules:

- evidence facts classify sensitive operations into stable behavior classes
- primitive facts do not redefine those classes; they bind concrete operands, targets, and logical objects
- reasoning links primitives through object identity, source/sink relations, and enabling relations to infer final security consequences

## Evidence Taxonomy

### Payload Execution

| Category | Subtype | Definition | Typical APIs / syscalls | Typical Bash / CLI | ATT&CK mapping |
| --- | --- | --- | --- | --- | --- |
| Payload Execution | direct_process_execution | Directly start a new process or program | `CreateProcess*`, `NtCreateUserProcess`, `execve`, `posix_spawn` | `cmd /c`, `bash -c`, direct ELF/EXE launch | Execution |
| Payload Execution | shell_interpreter_execution | Execute commands or script fragments through a shell interpreter | `system`, `popen`, `ShellExecute*` | `bash -c`, `sh -c`, `eval`, `source`, `.` | Execution |
| Payload Execution | script_host_execution | Execute code through a script interpreter or host runtime | interpreter startup or embedded execution APIs | `python -c`, `perl -e`, `ruby -e`, `node -e`, `php -r`, `powershell -enc` | Execution |
| Payload Execution | dynamic_module_load | Dynamically load DLL/so/dylib/module/plugin at runtime | `LoadLibrary*`, `LdrLoadDll`, `dlopen` | interpreter or loader driven module load | Execution |
| Payload Execution | proxy_execution_or_lolbin_abuse | Trigger execution through trusted system tooling or host proxies | COM/Automation or host invocation interfaces | `rundll32`, `regsvr32`, `mshta`, `wmic process call create` | Execution / Defense Evasion |

### Process and Memory Manipulation

| Category | Subtype | Definition | Typical APIs / syscalls | Typical Bash / CLI | ATT&CK mapping |
| --- | --- | --- | --- | --- | --- |
| Process and Memory Manipulation | process_attach | Attach to another process or acquire debugging/task-port capability | `OpenProcess`, `task_for_pid`, `ptrace` | `gdb -p`, `lldb -p`, `strace -p` | Defense Evasion / Privilege Escalation |
| Process and Memory Manipulation | cross_process_memory_read | Read another process address space | `ReadProcessMemory`, `process_vm_readv`, `/proc/<pid>/mem` | read `/proc/<pid>/mem`, debugger dump | Credential Access / Defense Evasion |
| Process and Memory Manipulation | cross_process_memory_write | Write data or code into another process | `WriteProcessMemory`, `process_vm_writev`, `mach_vm_write` | debugger or scripted process write | Defense Evasion / Execution |
| Process and Memory Manipulation | remote_thread_or_async_execution | Trigger execution inside another process context | `CreateRemoteThread`, `QueueUserAPC`, `SetThreadContext` | injector or debugger assisted remote trigger | Execution / Defense Evasion |
| Process and Memory Manipulation | executable_memory_mapping | Allocate, map, or modify executable memory pages | `VirtualAllocEx`, `VirtualProtect`, `mmap`, `mprotect` | loader driven RWX memory setup | Execution / Defense Evasion |
| Process and Memory Manipulation | process_hollowing_or_image_replacement | Replace a process image or hollow a host process | `NtUnmapViewOfSection`, `SetThreadContext` | low-level injector toolchains | Defense Evasion / Execution |

### Persistence and Startup Control

| Category | Subtype | Definition | Typical APIs / syscalls | Typical Bash / CLI | ATT&CK mapping |
| --- | --- | --- | --- | --- | --- |
| Persistence and Startup Control | startup_or_logon_persistence | Trigger execution at login or session start | registry/login item/config modification interfaces | `~/.bashrc`, `~/.profile`, `reg add ... Run`, autostart files | Persistence |
| Persistence and Startup Control | service_or_daemon_persistence | Register or modify system services or daemons | `CreateService*`, service config APIs, systemd D-Bus | `sc create`, `systemctl enable`, `service` | Persistence |
| Persistence and Startup Control | scheduled_persistence | Trigger execution through scheduled jobs or timers | Task Scheduler APIs, cron APIs | `schtasks /create`, `crontab -e`, `/etc/cron.*` | Persistence |
| Persistence and Startup Control | event_triggered_persistence | Trigger execution through event subscriptions or timers | WMI subscription, LaunchAgent, systemd timer interfaces | WMI persistence, `LaunchAgents`, `systemd timer` | Persistence |
| Persistence and Startup Control | boot_chain_persistence | Modify boot chain or low-level startup components | BCD/EFI/firmware related interfaces | `bcdedit`, bootloader or EFI modification | Persistence |

### Privilege and Identity Manipulation

| Category | Subtype | Definition | Typical APIs / syscalls | Typical Bash / CLI | ATT&CK mapping |
| --- | --- | --- | --- | --- | --- |
| Privilege and Identity Manipulation | identity_switch | Switch execution to another user or account | `LogonUser`, `CreateProcessAsUser`, `setuid`, `seteuid` | `su`, `sudo`, `runas`, `newgrp` | Privilege Escalation |
| Privilege and Identity Manipulation | privilege_adjustment | Modify token, privilege, or capability boundaries | `AdjustTokenPrivileges`, `capset`, `setresuid` | `sudo`, `setcap`, `chmod u+s` | Privilege Escalation |
| Privilege and Identity Manipulation | token_or_session_impersonation | Duplicate, impersonate, or inherit another security context | `DuplicateTokenEx`, `ImpersonateLoggedOnUser` | privilege or session reuse tooling | Privilege Escalation / Defense Evasion |
| Privilege and Identity Manipulation | group_or_acl_modification | Modify groups, ACLs, capabilities, or authorization relations | ACL and permission modification APIs | `usermod -aG`, `net localgroup`, `setfacl`, `setcap` | Privilege Escalation / Persistence |
| Privilege and Identity Manipulation | boundary_bypass | Bypass UAC, container, or policy boundaries | UAC or namespace/cgroup boundary interfaces | `pkexec`, container escape command chains | Privilege Escalation |

### Credential and Secret Access

| Category | Subtype | Definition | Typical APIs / syscalls | Typical Bash / CLI | ATT&CK mapping |
| --- | --- | --- | --- | --- | --- |
| Credential and Secret Access | password_or_hash_access | Access passwords, hashes, or cached authentication material | LSA/SSPI interfaces, `CryptUnprotectData`, PAM/Keyring APIs | `cat /etc/shadow`, dump cached credentials | Credential Access |
| Credential and Secret Access | session_or_token_access | Obtain cookies, session tokens, Kerberos, or NTLM material | browser storage, credential manager, ticket interfaces | read browser DB, cookie store, ticket cache | Credential Access |
| Credential and Secret Access | private_key_or_api_key_access | Access, export, or copy key material | certificate store, Keychain, OpenSSL APIs | `security dump-keychain`, `gpg --export-secret-keys`, `find ~/.ssh` | Credential Access |
| Credential and Secret Access | credential_decryption | Decrypt locally stored authentication material | DPAPI, Keychain Services, vault APIs | `openssl pkcs12`, keyring decryption helpers | Credential Access |
| Credential and Secret Access | authentication_input_capture | Intercept keyboard, form, or authentication input | keyboard hook, IME, window message interfaces | keylogger, proxy script, input hook | Credential Access / Collection |

### Host and Environment Discovery

| Category | Subtype | Definition | Typical APIs / syscalls | Typical Bash / CLI | ATT&CK mapping |
| --- | --- | --- | --- | --- | --- |
| Host and Environment Discovery | system_and_hardware_discovery | Enumerate OS, architecture, patches, hardware, timezone | `uname`, `sysctl`, `NtQuerySystemInformation` | `uname -a`, `hostname`, `lscpu`, `lsblk`, `dmidecode` | Discovery |
| Host and Environment Discovery | identity_and_account_discovery | Enumerate current user, accounts, groups, privileges | `NetUserEnum`, account and directory APIs | `whoami`, `id`, `net user`, `getent passwd` | Discovery |
| Host and Environment Discovery | process_and_service_discovery | Enumerate processes, services, modules, tasks | `CreateToolhelp32Snapshot`, `EnumServicesStatusEx` | `ps aux`, `tasklist`, `systemctl list-units`, `sc query` | Discovery |
| Host and Environment Discovery | network_and_neighbor_discovery | Enumerate interfaces, routes, connections, neighbors | `getifaddrs`, socket/ioctl network APIs | `ip a`, `ip route`, `ifconfig`, `ss -tulpn`, `arp -a` | Discovery |
| Host and Environment Discovery | domain_or_org_discovery | Enumerate domain, directory service, shares, organization data | LDAP/AD/WMI/NetAPI | `net group /domain`, `nltest`, LDAP queries | Discovery |
| Host and Environment Discovery | security_environment_discovery | Enumerate AV/EDR/policy/virtualization/container/cloud environment | security product enumeration and metadata access | `ps`, `grep`, `systemctl`, cloud metadata access, container checks | Discovery |

### File and Data Access

| Category | Subtype | Definition | Typical APIs / syscalls | Typical Bash / CLI | ATT&CK mapping |
| --- | --- | --- | --- | --- | --- |
| File and Data Access | file_enumeration_and_location | Search, list, or filter sensitive files and directories | `FindFirstFile`, `readdir`, `glob` | `find`, `locate`, `grep -R`, `fd` | Collection / Discovery |
| File and Data Access | content_read_and_parse | Read files, configs, databases, or logs | `CreateFile`, `ReadFile`, `open/read`, DB APIs | `cat`, `less`, `head`, `tail`, `sqlite3`, `jq` | Collection |
| File and Data Access | bulk_copy_and_archive | Copy, sync, package, or compress data in bulk | `CopyFile`, archive libraries or APIs | `cp`, `rsync`, `tar`, `zip`, `7z` | Collection / Exfiltration |
| File and Data Access | config_or_metadata_modification | Modify permissions, attributes, configs, or metadata | `WriteFile`, `chmod`, `chown`, `SetFileTime` | `sed -i`, `chmod`, `chown`, `touch -t` | Defense Evasion / Impact |
| File and Data Access | deletion_or_overwrite | Delete, truncate, or overwrite files | `DeleteFile`, `unlink`, `ftruncate` | `rm`, `truncate`, `shred` | Impact |

### Network and Remote Communication

| Category | Subtype | Definition | Typical APIs / syscalls | Typical Bash / CLI | ATT&CK mapping |
| --- | --- | --- | --- | --- | --- |
| Network and Remote Communication | outbound_connection | Initiate outbound network connections or sessions | `connect`, WinHTTP, WinINet, libcurl | `curl`, `wget`, `nc`, `openssl s_client` | Command and Control / Exfiltration |
| Network and Remote Communication | listener_and_receive | Bind, listen, and receive inbound connections | `bind`, `listen`, `accept`, socket APIs | `nc -l`, `socat`, custom listener | Command and Control |
| Network and Remote Communication | tunneling_and_forwarding | Create port forwarding, reverse tunnels, or SOCKS paths | socket/SSH/TLS tunnel interfaces | `ssh -L/-R/-D`, `socat`, `sshuttle` | Command and Control / Lateral Movement |
| Network and Remote Communication | proxy_or_route_manipulation | Modify proxies, routes, or forwarding behavior | network stack configuration APIs | `proxychains`, `iptables`, `nft`, `route`, `ip rule` | Command and Control / Defense Evasion |
| Network and Remote Communication | protocol_encapsulation_or_encrypted_comm | Use TLS, HTTP, DNS, or similar protocols as communication wrappers | TLS/HTTP/DNS libraries | `curl https://`, `dig`, custom DNS/HTTPS channels | Command and Control |
| Network and Remote Communication | traffic_capture_and_observation | Sniff or observe network traffic contents | pcap interfaces, raw sockets | `tcpdump`, `tshark`, `ngrep` | Credential Access / Discovery |

### Lateral Movement and Remote Execution

| Category | Subtype | Definition | Typical APIs / syscalls | Typical Bash / CLI | ATT&CK mapping |
| --- | --- | --- | --- | --- | --- |
| Lateral Movement and Remote Execution | remote_login | Authenticate to another host or environment | SSH/RDP/WinRM/SMB related APIs | `ssh`, `mstsc`, `winrs`, `smbclient` | Lateral Movement |
| Lateral Movement and Remote Execution | remote_command_execution | Execute commands or scripts on another host | WMI, WinRM, SSH exec, RPC | `ssh host cmd`, `wmic /node`, `Invoke-Command`, `psexec` | Lateral Movement |
| Lateral Movement and Remote Execution | remote_file_transfer | Transfer payloads or data between hosts | SMB/SFTP/SCP/object storage APIs | `scp`, `sftp`, `rsync`, `copy \\\\host\\share` | Lateral Movement / Exfiltration |
| Lateral Movement and Remote Execution | remote_management_abuse | Abuse admin or orchestration channels for control | SCM/WMI/Ansible/remote management APIs | `ansible`, `salt`, `pdsh`, `sc \\\\host`, `wmic` | Lateral Movement |
| Lateral Movement and Remote Execution | cluster_or_cloud_node_control | Control containers, pods, instances, or orchestration nodes | Kubernetes/Docker/SSM APIs | `kubectl exec`, `kubectl cp`, `docker exec`, `aws ssm send-command` | Lateral Movement |

### Defense Evasion and Anti-Forensics

| Category | Subtype | Definition | Typical APIs / syscalls | Typical Bash / CLI | ATT&CK mapping |
| --- | --- | --- | --- | --- | --- |
| Defense Evasion and Anti-Forensics | security_tool_impairment | Stop, disable, uninstall, or bypass AV/EDR/agent tooling | service control and security policy APIs | `systemctl stop`, `sc stop`, Defender/AV config changes | Defense Evasion |
| Defense Evasion and Anti-Forensics | logging_or_audit_suppression | Clear, disable, or suppress logs and auditing | ETW/logging/audit APIs | `wevtutil cl`, `journalctl --vacuum`, `auditctl -e 0` | Defense Evasion |
| Defense Evasion and Anti-Forensics | policy_or_access_control_weakening | Disable firewall, SELinux, AppArmor, UAC, or similar controls | firewall and policy config APIs | `ufw disable`, `iptables -F`, `setenforce 0` | Defense Evasion |
| Defense Evasion and Anti-Forensics | artifact_cleanup_or_timestomp | Delete traces, clear history, or alter timestamps | `SetFileTime`, file metadata APIs | `history -c`, `unset HISTFILE`, `rm ~/.bash_history`, `touch -t` | Defense Evasion |
| Defense Evasion and Anti-Forensics | object_hiding_or_visibility_evasion | Hide files, tasks, modules, processes, or mount points | object attribute/namespace/driver interfaces | hidden files, mount namespace isolation, directory masquerade | Defense Evasion |

### Impact and Destruction

| Category | Subtype | Definition | Typical APIs / syscalls | Typical Bash / CLI | ATT&CK mapping |
| --- | --- | --- | --- | --- | --- |
| Impact and Destruction | data_destruction | Delete, overwrite, or corrupt data | raw writes, bulk delete or overwrite APIs | `rm -rf`, `shred`, `dd if=/dev/zero` | Impact |
| Impact and Destruction | data_encryption_or_locking | Encrypt files, volumes, or configs to deny access | encryption libraries, bulk rewrite APIs | `openssl enc`, `gpg`, ransomware-style batch rewrites | Impact |
| Impact and Destruction | recovery_impairment | Remove backups, snapshots, or recovery paths | volume and snapshot interfaces | `vssadmin delete shadows`, `wbadmin delete`, backup deletion | Impact |
| Impact and Destruction | availability_disruption | Stop critical services, shut down systems, or exhaust resources | service control and shutdown APIs | `shutdown`, `reboot`, `kill -9`, fork bomb | Impact |
| Impact and Destruction | boot_or_low_level_destruction | Damage bootloader, partitions, firmware, or kernel config | BCD/EFI/raw disk interfaces | `bcdedit`, `dd` to MBR/EFI, `mkfs` | Impact |

## Primitive Taxonomy

Primitive taxonomy does not redefine the behavior classes above.
Primitive compilation only adds concrete operands, targets, logical objects, and object relations for evidence facts.

### Primitive responsibilities

For every sensitive operation, primitives should capture:

- concrete operand or target object
- logical object identity
- object binding role
- cross-artifact resolution
- same-object relation
- source-to-sink or enablement relation when available

### Typical primitive binding targets

- command string or executable path
- script body or remote script URL
- module, package, plugin, or skill identifier
- endpoint, channel, or remote host
- credential object, token, key, cookie, certificate
- file path, directory path, archive, backup, snapshot
- account, role, policy, service, startup hook, cron entry
- process id, process image, memory region, thread target
- cluster, pod, container, instance, remote node

## Reasoning Taxonomy

Reasoning consumes primitive facts and object relations to infer final security consequences.

### Reasoning classes

- `Execution_and_Delivery`
- `Persistence`
- `Privilege_Escalation_and_Identity_Abuse`
- `Injection_and_Covert_Residency`
- `Information_Theft`
- `Command_and_Control`
- `Lateral_Movement`
- `Defense_Evasion_and_Anti_Forensics`
- `Destruction_and_Ransomware`

### Reasoning principle

Reasoning should link:

- object identity
- operand equality or resolution
- source/sink relations
- same-object relations
- enabling relations
- taint or data-flow relations

to infer final malicious consequences.

## Working Rules

- New evidence extraction work must map into the `Evidence Taxonomy` above.
- Primitive compilation should only add concrete operands and object identity; it should not invent a parallel top-level behavior taxonomy.
- Reasoning rules should be written against object-linked primitive chains, not raw text snippets or producer-specific semantics.
- If taxonomy changes, update this file, `PLANS.md`, and `AGENTS.md` in the same change.
