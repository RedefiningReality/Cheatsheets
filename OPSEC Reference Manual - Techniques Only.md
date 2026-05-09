# Privilege Escalation: Local Admin to SYSTEM

## P1. Service Abuse

### P1.1 Creation

1. **P1.1.1** `CreateServiceW`, `StartServiceW`

### P1.2 Hijack

1. **P1.2.1** Overwrite Service Executable
    - Requirements: write access to binary directory
2. **P1.2.2** Reconfigure Service: `ChangeServiceConfigW`

## P2. Scheduled Task Abuse

### P2.1 Creation

1. **P2.1.1** `ITaskService::NewTask`, `ITaskFolder::RegisterTaskDefinition` with principal `S-1-5-18`

### P2.2 Hijack

1. **P2.2.1** `ITaskFolder::GetTask`, `IRegisteredTask::get_Definition`, `IExecAction::put_Path`, `IRegisteredTask::put_Definition`
2. **P2.2.2** Overwrite XML in `C:\Windows\System32\Tasks\<task>`
    - Requirements: write access to task definition file

## P3. Token Impersonation

- Requirements: SeDebugPrivilege (enable via `AdjustTokenPrivileges`)

### P3.1 Token Duplication

1. **P3.1.1** `OpenProcess`, `OpenProcessToken`, `DuplicateTokenEx`

### P3.2 Token Application

1. **P3.2.1** `ImpersonateLoggedOnUser` (current thread, no new process)
2. **P3.2.2** `CreateProcessWithTokenW` (new process)
    - Requirements: SeImpersonatePrivilege
3. **P3.2.3** `CreateProcessAsUserW` (new process)
    - Requirements: SeAssignPrimaryTokenPrivilege + SeIncreaseQuotaPrivilege

## P4. Named Pipe Impersonation

- Requirements: SeImpersonatePrivilege (held by admins in high IL)

1. **P4.1** `CreateNamedPipe`, `ConnectNamedPipe`, `ImpersonateNamedPipeClient`

## P5. Registry Autoruns Targeting SYSTEM Contexts

1. **P5.1** Set `HKLM\...\Image File Execution Options\<exe>\Debugger` (trigger: invocation of `<exe>`, e.g. `sethc.exe` from login screen)
2. **P5.2** Set `HKLM\...\Winlogon\Userinit` or `Shell` (trigger: user logon)
3. **P5.3** Set `HKLM\...\Windows NT\CurrentVersion\Windows\AppInit_DLLs`

## P6. Driver Load

- Requirements: kernel code execution via vulnerable or malicious driver

1. **P6.1** `CreateServiceW` with `SERVICE_KERNEL_DRIVER`, `StartServiceW`, locate `EPROCESS`, swap token with SYSTEM process token

---

# Credential Dumping: LSASS Process

## L1. Userland

### Model

1. Handle Acquisition
2. Process Cloning (optional)
3. Obtain Memory or WerFault Trigger

### L1.1 Handle Acquisition

1. **L1.1.1** Open Directly: `OpenProcess`
    - Requirements: SeDebugPrivilege or SYSTEM, no PPL
2. **L1.1.2** Duplicate Handle: `DuplicateHandle`
    - Requirements: process that holds an LSASS handle, SeDebugPrivilege
3. **L1.1.3** Seclogon RPC: `SeclCreateProcessWithLogonW`
    - Requirements: secondary logon service running, no PPL

### L1.2 Process Cloning (optional)

1. **L1.2.1** `PssCaptureSnapshot`

### L1.3 Obtain Memory

1. **L1.3.1** Export Memory to File: `MiniDumpWriteDump`
2. **L1.3.2** Read Memory: `ReadProcessMemory`

### L1.4 WerFault Trigger

1. **L1.4.1** `GetProcAddress`, `RtlReportSilentProcessExit`
2. **L1.4.2** `GetProcAddress`, `CreateRemoteThread`

## L2. Kernel

- Requirements: kernel code execution via vulnerable or malicious driver

### L2.1 Memory Access Primitives

1. **L2.1.1** `MmCopyVirtualMemory` / `ZwReadVirtualMemory` / `KeStackAttachProcess`

---

# Credential Dumping: SAM & LSA Secrets

## S1. Local

### S1.1 Registry

1. **S1.1.1** Export Hive to Disk: `RegSaveKeyEx`
    - Requirements: SeBackupPrivilege (attainable as local admin)
2. **S1.1.2** Read Registry: `RegEnumKeyEx`, `RegEnumValueEx`, `RegQueryValueEx`
    - Requirements: SYSTEM token

### S1.2 Volume Shadow Copy

1. **S1.2.1** Direct Call: `CreateVssBackupComponents`
2. **S1.2.2** WMI: `IWbemServices::ExecMethod` `Win32_ShadowCopy.Create`

### S1.3 Direct Volume Access

1. **S1.3.1** `CreateFile`, `DeviceIoControl`, `SetFilePointerEx`, `ReadFile`

## S2. Remote

### S2.1 Registry

1. **S2.1.1** Export Hive to Disk: MS-RRP `BaseRegSaveKey` (secdump)
2. **S2.1.2** Read Registry: MS-RRP `BaseRegEnumKey`, `BaseRegEnumValue`, `BaseRegQueryValue` (regdump)

---

# Credential Dumping: Ticket Dumping

## T1. Windows LSA (live API)

### Model

1. LSA Handle Acquisition
2. Logon Session Enumeration (cross-LUID only)
3. Ticket Query
4. Ticket Retrieval

### T1.1 LSA Handle Acquisition

1. **T1.1.1** Current LUID: `LsaConnectUntrusted`
    - Requirements: none (any user)
2. **T1.1.2** All LUIDs: `LsaRegisterLogonProcess`
    - Requirements: SeTcbPrivilege (admin only)

### T1.2 Logon Session Enumeration (optional)

1. **T1.2.1** `LsaEnumerateLogonSessions`, `LsaGetLogonSessionData`

### T1.3 Ticket Query

1. **T1.3.1** `LsaCallAuthenticationPackage`, `KerbQueryTicketCacheMessage`
2. **T1.3.2** `LsaCallAuthenticationPackage`, `KerbQueryTicketCacheExMessage`

### T1.4 Ticket Retrieval

1. **T1.4.1** `LsaCallAuthenticationPackage`, `KerbRetrieveEncodedTicketMessage`
2. **T1.4.2** `LsaCallAuthenticationPackage`, `KerbRetrieveTicketMessage`

## T2. Windows LSASS Memory

- Requirements: handle to LSASS (live) or pre-existing LSASS dump (see [L1.3 Obtain Memory](#l13-obtain-memory))

### Model

1. Acquire LSASS memory access (handle or dump)
2. Locate Kerberos package structures
3. Parse ticket entries and session keys

### T2.1 Live Memory Read

- `L1.1.1 → L1.3.2`

### T2.2 Offline Dump Parse

- `L1.3.1`, parse offline

---

# Credential Dumping: NTDS.dit

## D1. Local

See [S1.2 Volume Shadow Copy](#s12-volume-shadow-copy) and [S1.3 Direct Volume Access](#s13-direct-volume-access)

## D2. Remote

1. **D1** DCSync: MS-DRSR `DRSGetNCChanges`

---

# Keylogging

## K1. Global Hook

1. `SetWindowsHookEx` (`WH_KEYBOARD_LL` or `WH_KEYBOARD`), `CallNextHookEx`
    - Requirements: DLL injectable into target processes
    - Note: `WH_KEYBOARD_LL` runs in hook-installing process, `WH_KEYBOARD` requires DLL injection per target process

## K2. Polling

1. `GetAsyncKeyState` / `GetKeyState` / `GetKeyboardState`
    - Note: low fidelity - misses rapid keystrokes, no window context

## K3. Raw Input

1. `RegisterRawInputDevices` `RIDEV_INPUTSINK`, `GetRawInputData` via `WM_INPUT`
    - Requirements: window with message loop in target session

---

# Packet Capture

- Requirements: local admin

## C1. NDIS Packet Capture (ETW)

1. `EnableTraceEx2` `Microsoft-Windows-NDIS-PacketCapture`

## C2. PktMon (ETW)

1. `EnableTraceEx2` `Microsoft-Windows-PktMon`

## C3. Raw Sockets

1. `WSASocket` (`AF_INET, SOCK_RAW`), `bind`, `WSAIoctl` (`SIO_RCVALL`), `recv` / `recvfrom`
    - Note: captures IP traffic addressed to local host only (not promiscuous)

## C4. NDIS Filter Driver (Kernel)

1. Custom NDIS filter/miniport driver or Npcap/WinPcap kernel driver
    - Requirements: kernel code execution or signed driver

---

# Host Lateral Movement

## Background

### Transports

- TCP/135 + dynamic high port
- SMB (TCP/445) - IPC$ exposes named pipes
- WinRM (TCP/5985, TCP/5986)
- RDP (TCP/3389)

### MS-RPC (TCP/135 or SMB named pipe)

- SCMR: create scheduled task
- TSCH: create service
- WMI: query class (recon) or spawn a process
- DCOM: invoke methods on COM objects: eg. MMC20, ShellWindows, Excel

### Opportunities for Detection

1. remote access protocols and transports
2. authentication type
    - local account — expected: domain account
    - domain account w/ NTLM — expected: Kerberos
    - domain account w/ Kerberos — ticket anomalies (eg. weak encryption, pass-the-ticket)
3. attempted access across multiple hosts in short timeframe

## M1. Service Control Manager (MS-SCMR)

- Transports: TCP/445 (`\PIPE\svcctl`), TCP/135 + dynamic
- Requirements: local admin, service binary present or `lpBinaryPathName` set to `cmd /c` command line

1. **M1.1** Create Service: `ROpenSCManagerW`, `RCreateServiceW`, `RStartServiceW`
2. **M1.2** Hijack Service: `ROpenSCManagerW`, `ROpenServiceW`, `RQueryServiceConfigW`, `RChangeServiceConfigW`, `RStartServiceW`
    - Requirements: writable service exists

## M2. Task Scheduler (MS-TSCH)

- Transports: TCP/445 (`\PIPE\atsvc`), TCP/135 + dynamic
- Requirements: local admin

1. **M2.1** Create Task: `SchRpcRegisterTask` with near-immediate `TimeTrigger`, `DeleteExpiredTaskAfter`
2. **M2.2** Create and Run Task: `SchRpcRegisterTask`, `SchRpcRun`, `SchRpcDelete`
    - Note: permits user session hijacking via `TASK_RUN_USE_SESSION_ID` in `SchRpcRun`
3. **M2.3** Hijack Task: `SchRpcRetrieveTask`, modify `IExecAction`, `SchRpcRegisterTask` (overwrite), `SchRpcRun`
    - Note: permits user session hijacking via `TASK_RUN_USE_SESSION_ID` in `SchRpcRun`

## M3. Windows Management Instrumentation (MS-WMI over DCOM)

- Transports: TCP/135 + dynamic
- Requirements: local admin, DCOM inbound allowed

1. **M3.1** Create Process: `IWbemServices::ExecMethod` `Win32_Process.Create`
2. **M3.2** Event Subscription: `IWbemServices::PutInstance` creating `__EventFilter` + `CommandLineEventConsumer` + `__FilterToConsumerBinding`

## M4. DCOM Object (MS-DCOM)

- Transports: TCP/135 + dynamic
- Requirements: local admin, DCOM inbound allowed

1. **M4.1** MMC20: `MMC20.Application`; `Document.ActiveView.ExecuteShellCommand`
2. **M4.2** ShellWindows: `ShellWindows`; `Document.Application.ShellExecute`
    - Requirements: active Explorer shell (fails on Server Core)
3. **M4.3** ShellBrowserWindow: `ShellBrowserWindow`; `Document.Application.ShellExecute`
    - Requirements: active Explorer shell (fails on Server Core)
4. **M4.4** Excel: `Excel.Application`; `RegisterXLL` or `Workbooks.Open`, `Run`
    - Requirements: Excel installed
5. **M4.5** HTA: `htafile`; `IPersistMoniker::Load` with attacker URL moniker
    - Requirements: reachable attacker URL
6. **M4.6** Visual Studio: `VisualStudio.DTE.<ver>`; `ExecuteCommand`
    - Requirements: Visual Studio installed

## M5. Windows Remote Management (WS-Man)

- Transports: TCP/5985 HTTP, TCP/5986 HTTPS
- Requirements: WinRM enabled on target, user in `Remote Management Users` or local admin

1. **M5.1** cmd shell (MS-WSMV): WS-Man `Create` `Windows/Shell/cmd`, `Command` & `Receive`
2. **M5.2** PowerShell remoting (MS-PSRP): WS-Man `Create` `Microsoft.PowerShell`, `Send` & `Receive`

## M6. Remote Desktop Protocol (MS-RDPBCGR)

- Transports: TCP/3389
- Requirements: RDP enabled on target, user in `Remote Desktop Users` or local admin

1. **M6.1** Interactive Logon: RDP session connect, user logon, shell via input/output virtual channels
    - Note: `alternateShell` in Client Info PDU auto-runs a command at session start
2. **M6.2** Keystroke Injection: `TS_INPUT_PDU`
3. **M6.3** Session Hijack: `WinStationConnect`
    - Note: executed locally on target host, not a remote technique
    - Requirements: SYSTEM or session owner credentials
