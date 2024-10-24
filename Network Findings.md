## Information Gathering

### Host Discovery
```sh
sudo nmap -PE -sn -iL ranges.txt -oA ping
nmap -n -Pn -T4 --min-hostgroup 128 --max-retries 0 --top-ports 50 -iL ranges.txt -oA tcp-discovery
sudo nmap -n -Pn --min-hostgroup 128 -sU -p 53,69,111,123,161,514,1900 -iL ranges.txt -oA udp
```

```sh
grep Up ping.gnmap | cut -d ' ' -f 2 > live-ping.txt
grep 'open/' tcp-discovery.gnmap | cut -d ' ' -f 2 > live-tcp.txt
grep 'open/' udp.gnmap | cut -d ' ' -f 2 > live-udp.txt

sort -uV live-ping.txt live-tcp.txt live-udp.txt > live.txt
shuf -n <num> live.txt | sort -uV > targets.txt
```
### Service Scan
```sh
sudo nmap -n -Pn --min-hostgroup 128 --max-retries 0 -p- -sV -O -iL ranges.txt -oA tcp-full
```

```sh
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
nmap -Pn -p <port> --script vmware-version <target>
```
## Services

### Terminal Access
#### SSH (22)
- default password
- weak password
- weak encryption

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
5. on failure, `Ctrl+]` followed by `quit`
If the service hangs, `Ctrl+C`, edit temp.txt, remove all hosts up to and including the offending host.

**Weak Password**
```sh
echo -en "root\nadmin" > usernames.txt
echo -en "\nroot\nadmin\npassword" > passwords.txt
hydra -M telnet.txt -L usernames.txt -P passwords.txt telnet -t 4
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

**Default Password**
I don't check for default passwords on FTP because this is usually covered by other services.

**Weak Password**
```sh
echo -en "root\nadmin" > usernames.txt
echo -en "\nroot\nadmin\npassword" > passwords.txt
hydra -M ftp.txt -L usernames.txt -P passwords.txt ftp -t 4
```

**Insecure Protocol**
```sh
sed 's/$/ (tcp/21)/' ftp.txt
# copy-and-paste to affected hosts
```
#### SMB (139/445)
- null session (blank username, blank password)
- guest session (username Guest, no password)
- default password - only special cases like printers or IoT devices
- weak password - tied to Active Directory on domain-joined machines
- known CVEs
- insecure protocol (SMBv1)
- signing not required
- excessive share or NTFS ACLs
#### NFS (2049)
- publicly mountable shares
- share enumeration
### Database

#### MSSQL (1433)
- default/weak password (unauth)
- weak password (auth)
- impersonation
- linked servers
- excessive login permissions
- sysadmin
- server account NTLM relay
#### Oracle (1521)
- default/weak password
#### MySQL (3306)
- default/weak password
#### PostgreSQL (5432)
- default/weak password
#### Redis (6379)\
- default/weak password
### Other
#### SMTP (25/587)
- open relay
- lack of sender validation
- insecure protocol
#### SNMP (udp/161)
- default RW community string
- default RO community string
- insecure protocol
#### RDP (3389)
- known CVEs
- weak encryption
#### Cisco
- Cisco Smart Install
- type 7 encryption
- exposed community strings