# Printing Tricks
*aka Useful Commands for Working with Output*

## Linux Terminal

#### Searching: `grep`
`… | grep [contents]` or `grep [contents] [file]` ⇒ only show lines with `[contents]`
- `-v [contents]` ⇒ only show lines *without* `[contents]`
- `\|` in `[contents]` is an or
- `-E` or `egrep` allows regex in `[contents]`
  - `|` can be used without backslash
  - `^[start]` ⇒ only show lines that start with `[start]`
  - `[end]$` ⇒ only show lines that end with `[end]`
- `-i` ⇒ ignore case
- `-B [num]` ⇒ show `[num]` lines before line
- `-A [num]` ⇒ show `[num]` lines after line

Common Use Cases
- `grep -Horn [contents] [dir]` ⇒ recursively search `[dir]` for files containing `[contents]`
  - `-Hrn` (without the `o`) ⇒ display text surrounding `[contents]` as well as filename
- `… | egrep -v '^$'` ⇒ remove blank lines
- `grep '[port]/open/' [nmap scan].gnmap` ⇒ get hosts with open port `[port]`
- `grep '[script contents]' [nmap scan].nmap -B [num] | grep 'report for'` ⇒ get hosts with specific contents in script results
  - useful for SMBv1 or SMB signing checks
  - first try without `grep 'report for'` and play around with `-B [num]` to get the right number of lines

https://www.cyberciti.biz/faq/grep-regular-expressions/

#### Cutting and Replacing: `cut`, `tr`, and `sed`
`… | cut -d [delimiter] -f [field]` or `cut -d [delimiter] -f [field] [file]` ⇒ get `[field]` field from each line after cutting it with `[delimiter]`

`… | tr [original] [new]` or `tr [original] [new] [file]` ⇒ replace corresponding character in `[original]` with character in same position in new `[new]`
- `-d [chars]` ⇒ delete all instances of every character in `[chars]`
- `-s [chars]` ⇒ (squash) remove repeats for each character in `[chars]`

`… | sed 's/[original]/[new]/g'` or `sed 's/[original]/[new]/g' [file]` ⇒ replace all `[original]` with `[new]` in terminal output
- `sed -i 's/[original]/[new]/g' [file]` ⇒ replace all `[original]` with `[new]` in `[file]`

Common Use Cases
- `… | tr [a-z] [A-Z]` ⇒ make text uppercase
- `… | tr -s ' ' | cut -d ' ' -f [field]` ⇒ get `[field]` but account for contiguous spaces
  - `netexec [protocol] [targets] -u [user] -p [password] | grep '[+]' | tr -s ' ' | cut -d ' ' -f 2` ⇒ get IP addresses of hosts you have valid creds for
- `grep 'open/' [nmap scan].gnmap | cut -d ' ' -f 2` ⇒ get IP addresses of live hosts (having at least one port open)

#### Sorting: `sort` and `uniq`
`… | sort` or `sort [file]` ⇒ sort lines in alphabetical order
- `-u` ⇒ remove duplicates (similar to `… | sort | uniq`)
- `-V` ⇒ sort by version number - great for IPv4 addresses

`… | uniq` ⇒ unique (only display consecutive duplicate lines once)
- `… | sort | uniq` ⇒ remove ALL (not just consecutive) duplicate lines

Common Use Cases
- `cat [ip lists] | sort -uV > ips.txt` ⇒ combine multiple lists of IPv4 addresses
- `sort -u [hash list] > hashes.txt` ⇒ remove duplicate hashes from hashlist
- `grep '(' [nmap scan].gnmap | grep -v '()' | cut -d '(' -f 2 | cut -d ')' -f 1 | sort -u > dns.txt` ⇒ retrieve sorted domain names from nmap scan

#### Viewing and Saving to File: `more`/`less`, `tee`, `base64`, and redirection
- `… | more` or `more [file]` ⇒ scrollable output
- `… | less` or `less [file]` ⇒ scrollable output in vim-like viewer
  - press `/` then enter pattern to search
- `… | base64` or `base64 [file]` ⇒ base64 encode
  - `-d` ⇒ base64 decode instead
  - `-i` ⇒ ignore non-alphabet characters

Common Use Cases
- `set str '[powershell]' ; echo -en $str | iconv -t UTF-16LE | base64 -w 0` ⇒ base64 encode Windows PowerShell command
- `cat [script].ps1 | iconv -t UTF-16LE | base64 -w 0` ⇒ base64 encode Windows PowerShell script

#### Redirection
##### Streams
*technically File Descriptors*
- `0` ⇒ input (stdin)
- `1` ⇒ output (stdout)
- `2` ⇒ errors (stderr)
- not specified ⇒ defaults to `1`

##### Redirection
- `… [stream]>[file]` ⇒ overwrite file
  - `… [stream]>>[file]` ⇒ append to file
- `… [stream]<[file]` ⇒ read from file
- `… [stream1]>&[stream2]` ⇒ redirect one stream to another

Common Use Cases
- `… >[file]` ⇒ write output to file
- `… 2>&1` ⇒ treat errors as output
  - `… 2>&1 >[file]` ⇒ write to file, including errors
- `… [stream]>/dev/null` ⇒ don't show stream
  - `… 2>/dev/null` ⇒ don't show errors
- input multiple lines of text to command (aka here document)
```
… << EOF
[lines]
EOF
```
`… | tee [file]` ⇒ both print to standard output and write to `[file]` (think `>`)
- `-a` ⇒ append instead of overwriting (think `>>`)

https://www.geeksforgeeks.org/input-output-redirection-in-linux/
