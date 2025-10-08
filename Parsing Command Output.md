# Printing Tricks
*aka useful commands for parsing terminal output*

## Linux Terminal

### Searching: `grep`
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

##### Common Use Cases
- `grep -Horn [contents] [dir]` ⇒ recursively search `[dir]` for files containing `[contents]`
  - `-Hrn` (without the `o`) ⇒ display text surrounding `[contents]` as well as filename
- `… | egrep -v '^$'` ⇒ remove blank lines
- `grep '[port]/open/' [nmap scan].gnmap` ⇒ get hosts with open port `[port]`
- `grep '[script contents]' [nmap scan].nmap -B [num] | grep 'report for'` ⇒ get hosts with specific contents in script results
  - useful for SMBv1 or SMB signing checks
  - first try without `grep 'report for'` and play around with `-B [num]` to get the right number of lines

https://www.cyberciti.biz/faq/grep-regular-expressions/

### Cutting and Replacing: `cut`, `tr`, and `sed`
`… | cut -d [delimiter] -f [field]` or `cut -d [delimiter] -f [field] [file]` ⇒ get `[field]` field from each line after cutting it with `[delimiter]`

`… | tr [original] [new]` or `tr [original] [new] [file]` ⇒ replace corresponding character in `[original]` with character in same position in new `[new]`
- `-d [chars]` ⇒ delete all instances of every character in `[chars]`
- `-s [chars]` ⇒ (squash) remove repeats for each character in `[chars]`

`… | sed 's/[original]/[new]/g'` or `sed 's/[original]/[new]/g' [file]` ⇒ replace all `[original]` with `[new]` in terminal output
- `sed -i 's/[original]/[new]/g' [file]` ⇒ replace all `[original]` with `[new]` in `[file]`

##### Common Use Cases
- `… | tr [a-z] [A-Z]` ⇒ make text uppercase
- `… | tr -s ' ' | cut -d ' ' -f [field]` ⇒ get `[field]` but account for contiguous spaces
  - `netexec [protocol] [targets] -u [user] -p [password] | grep '[+]' | tr -s ' ' | cut -d ' ' -f 2` ⇒ get IP addresses of hosts you have valid creds for
- `grep 'open/' [nmap scan].gnmap | cut -d ' ' -f 2` ⇒ get IP addresses of live hosts (having at least one port open)

### Sorting: `sort` and `uniq`
`… | sort` or `sort [file]` ⇒ sort lines in alphabetical order
- `-u` ⇒ remove duplicates (similar to `… | sort | uniq`)
- `-V` ⇒ sort by version number - great for IPv4 addresses

`… | uniq` ⇒ unique (only display consecutive duplicate lines once)
- `… | sort | uniq` ⇒ remove ALL (not just consecutive) duplicate lines

##### Common Use Cases
- `sort -uV [ip lists] > ips.txt` ⇒ combine multiple lists of IPv4 addresses
- `sort -u [hash list] > hashes.txt` ⇒ remove duplicate hashes from hashlist
- `grep '(' [nmap scan].gnmap | grep -v '()' | cut -d '(' -f 2 | cut -d ')' -f 1 | sort -u > dns.txt` ⇒ retrieve sorted domain names from nmap scan

### Viewing: `more`/`less` and `base64`
- `… | more` or `more [file]` ⇒ scrollable output
- `… | less` or `less [file]` ⇒ scrollable output in vim-like viewer
  - press `/` then enter pattern to search
- `… | base64` or `base64 [file]` ⇒ base64 encode
  - `-d` ⇒ base64 decode instead
  - `-i` ⇒ ignore non-alphabet characters

##### Common Use Cases
- `set str '[powershell]' ; echo -en $str | iconv -t UTF-16LE | base64 -w 0` ⇒ base64 encode Windows PowerShell command
- `cat [script].ps1 | iconv -t UTF-16LE | base64 -w 0` ⇒ base64 encode Windows PowerShell script

### Redirection
#### Streams
*technically File Descriptors*
- `0` ⇒ input (stdin)
- `1` ⇒ output (stdout)
- `2` ⇒ errors (stderr)
- not specified ⇒ defaults to `1`

#### Redirection
- `… [stream]>[file]` ⇒ overwrite file
  - `… [stream]>>[file]` ⇒ append to file
- `… [stream]<[file]` ⇒ read from file
- `… [stream1]>&[stream2]` ⇒ redirect one stream to another

##### Common Use Cases
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

## Windows PowerShell

### Viewing: `select`, `ft`, and `fl`
`… | Get-Member` or `… | member` ⇒ see all property names (even ones not displayed by default)
- `-MemberType [type]` ⇒ properties of a specific type

`… | Select-Object -Property [prop1],[prop2]` or `… | select [prop1],[prop2]` ⇒ show values for (select) specific properties
- `-First [num]` ⇒ select the first `[num]` objects
- `-Skip [num]` ⇒ skip the first `[num]` objects
- `-Last [num]` ⇒ select the last `[num]` objects
- `-Unique` ⇒ show duplicate values only once
- `-ExpandProperty [prop]` instead of `-Property` ⇒ return items directly in an array

`… | Format-Table -Property [prop1],[prop2]` or `… | ft [prop1],[prop2]` ⇒ display in table form
- `-AutoSize` ⇒ automatically size cells to accommodate data
- `-Wrap` ⇒ wrap text that doesn't fit in a cell

`… | Format-List -Property [prop1],[prop2]` or `… | fl [prop1],[prop2]` ⇒ display in list form

Convert to Base64 (to run with `powershell -e [base64]`)
- `$str = '[powershell]' ; [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($str))` ⇒ base64 encode Windows PowerShell command
- `[System.Convert]::ToBase64String((Get-Content -Path [script].ps1 -Encoding byte))` ⇒ base64 encode Windows PowerShell script

 ### Searching: `where`
`… | Where-Object -Property [prop] -[operator] [value]` or `… | ?/where [prop] -[operator] [value]`  
- [Operators](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_comparison_operators): `-eq`, `-like`, `-match`, `-gt`, `-lt`, ...

### Sorting and Counting: `sort` and `measure`
`… | Sort-Object -Property [prop]` or `… | sort [prop]` ⇒ sort objects in order by property `[prop]`
- `-Descending` ⇒ reverse order
- `-Unique` ⇒ remove duplicates

`… | Measure-Object` or `… | measure` ⇒ count the number of objects
- `-Property [prop]` ⇒ statistics for a property

### Saving: `out-file`, `export-csv`, and `ogv`
`… | Out-File -FilePath [file]` ⇒ overwrite file (same as `>`)
- `-Append` ⇒ append to file (same as `>>`)

`… | Export-Csv -Path [file].csv` ⇒ write to csv file (for opening in excel)
- `-Append` ⇒ append to csv file
- `-NoTypeInformation` ⇒ don't include first row with property types

`… | Out-GridView` or `… | ogv` ⇒ view in interactive table

### Iterating: `foreach`
`… | ForEach-Object -Process [what to do on each iteration]` or `… | %/foreach [what to do on each iteration (process)]`
- `-Begin [before loop]`
- `-Process [each iteration]`
- `-End [after loop]`

`… | ForEach-Object -MemberName [prop]` or `… | %/foreach [prop]` ⇒ get values for specific properties
- same as `select` but doesn't change property type

### Script Block
Within a PowerShell command, use `{` and `}`. Reference the current item with `$_`
- `Get-Service | Where-Object { $_.Status -eq "Stopped" }`
- `Get-Process | ForEach-Object { $_.ProcessName }`

## AD PowerShell Module Tips & Tricks
Commandlets you should know:
```powershell
Get-ADDomain
Get-ADObject
Get-ADUser
Get-ADComputer
Get-ADGroup
Get-ADGroupMember
```
### Command Structure
A good general structure is `[initial cmdlet] | where [filter] | [format output]`
#### Initial Commandlet
- include `-Server [dc.domain.com]` if running from a machine that is not domain joined
- select a specific item with `[item]`, filter with `-Filter { <basic filter> }`, or include all items with `-Filter *` then pipe results into a more complex `where` filter
- include `-Properties [prop1],[prop2]` to pull a specific property that you can later reference with `where` or `select`
#### Filter
- for a single filter, see [Searching: where](#searching-where) above
- for multiple filters, `where { ([filter1]) -[and/or] ([filter2]) }`
#### Format Output
Choose between the following:
- display the properties you want in a list: `fl [prop1],[prop2]`
- display the properties you want in a table: `ft [prop1],[prop2] -Wrap`
- save the properties you want to a CSV file: `select [prop1],[prop2] | Export-Csv -NoTypeInformation [path].csv`
### Example
Get unconstrained delegation users
```powershell
Get-ADUser -Server $dc -Filter {TrustedForDelegation -eq $true} -Property TrustedForDelegation | ft SamAccountName,TrustedForDelegation -Wrap
```
