# Printing Tricks
*aka Useful Commands for Working with Output*

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

#### Common Use Cases
- `grep -Horn [contents] [dir]` ⇒ recursively search `[dir]` for files containing `[contents]`
  - `-Hrn` (without the `o`) ⇒ display text surrounding `[contents]` as well as filename
- `… | egrep -v '^$' ⇒ remove blank lines
- `grep 'open/' [nmap scan].gnmap` ⇒ get hosts with open port
- `grep '[script contents]' [nmap scan].nmap -B [num] | grep 'report for'` ⇒ get hosts with specific contents in script results
  - useful for SMBv1 or SMB signing checks
  - first try without `grep 'report for'` and play around with `-B [num]` to get the right number of lines

https://www.cyberciti.biz/faq/grep-regular-expressions/

#### Cutting and Replacing: `cut`, `tr`, and `sed`
- `… | cut -d [delimiter] -f [field]` ⇒ get `[field]` field from each line after cutting it with `[delimiter]`
---
- `… | tr [original] [new]` ⇒ replace corresponding character in `[original]` with character in same position in new `[new]`
  - ex. `… | tr [a-z] [A-Z]` ⇒ make text uppercase
- `… | tr -d [chars]` ⇒ delete all instances of every character in `[chars]`
- `… | tr -s [chars]` ⇒ (squash) remove repeats for each character in `[chars]`
  - ex. `… | tr -s " " | cut -d " " -f [field]` ⇒ get `[field]` but account for contiguous spaces
---
- `… | sed 's/[original]/[new]/g'` or `sed 's/[original]/[new]/g' [file]` ⇒ replace all `[original]` with `[new]` in output
- `sed -i 's/[original]/[new]/g' [file]` ⇒ replace all `[original]` with `[new]` in `[file]`

#### Sorting: `sort` and `uniq`
`… | sort` or `sort [file]` ⇒ sort lines in alphabetical order
- `-u` ⇒ remove duplicates (similar to `… | sort | uniq`)
- `-V` ⇒ sort by version number - great for IPv4 addresses
`… | uniq` ⇒ unique (only display consecutive duplicate lines once)
- ex. `… | sort | uniq` ⇒ remove ALL (not just consecutive) duplicate lines

Common Use Cases
- `cat [ip lists] | sort -uV > ips.txt` ⇒ combine multiple lists of IPv4 addresses
- `sort -u [hash list] > hashes.txt` ⇒ remove duplicate hashes from hashlist
- `grep '(' [nmap scan].gnmap | grep -v '()' | cut -d '(' -f 2 | cut -d ')' -f 1 | sort -u > dns.txt` ⇒ retrieve sorted domain names from nmap scan

---
- `… | cut -d [delimiter] -f [field]` ⇒ get `[field]` field from each line after cutting it with `[delimiter]`

- `… | base64 -d` ⇒ base-64 decode output
- `… | more` or `… | less` ⇒ scrollable output
- `… | tee [file]` ⇒ both print to standard output and write to `[file]`
  - `-a` ⇒ append instead of overwriting
---
- `… | tr [original] [new]` ⇒ replace corresponding character in `[original]` with character in same position in new `[new]`
  - ex. `… | tr [a-z] [A-Z]` ⇒ make text uppercase
- `… | tr -d [chars]` ⇒ delete all instances of every character in `[chars]`
- `… | tr -s [chars]` ⇒ (squash) remove repeats for each character in `[chars]`
  - ex. `… | tr -s " " | cut -d " " -f [field]` ⇒ get `[field]` but account for contiguous spaces
---
- `… | sed 's/[original]/[new]/g'` or `sed 's/[original]/[new]/g' [file]` ⇒ replace all `[original]` with `[new]` in output
- `sed -i 's/[original]/[new]/g' [file]` ⇒ replace all `[original]` with `[new]` in `[file]`
---
https://www.geeksforgeeks.org/input-output-redirection-in-linux/
