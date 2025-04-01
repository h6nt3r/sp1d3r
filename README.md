### Required tools
https://github.com/lc/gau

https://github.com/projectdiscovery/urlfinder

https://github.com/tomnomnom/anew

https://github.com/tomnomnom/qsreplace

https://github.com/Emoe/kxss

## Installation
```
wget "https://raw.githubusercontent.com/h6nt3r/bugs/refs/heads/main/bugs.sh"
sudo chmod +x ./bugs.sh
./bugs.sh
```
## Usage
```
./bugs.sh -d "http://testphp.vulnweb.com"
```
```
./bugs.sh -l "http://testphp.vulnweb.com"
```
#### RXSS ready urls
```
cat bug_bounty/domain.com/multi_domain/recon/all_urls_rxss.txt |  grep -av "\\[]" | awk '{print $2}' | anew | tee bug_bounty/domain.com/multi_domain/recon/rxss_only_urls.txt
```
#### pdf read
```
cat recon/all_extension_urls.txt | grep -aEi '\.pdf$' | while read -r url; do curl -s "$url" | pdftotext -q - - 2>/dev/null | grep -Eaiq '(internal use only|confidential|strictly private|personal & confidential|private|restricted|internal|not for distribution|do not share|proprietary|trade secret|classified|sensitive|bank statement|invoice|salary|contract|agreement|non disclosure|passport|social security|ssn|date of birth|credit card|identity|id number|company confidential|staff only|management only|internal only|shareholder information|Members Only)' && echo "$url"; done
```
#### backup and database read
```
cat recon/all_extension_urls.txt | grep -aiE '\.(zip|tar\.gz|tgz|7z|rar|gz|bz2|xz|lzma|z|cab|arj|lha|ace|arc|iso|db|sqlite|sqlite3|db3|sql|sqlitedb|sdb|sqlite2|frm|mdb|accdb|bak|backup|old|sav|save)$'
```
#### microsoft document
```
cat recon/all_extension_urls.txt | grep -aiE '\.(doc[xm]?|dot[xm]?|xls[xmb]?|xlt[xm]?|ppt[xm]?|pot[xm]?|pps[xm]?|mdb|accd[be]|adp|accdt|pub|puz|one(pkg)?)$'
```
#### All JS files
```
cat recon/all_extension_urls.txt | grep -aiE '\.(config|credentials|secrets|keys|password|api_keys|auth_tokens|access_tokens|sessions|authorization|encryption|certificates|ssl_keys|passphrases|policies|permissions|privileges|hashes|salts|nonces|signetures|digests|tokens|cookies|topsecr3tdotnotlook)\.js$'
```
