### Required tools
https://github.com/lc/gau
https://github.com/projectdiscovery/urlfinder
https://github.com/tomnomnom/anew
https://github.com/tomnomnom/qsreplace

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
```
cat bug_bounty/domain.com/multi_domain/recon/all_urls_rxss.txt |  grep -av "\\[]" | awk '{print $2}' | anew | tee bug_bounty/domain.com/multi_domain/recon/rxss_only_urls.txt
```
#### pdf read
```
cat recon/all_extension_urls.txt | grep -aE '\.pdf' | while read -r url; do curl -s "$url" | pdftotext -q - - 2>/dev/null | grep -Eaiq '(internal use only|confidential|strictly private|personal & confidential|private|restricted|internal|not for distribution|do not share|proprietary|trade secret|classified|sensitive|bank statement|invoice|salary|contract|agreement|non disclosure|passport|social security|ssn|date of birth|credit card|identity|id number|company confidential|staff only|management only|internal only|shareholder information)' && echo "$url"; done
```
#### backup and database read
```
cat recon/all_extension_urls.txt | grep -aE '\.zip|\.tar\.gz|\.tgz|\.7z|\.rar|\.gz|\.bz2|\.xz|\.lzma|\.z|\.cab|\.arj|\.lha|\.ace|\.arc|\.iso|\.db|\.sqlite|\.sqlite3|\.db3|\.sql|\.sqlitedb|\.sdb|\.sqlite2|\.frm|\.mdb|\.accdb|\.bak|\.backup|\.old|\.sav|\.save'
```
#### microsoft document
```
cat recon/all_extension_urls.txt | grep -aE '\.doc|\.docx|\.dot|\.dotx|\.docm|\.dotm|\.xls|\.xlsx|\.xlt|\.xltx|\.xlsm|\.xltm|\.xlsb|\.ppt|\.pptx|\.pot|\.potx|\.pps|\.ppsx|\.pptm|\.potm|\.ppsm|\.mdb|\.accdb|\.mde|\.accde|\.adp|\.accdt|\.pub|\.puz|\.one|\.onepkg'
```
