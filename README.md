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
