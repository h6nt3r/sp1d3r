#!/usr/bin/env bash
BOLD_BLUE="\033[1;34m"
RED="\033[0;31m"
NC="\033[0m"
BOLD_YELLOW="\033[1;33m"

# Function to display usage message
display_usage() {
    echo "Options:"
    echo "  -h               Display this help message"
    echo "  -d               Single domain enumeration"
    echo "  -l               Full server domains enumeration"
    echo "  -i               Check required tool installed or not."
    echo "  -c               Installing required tools"
    echo ""
    echo -e "${BOLD_YELLOW}Usage:${NC}"
    echo -e "${BOLD_YELLOW}    $0 -d https://example.com${NC}"
    echo -e "${BOLD_YELLOW}    $0 -l https://example.com${NC}"
    echo ""
    echo "Required Tools:"
    echo "              https://github.com/tomnomnom/unfurl
              https://github.com/aboul3la/Sublist3r
              https://github.com/projectdiscovery/subfinder
              https://github.com/RevoltSecurities/Subdominator
              https://github.com/projectdiscovery/httpx
              https://github.com/tomnomnom/anew
              https://github.com/projectdiscovery/urlfinder
              https://github.com/projectdiscovery/katana/releases/tag/v1.1.0
              https://github.com/lc/gau
              https://github.com/tomnomnom/waybackurls"
    exit 0
}


# Function to check installed tools
check_tools() {
    tools=("unfurl" "sublist3r" "subfinder" "subdominator" "anew" "httpx" "urlfinder" "katana" "gau" "waybackurls" "sed" "waymore" "wget" "curl" "awk" "iconv")

    echo "Checking required tools:"
    for tool in "${tools[@]}"; do
        if command -v "$tool" &> /dev/null; then
            echo -e "${BOLD_BLUE}$tool is installed at ${BOLD_WHITE}$(which $tool)${NC}"
        else
            echo -e "${RED}$tool is NOT installed or not in the PATH${NC}"
        fi
    done
}

# Check if tool installation check is requested
if [[ "$1" == "-i" ]]; then
    check_tools
    exit 0
fi

# Check if help is requested
if [[ "$1" == "-c" ]]; then
    mkdir -p --mode=777 sp1d3r
    cd sp1d3r
    sudo apt install unzip -y

    echo "anew===================================="
    wget "https://github.com/tomnomnom/anew/releases/download/v0.1.1/anew-linux-amd64-0.1.1.tgz"
    sudo tar -xzf anew-linux-amd64-0.1.1.tgz
    sudo mv anew /usr/local/bin/
    sudo chmod +x /usr/local/bin/anew
    anew -h
    sudo rm -rf ./*
    cd

    cd sp1d3r
    echo "subdominator===================================="
    cd /opt/ && sudo git clone https://github.com/RevoltSecurities/Subdominator.git
    cd Subdominator/
    sudo chmod +x ./*
    sudo pip3 install -r requirements.txt --break-system-packages
    sudo python3 setup.py install
    sudo pip3 install aiosqlite --break-system-packages
    cd
    subdominator -h

    cd sp1d3r
    echo "Sublist3r===================================="
    cd /opt/ && sudo git clone https://github.com/aboul3la/Sublist3r.git && cd Sublist3r
    sudo chmod +x *
    sudo pip3 install -r requirements.txt
    sudo python3 setup.py install
    cd
    sublist3r -h


    cd sp1d3r
    echo "subfinder===================================="
    wget "https://github.com/projectdiscovery/subfinder/releases/download/v2.8.0/subfinder_2.8.0_linux_amd64.zip"
    sudo unzip subfinder_2.8.0_linux_amd64.zip
    sudo mv subfinder /usr/local/bin/
    sudo chmod +x /usr/local/bin/subfinder
    sudo rm -rf ./*
    subfinder -h
    cd

    cd sp1d3r
    echo "urlfinder===================================="
    wget "https://github.com/projectdiscovery/urlfinder/releases/download/v0.0.3/urlfinder_0.0.3_linux_amd64.zip"
    sudo unzip urlfinder_0.0.3_linux_amd64.zip
    sudo mv urlfinder /usr/local/bin/
    sudo chmod +x /usr/local/bin/urlfinder
    sudo rm -rf ./*
    urlfinder -h
    cd

    cd sp1d3r
    echo "waymore===================================="
    cd /opt/ && sudo git clone https://github.com/xnl-h4ck3r/waymore.git && cd waymore/
    sudo chmod +x ./*
    sudo pip3 install -r requirements.txt --break-system-packages
    sudo python3 setup.py install
    cd
    waymore -h

    cd sp1d3r
    echo "gau===================================="
    wget "https://github.com/lc/gau/releases/download/v2.2.4/gau_2.2.4_linux_amd64.tar.gz"
    sudo tar -xzf gau_2.2.4_linux_amd64.tar.gz
    sudo mv gau /usr/local/bin/
    sudo chmod +x /usr/local/bin/gau
    sudo rm -rf ./*
    gau -h
    cd

    cd sp1d3r
    echo "unfurl===================================="
    wget "https://github.com/tomnomnom/unfurl/releases/download/v0.4.3/unfurl-linux-amd64-0.4.3.tgz"
    tar -xzvf unfurl-linux-amd64-0.4.3.tgz
    sudo mv unfurl /usr/local/bin/
    sudo chmod +x /usr/local/bin/unfurl
    sudo rm -rf ./*
    unfurl -h
    cd

    cd sp1d3r
    echo "httpx=================================="
    wget "https://github.com/projectdiscovery/httpx/releases/download/v1.6.10/httpx_1.6.10_linux_amd64.zip"
    sudo unzip httpx_1.6.10_linux_amd64.zip
    sudo mv httpx /usr/local/bin/
    sudo chmod +x /usr/local/bin/httpx
    sudo rm -rf ./*
    httpx -h
    cd

    cd sp1d3r
    echo "katana=================================="
    wget "https://github.com/projectdiscovery/katana/releases/download/v1.1.0/katana_1.1.0_linux_amd64.zip"
    unzip katana_1.1.0_linux_amd64.zip
    sudo mv katana /usr/local/bin/
    sudo rm -rf ./*
    katana -h
    cd

    cd sp1d3r
    echo "waybackurls=================================="
    wget "https://github.com/tomnomnom/waybackurls/releases/download/v0.1.0/waybackurls-linux-amd64-0.1.0.tgz"
    sudo tar -xzf waybackurls-linux-amd64-0.1.0.tgz
    sudo mv waybackurls /usr/local/bin/
    sudo rm -rf ./*
    waybackurls -h
    cd

    sudo rm -rf sp1d3r
    echo "If all tools are not install correctly then install it manually."
    exit 0
fi

if [[ "$1" == "-h" ]]; then
    display_usage
    exit 0
fi

if [[ "$1" == "-l" ]]; then
    domain_Without_Protocol=$(echo "$2" | unfurl -u domains)
    # making directory
    main_dir="bug_bounty/$domain_Without_Protocol"
    base_dir="$main_dir/multi_domain/recon"

    mkdir -p $main_dir

    echo "Multi Domain Url Spidering"
    echo ""
    echo "=================================================================="
    echo "================= Sublist3r checking ============================="
    echo "=================================================================="
    echo ""
    sublist3r -d "$domain_Without_Protocol" -e baidu,yahoo,google,bing,ask,netcraft,virustotal,threatcrowd,crtsh,passivedns -v -o $base_dir/sublist3r.txt
    echo ""
    echo "=================================================================="
    echo "================= Sublist3r finished ============================="
    echo "=================================================================="
    echo ""


    echo ""
    echo "=================================================================="
    echo "================== Subfinder checking ============================"
    echo "=================================================================="
    echo ""
    subfinder -d "$domain_Without_Protocol" -recursive -all -v -o $base_dir/subfinder.txt
    echo ""
    echo "=================================================================="
    echo "================== Subfinder finished ============================"
    echo "=================================================================="
    echo ""

    echo ""
    echo "=================================================================="
    echo "================= Subdominator checking =========================="
    echo "=================================================================="
    echo ""
    subdominator -d "$domain_Without_Protocol" -all -V -t 20 -o $base_dir/subdominator.txt
    echo ""
    echo "=================================================================="
    echo "============== Subdominator finished ============================="
    echo "=================================================================="
    echo ""

    cat $base_dir/sublist3r.txt $base_dir/subfinder.txt $base_dir/subdominator.txt | anew | tee $base_dir/all_subdomains.txt

    cat $base_dir/all_subdomains.txt | wc -l
    echo ""
    echo "=================================================================="
    echo "==================== All domain collection Finished =============="
    echo "=================================================================="
    echo ""


    echo ""
    echo "=================================================================="
    echo "================ Probing subdomains checking ======================="
    echo "=================================================================="
    echo ""

    httpx -l $base_dir/all_subdomains.txt -sc -title -server -td -t 80 -rl 200 -o $base_dir/httpx_full_detail_subdomains.txt

    echo ""
    echo "=================================================================="
    echo "================ Probing subdomains checking finished =============="
    echo "=================================================================="
    echo ""


    echo ""
    echo "=================================================================="
    echo "========================== Live collecting ========================"
    echo "=================================================================="
    echo ""
    # grep -Eia "200|301|302|401|402|403|404"
    cat $base_dir/httpx_full_detail_subdomains.txt | awk '{print $1}' | sed -E 's,https?://(www\.)?,,' | anew | tee $base_dir/alive_subdomains.txt
    echo ""
    echo "=================================================================="
    echo "========================== Live collecting finished ==============="
    echo "=================================================================="
    echo ""

    urlfinder -all -list $base_dir/alive_subdomains.txt -fs fqdn -o $base_dir/urlfinder.txt
    sleep 3

    katana -list $base_dir/alive_subdomains.txt -rl 170 -timeout 5 -retry 2 -aff -d 4 -duc -ps -pss waybackarchive,commoncrawl,alienvault -o $base_dir/katana.txt
    sleep 3

    cat $base_dir/alive_subdomains.txt | gau --providers wayback,commoncrawl,otx,urlscan --verbose --o $base_dir/gau.txt
    sleep 3

    cat $base_dir/alive_subdomains.txt | waybackurls -no-subs | tee $base_dir/waybackurls.txt
    sleep 3

    waymore -i "$base_dir/alive_subdomains.txt" -n -mode U -p 2 -t 20 -xcc -oU $base_dir/waymore.txt
    sleep 3

    cat $base_dir/urlfinder.txt $base_dir/katana.txt $base_dir/gau.txt $base_dir/waybackurls.txt $base_dir/waymore.txt | sed 's/:[0-9]\+//' | anew | tee $base_dir/all_urls.txt
    sleep 3

    cat $base_dir/all_urls.txt | grep -aiE '\.(zip|tar\.gz|tgz|7z|rar|gz|bz2|xz|lzma|z|cab|arj|lha|ace|arc|iso|db|sqlite|sqlite3|db3|sql|sqlitedb|sdb|sqlite2|frm|mdb|accd[be]|adp|accdt|pub|puz|one(pkg)?|doc[xm]?|dot[xm]?|xls[xmb]?|xlt[xm]?|ppt[xm]?|pot[xm]?|pps[xm]?|pdf|bak|backup|old|sav|save|env|txt|js|json)$' | anew | tee $base_dir/all_extension_urls.txt
    sleep 3
    
    cat $base_dir/all_urls.txt | grep -ai "[&=]" | iconv -f ISO-8859-1 -t UTF-8 | anew | tee $base_dir/all_params.txt
    sleep 3

    all_urls_domains_path=$base_dir/all_urls.txt
    all_urls_domains_count=$(cat $base_dir/all_urls.txt | wc -l)
    echo -e "${BOLD_YELLOW}All urls${NC}(${RED}$all_urls_domains_count${NC}): ${BOLD_BLUE}$all_urls_domains_path${NC}"

    all_extensions_path=$base_dir/all_extension_urls.txt
    all_extensions_count=$(cat $base_dir/all_extension_urls.txt | wc -l)
    echo -e "${BOLD_YELLOW}All extension urls${NC}(${RED}$all_extensions_count${NC}): ${BOLD_BLUE}$all_extensions_path${NC}"

    all_params_path=$base_dir/all_params.txt
    all_params_count=$(cat $base_dir/all_params.txt | wc -l)
    echo -e "${BOLD_YELLOW}All params urls${NC}(${RED}$all_params_count${NC}): ${BOLD_BLUE}$all_params_path${NC}"

    chmod -R 777 $main_dir
    exit 0

fi


if [[ "$1" == "-d" ]]; then
    domain_Without_Protocol=$(echo "$2" | unfurl -u domains)
    # making directory
    main_dir="bug_bounty/$domain_Without_Protocol"
    base_dir="$main_dir/single_domain/recon"

    mkdir -p $main_dir

    echo "Single Domain Url Spidering"
    echo ""

    urlfinder -all -d "$domain_Without_Protocol" -fs fqdn -o $base_dir/urlfinder.txt
    sleep 3

    katana -u "$domain_Without_Protocol" -fs fqdn -rl 170 -timeout 5 -retry 2 -aff -d 4 -duc -ps -pss waybackarchive,commoncrawl,alienvault -o $base_dir/katana.txt
    sleep 3

    cat "$domain_Without_Protocol" | gau --providers wayback,commoncrawl,otx,urlscan --verbose --o $base_dir/gau.txt
    sleep 3

    cat "$domain_Without_Protocol" | waybackurls -no-subs | tee $base_dir/waybackurls.txt
    sleep 3

    waymore -i "$domain_Without_Protocol" -n -mode U -p 2 -t 20 -xcc -oU $base_dir/waymore.txt

    sleep 3
    cat $base_dir/urlfinder.txt $base_dir/katana.txt $base_dir/gau.txt $base_dir/waybackurls.txt $base_dir/waymore.txt | sed 's/:[0-9]\+//' | anew | tee $base_dir/all_urls.txt
    sleep 3

    cat $base_dir/all_urls.txt | grep -aiE '\.(zip|tar\.gz|tgz|7z|rar|gz|bz2|xz|lzma|z|cab|arj|lha|ace|arc|iso|db|sqlite|sqlite3|db3|sql|sqlitedb|sdb|sqlite2|frm|mdb|accd[be]|adp|accdt|pub|puz|one(pkg)?|doc[xm]?|dot[xm]?|xls[xmb]?|xlt[xm]?|ppt[xm]?|pot[xm]?|pps[xm]?|pdf|bak|backup|old|sav|save|env|txt|js|json)$' | anew | tee $base_dir/all_extension_urls.txt
    sleep 3

    cat $base_dir/all_urls.txt | grep -ai "[&=]" | iconv -f ISO-8859-1 -t UTF-8 | anew | tee $base_dir/all_params.txt
    sleep 3

    all_urls_domains_path=$base_dir/all_urls.txt
    all_urls_domains_count=$(cat $base_dir/all_urls.txt | wc -l)
    echo -e "${BOLD_YELLOW}All urls${NC}(${RED}$all_urls_domains_count${NC}): ${BOLD_BLUE}$all_urls_domains_path${NC}"

    all_extensions_path=$base_dir/all_extension_urls.txt
    all_extensions_count=$(cat $base_dir/all_extension_urls.txt | wc -l)
    echo -e "${BOLD_YELLOW}All extension urls${NC}(${RED}$all_extensions_count${NC}): ${BOLD_BLUE}$all_extensions_path${NC}"

    all_params_path=$base_dir/all_params.txt
    all_params_count=$(cat $base_dir/all_params.txt | wc -l)
    echo -e "${BOLD_YELLOW}All params urls${NC}(${RED}$all_params_count${NC}): ${BOLD_BLUE}$all_params_path${NC}"

    chmod -R 777 $main_dir
    exit 0
fi
