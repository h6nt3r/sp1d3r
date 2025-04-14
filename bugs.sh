#!/usr/bin/env bash
BOLD_BLUE="\033[1;34m"
RED="\033[0;31m"
NC="\033[0m"
BOLD_YELLOW="\033[1;33m"

# Function to display usage message
display_usage() {
    echo ""
    echo "Options:"
    echo "     -h               Display this help message"
    echo "     -d               Single Domain link Spidering"
    echo "     -l               Multi Domain link Spidering"
    echo "     -i               Check required tool installed or not."
    echo -e "${BOLD_YELLOW}Usage:${NC}"
    echo -e "${BOLD_YELLOW}    $0 -d http://example.com${NC}"
    echo -e "${BOLD_YELLOW}    $0 -l http://example.com${NC}"
    echo -e "${RED}Required Tools:${NC}"
    echo -e "              ${RED}
            https://github.com/xnl-h4ck3r/waymore
            https://github.com/tomnomnom/anew
            https://github.com/projectdiscovery/urlfinder
            https://github.com/lc/gau${NC}"
    exit 0
}

# Function to check installed tools
check_tools() {
    tools=("gau" "urlfinder" "anew" "qsreplace")

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

# help function execution
if [[ "$1" == "-h" ]]; then
    display_usage
    exit 0
fi

# single domain url getting
if [[ "$1" == "-d" ]]; then
    domain_Without_Protocol=$(echo "$2" | sed 's|https\?://||g')
    # making directory
    main_dir="bug_bounty/$domain_Without_Protocol"
    base_dir="$main_dir/single_domain/recon"

    mkdir -p $main_dir

    urlfinder -all -d "$domain_Without_Protocol" -fs fqdn -o $base_dir/urlfinder.txt

    gau "$domain_Without_Protocol" --providers wayback,commoncrawl,otx,urlscan --verbose --o $base_dir/gau.txt

    cat $base_dir/urlfinder.txt $base_dir/gau.txt | anew $base_dir/all_urls.txt
    cat $base_dir/all_urls.txt | grep -aiE '\.(zip|tar\.gz|tgz|7z|rar|gz|bz2|xz|lzma|z|cab|arj|lha|ace|arc|iso|db|sqlite|sqlite3|db3|sql|sqlitedb|sdb|sqlite2|frm|mdb|accd[be]|adp|accdt|pub|puz|one(pkg)?|doc[xm]?|dot[xm]?|xls[xmb]?|xlt[xm]?|ppt[xm]?|pot[xm]?|pps[xm]?|pdf|bak|backup|old|sav|save)$' | anew $base_dir/all_extension_urls.txt

    cat $base_dir/all_urls.txt | grep -a "[=&]" | sort -u | tee $base_dir/all_urls_bxss1.txt

    cat $base_dir/all_urls.txt | grep -aiE "\.(php|asp|aspx|cfm|jsp)([?&#/.\s]|$)" | grep -av "\?" | anew | tee $base_dir/all_urls_bxss2.txt

    cat $base_dir/all_urls_bxss1.txt $base_dir/all_urls_bxss2.txt | anew | tee $base_dir/all_urls_bxss.txt

    cat $base_dir/all_urls_bxss.txt | grep -a "[=&]" | sort -u | grep -aiEv "\.(css|ico|woff|woff2|svg|ttf|eot|png|jpg)($|\s|\?|&|#|/|\.)" | qsreplace "BXSS" | grep -a "BXSS" | anew | tee $base_dir/all_urls_rxss1.txt | kxss | grep -iav "\\[]" | tee $base_dir/all_urls_rxss.txt

    rm -rf $base_dir/all_urls_bxss1.txt $base_dir/all_urls_bxss2.txt $base_dir/all_urls_rxss1.txt


    all_urls_path=$base_dir/all_urls.txt
    all_urls_count=$(cat $base_dir/all_urls.txt | wc -l)
    echo -e "${BOLD_YELLOW}All urls${NC}(${RED}$all_urls_count${NC}): ${BOLD_BLUE}$all_urls_path${NC}"

    all_extension_urls_path=$base_dir/all_extension_urls.txt
    all_extension_urls_count=$(cat $base_dir/all_extension_urls.txt | wc -l)
    echo -e "${BOLD_YELLOW}All extension urls${NC}(${RED}$all_extension_urls_count${NC}): ${BOLD_BLUE}$all_extension_urls_path${NC}"

    all_bxss_urls_path=$base_dir/all_urls_bxss.txt
    all_bxss_urls_count=$(cat $base_dir/all_urls_bxss.txt | wc -l)
    echo -e "${BOLD_YELLOW}All bxss urls${NC}(${RED}$all_bxss_urls_count${NC}): ${BOLD_BLUE}$all_bxss_urls_path${NC}"

    all_rxss_urls_path=$base_dir/all_urls_rxss.txt
    all_rxss_urls_count=$(cat $base_dir/all_urls_rxss.txt | wc -l)
    echo -e "${BOLD_YELLOW}All rxss urls${NC}(${RED}$all_rxss_urls_count${NC}): ${BOLD_BLUE}$all_rxss_urls_path${NC}"

    chmod -R 777 $main_dir

    exit 0
fi



# multi domain url getting
if [[ "$1" == "-l" ]]; then
    domain_Without_Protocol=$(echo "$2" | sed 's|https\?://||g')
    # making directory
    main_dir="bug_bounty/$domain_Without_Protocol"
    base_dir="$main_dir/multi_domain/recon"

    mkdir -p $main_dir

    urlfinder -all -d "$domain_Without_Protocol" -o $base_dir/urlfinder.txt

    gau "$domain_Without_Protocol" --subs --providers wayback,commoncrawl,otx,urlscan --verbose --o $base_dir/gau.txt

    cat $base_dir/urlfinder.txt $base_dir/gau.txt | anew $base_dir/all_urls.txt
    cat $base_dir/all_urls.txt | grep -aEi '\.(zip|tar\.gz|tgz|7z|rar|gz|bz2|xz|lzma|z|cab|arj|lha|ace|arc|iso|db|sqlite|sqlite3|db3|sql|sqlitedb|sdb|sqlite2|frm|mdb|accd[be]|adp|accdt|pub|puz|one(pkg)?|doc[xm]?|dot[xm]?|xls[xmb]?|xlt[xm]?|ppt[xm]?|pot[xm]?|pps[xm]?|pdf|bak|backup|old|sav|save)$' | anew $base_dir/all_extension_urls.txt

    cat $base_dir/all_urls.txt | grep -a "[=&]" | sort -u | tee $base_dir/all_urls_bxss1.txt

    cat $base_dir/all_urls.txt | grep -aiE "\.(php|asp|aspx|cfm|jsp)([?&#/.\s]|$)" | grep -av "\?" | anew | tee $base_dir/all_urls_bxss2.txt

    cat $base_dir/all_urls_bxss1.txt $base_dir/all_urls_bxss2.txt | anew | tee $base_dir/all_urls_bxss.txt

    cat $base_dir/all_urls_bxss.txt | grep -a "[=&]" | sort -u | grep -aiEv "\.(css|ico|woff|woff2|svg|ttf|eot|png|jpg)($|\s|\?|&|#|/|\.)" | qsreplace "BXSS" | grep -a "BXSS" | anew | tee $base_dir/all_urls_rxss1.txt | kxss | grep -iav "\\[]" | tee $base_dir/all_urls_rxss.txt

    rm -rf $base_dir/all_urls_bxss1.txt $base_dir/all_urls_bxss2.txt $base_dir/all_urls_rxss1.txt


    all_urls_path=$base_dir/all_urls.txt
    all_urls_count=$(cat $base_dir/all_urls.txt | wc -l)
    echo -e "${BOLD_YELLOW}All urls${NC}(${RED}$all_urls_count${NC}): ${BOLD_BLUE}$all_urls_path${NC}"

    all_extension_urls_path=$base_dir/all_extension_urls.txt
    all_extension_urls_count=$(cat $base_dir/all_extension_urls.txt | wc -l)
    echo -e "${BOLD_YELLOW}All extension urls${NC}(${RED}$all_extension_urls_count${NC}): ${BOLD_BLUE}$all_extension_urls_path${NC}"

    all_bxss_urls_path=$base_dir/all_urls_bxss.txt
    all_bxss_urls_count=$(cat $base_dir/all_urls_bxss.txt | wc -l)
    echo -e "${BOLD_YELLOW}All bxss urls${NC}(${RED}$all_bxss_urls_count${NC}): ${BOLD_BLUE}$all_bxss_urls_path${NC}"

    all_rxss_urls_path=$base_dir/all_urls_rxss.txt
    all_rxss_urls_count=$(cat $base_dir/all_urls_rxss.txt | wc -l)
    echo -e "${BOLD_YELLOW}All rxss urls${NC}(${RED}$all_rxss_urls_count${NC}): ${BOLD_BLUE}$all_rxss_urls_path${NC}"

    chmod -R 777 $main_dir

    exit 0
fi
