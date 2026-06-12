#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

JETT_BIN="${JETT_BIN:-$HOME/Projects/jeTT/target/release/jeTT}"
export JETT_MODEL="${JETT_MODEL:-$HOME/Projects/jeTT/models/jeTT-r3-q4.gguf}"

clear

echo -e "${RED}"
cat << 'BANNER'
     _ _____ _____ _____ 
    | | ____|_   _|_   _|
 _  | |  _|   | |   | |  
| |_| | |___  | |   | |  
 \___/|_____| |_|   |_|  
BANNER
echo -e "${NC}"
echo -e "${DIM}  GowskiNet AI Security Engine${NC}"
echo -e "${DIM}  IBM Granite 3.3 2B — RTX 3060 — NyXxOS${NC}"
echo ""

show_menu() {
    echo -e "${BOLD}${CYAN}──────────────────────────────────────${NC}"
    
    # Show daemon status inline
    if systemctl is-active --quiet jett-daemon 2>/dev/null; then
        echo -e "  Daemon: ${GREEN}● RUNNING${NC}"
    else
        echo -e "  Daemon: ${RED}● STOPPED${NC}"
    fi
    
    echo -e "${BOLD}${CYAN}──────────────────────────────────────${NC}"
    echo ""
    echo -e "  ${GREEN}1${NC}  Start daemon"
    echo -e "  ${RED}2${NC}  Stop daemon"
    echo -e "  ${YELLOW}3${NC}  Restart daemon"
    echo -e "  ${CYAN}4${NC}  Status"
    echo -e "  ${CYAN}5${NC}  Live log view"
    echo -e "  ${CYAN}6${NC}  Quarantine log"
    echo -e "  ${CYAN}7${NC}  Run demo tests"
    echo ""
    echo -e "  ${YELLOW}8${NC}  Guard mode  (test an event)"
    echo -e "  ${YELLOW}9${NC}  Alert mode  (explain an event)"
    echo -e "  ${YELLOW}0${NC}  Query mode  (ask jeTT anything)"
    echo ""
    echo -e "  ${DIM}q  Exit${NC}"
    echo ""
    echo -e "${BOLD}${CYAN}──────────────────────────────────────${NC}"
    echo -ne "  ${BOLD}→ ${NC}"
}

while true; do
    show_menu
    read -r choice

    case $choice in
        1)
            echo ""
            sudo systemctl start jett-daemon
            sleep 1
            if systemctl is-active --quiet jett-daemon; then
                echo -e "  ${GREEN}[+] jeTT daemon started${NC}"
            else
                echo -e "  ${RED}[!] Failed to start daemon${NC}"
            fi
            sleep 1
            clear
            ;;
        2)
            echo ""
            sudo systemctl stop jett-daemon
            echo -e "  ${RED}[-] jeTT daemon stopped${NC}"
            sleep 1
            clear
            ;;
        3)
            echo ""
            sudo systemctl restart jett-daemon
            sleep 1
            echo -e "  ${YELLOW}[~] jeTT daemon restarted${NC}"
            sleep 1
            clear
            ;;
        4)
            echo ""
            sudo systemctl status jett-daemon --no-pager
            echo ""
            echo -e "  ${DIM}Log entries: $(wc -l < /var/log/jett/jett.log 2>/dev/null || echo 0)${NC}"
            echo -e "  ${DIM}Quarantine events: $(wc -l < /var/jett/quarantine/quarantine.log 2>/dev/null || echo 0)${NC}"
            echo ""
            read -rp "  Press Enter to continue..."
            clear
            ;;
        5)
            echo ""
            echo -e "  ${DIM}Watching /var/log/jett/jett.log — Ctrl+C to stop${NC}"
            echo ""
            tail -f /var/log/jett/jett.log
            clear
            ;;
        6)
            echo ""
            if [ -f /var/jett/quarantine/quarantine.log ]; then
                echo -e "  ${RED}${BOLD}QUARANTINE LOG${NC}"
                echo ""
                cat /var/jett/quarantine/quarantine.log
            else
                echo -e "  ${GREEN}[+] No quarantine events${NC}"
            fi
            echo ""
            read -rp "  Press Enter to continue..."
            clear
            ;;
        7)
            echo ""
            echo -e "  ${CYAN}Running demo tests...${NC}"
            echo ""
            "$JETT_BIN" 2>/dev/null
            echo ""
            read -rp "  Press Enter to continue..."
            clear
            ;;
        8)
            echo ""
            echo -ne "  ${YELLOW}Event to analyze: ${NC}"
            read -r event
            echo ""
            "$JETT_BIN" --guard "$event" 2>/dev/null
            echo ""
            read -rp "  Press Enter to continue..."
            clear
            ;;
        9)
            echo ""
            echo -ne "  ${YELLOW}Event to explain: ${NC}"
            read -r event
            echo ""
            "$JETT_BIN" --alert "$event" 2>/dev/null
            echo ""
            read -rp "  Press Enter to continue..."
            clear
            ;;
        0)
            echo ""
            echo -ne "  ${YELLOW}Ask jeTT: ${NC}"
            read -r question
            echo ""
            "$JETT_BIN" --query "$question" 2>/dev/null
            echo ""
            read -rp "  Press Enter to continue..."
            clear
            ;;
        q|Q)
            echo ""
            echo -e "  ${DIM}Heimdall Never Sleeps.${NC}"
            echo ""
            exit 0
            ;;
        *)
            clear
            ;;
    esac
done
