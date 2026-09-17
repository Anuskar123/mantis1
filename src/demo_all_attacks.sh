#!/bin/bash
# Run all 3 live attacks in one command - tests KNN, Z-Score, and Naive Bayes
#
# Usage (MANTIS must already be running in another terminal):
#   cd src
#   sudo ./demo_all_attacks.sh                    # auto: wlan0 LAN IP
#   sudo ./demo_all_attacks.sh lo                 # loopback 127.0.0.1
#   sudo ./demo_all_attacks.sh 192.168.196.228    # explicit victim IP
#   sudo ./demo_all_attacks.sh 192.168.196.228 8  # IP + flood seconds
#
# Attacks run in order:
#   1. Port scan   -> KNN engine
#   2. Max flood   -> Z-Score engine  (5 sec)
#   3. SQLi curl   -> Naive Bayes engine
#
# Needs: sudo, nmap, hping3, curl, nc
set -e

SQLI_PORT=8085

detect_lan_ip() {
  local ip
  # wlan0 first (typical laptop Wi-Fi - e.g. 192.168.196.228)
  ip=$(ip -4 addr show wlan0 2>/dev/null | awk '/inet / {print $2}' | cut -d/ -f1 | head -1)
  if [ -n "$ip" ]; then
    echo "$ip"
    return
  fi
  # any UP interface except lo
  ip=$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)
  if [ -n "$ip" ]; then
    echo "$ip"
    return
  fi
  # default route source
  ip=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '/src/ {for (i = 1; i <= NF; i++) if ($i == "src") { print $(i + 1); exit }}')
  if [ -n "$ip" ]; then
    echo "$ip"
    return
  fi
  echo "127.0.0.1"
}

show_network() {
  echo "  Your interfaces:"
  ip -4 -o addr show 2>/dev/null | while read -r _ if _ addr _; do
    addr="${addr%%/*}"
    state=$(ip link show "$if" 2>/dev/null | awk '/state/ {print $2}')
    echo "    $if  $addr  ($state)"
  done
}

if [ "$EUID" -ne 0 ]; then
  echo "[!] run as root: sudo ./demo_all_attacks.sh [IP|lo] [flood_seconds]"
  exit 1
fi

# victim IP: lo/local -> 127.0.0.1, empty -> auto-detect wlan/LAN, else use argument
if [ -z "${1:-}" ]; then
  VICTIM=$(detect_lan_ip)
  IP_MODE="auto (wlan/LAN)"
elif [ "$1" = "lo" ] || [ "$1" = "local" ] || [ "$1" = "127.0.0.1" ]; then
  VICTIM="127.0.0.1"
  IP_MODE="loopback"
else
  VICTIM="$1"
  IP_MODE="manual"
fi

FLOOD_SEC="${2:-5}"

for cmd in nmap hping3 curl nc; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "[!] missing: $cmd"
    case "$cmd" in
      hping3) echo "    install: sudo apt install hping3" ;;
      nmap)   echo "    install: sudo apt install nmap" ;;
    esac
    exit 1
  fi
done

echo ""
echo "================================================================"
echo "  MANTIS - All 3 Model Live Attack Demo"
echo "================================================================"
show_network
echo ""
echo "  Victim IP      : $VICTIM  ($IP_MODE)"
echo "  Flood duration : ${FLOOD_SEC}s"
echo "  Active Wi-Fi   : wlan0 -> use this IP when attacking from another device"
echo "  Loopback       : sudo ./demo_all_attacks.sh lo"
echo ""
echo "  Watch the MANTIS dashboard: http://127.0.0.1:8080"
echo "================================================================"
echo ""
echo "[!] Start MANTIS first and wait ~10 s for Z-Score baseline."
echo "[!] Only attack your own machine / lab VM."
echo ""
read -r -p "Press Enter when MANTIS is running..." _

# -- Attack 1: PORT SCAN -> KNN ----------------------------------------------
echo ""
echo "[1/3] PORT SCAN -> KNN engine"
echo "      Command: nmap -sS -p 1-200 $VICTIM"
echo "      nmap -sS  = SYN stealth scan (many ports quickly)"
echo "      -p 1-200  = scan ports 1 to 200"
echo "      KNN sees: high unique_ports + packet_count -> Scan alert"
echo ""
nmap -sS -p 1-200 "$VICTIM"
echo "[+] Port scan done - check MANTIS for PORT SCAN DETECTED"
sleep 2

# -- Attack 2: MAX PACKET FLOOD -> Z-Score -----------------------------------
echo ""
echo "[2/3] MAX PACKET FLOOD -> Z-Score engine (${FLOOD_SEC}s)"
echo "      Command: hping3 -S --flood -p 80 $VICTIM"
echo "      -S        = TCP SYN packets"
echo "      --flood   = send at MAXIMUM rate (no delay between packets)"
echo "      -p 80     = target port 80"
echo "      Z-Score: z = (PPS - mean) / std -> alert when z > 3"
echo ""
timeout "$FLOOD_SEC" hping3 -S --flood -p 80 "$VICTIM" 2>/dev/null || true
echo "[+] Flood stopped - check MANTIS for DDoS DETECTED (red dashboard)"
sleep 2

# -- Attack 3: SQL INJECTION -> Naive Bayes ----------------------------------
echo ""
echo "[3/3] SQL INJECTION -> Naive Bayes engine"
echo "      Payload contains: UNION SELECT (SQLi keywords)"
echo "      Naive Bayes scores TCP payload text -> Malicious alert"
echo ""
nc -l -p "$SQLI_PORT" >/dev/null 2>&1 &
NC_PID=$!
sleep 0.3
curl -s --max-time 3 \
  "http://${VICTIM}:${SQLI_PORT}/?id=1%20UNION%20SELECT%20user,password%20FROM%20users" \
  >/dev/null 2>&1 || true
kill "$NC_PID" 2>/dev/null || true
wait "$NC_PID" 2>/dev/null || true
echo "[+] SQLi request sent - check MANTIS for MALICIOUS PAYLOAD"
sleep 1

echo ""
echo "================================================================"
echo "  All 3 attacks complete - victim was $VICTIM"
echo "================================================================"
echo "  Engine tested   | Attack type      | What to look for on MANTIS"
echo "  ----------------|------------------|----------------------------"
echo "  KNN             | Port scan        | PORT SCAN DETECTED"
echo "  Z-Score         | Max SYN flood    | DDoS DETECTED / Z-Score > 3"
echo "  Naive Bayes     | SQLi payload     | MALICIOUS PAYLOAD / UNION SELECT"
echo ""
echo "  Offline test (no live sensor):  ./benchmark.sh"
echo "================================================================"
echo ""
