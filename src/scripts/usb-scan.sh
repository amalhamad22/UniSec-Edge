#!/bin/bash
USB_MOUNT_DIR="/tmp/usb"
CONTAINER_NAME="unisec-usb-sanitizer"
LOG_FILE="/var/log/clamav/usb_scan.log"

echo "[*] UniSec-Edge: USB device detected. Initiating ClamAV sandbox scan..."
echo "[*] Timestamp: $(date)"

if ! docker inspect --format='{{.State.Status}}' $CONTAINER_NAME 2>/dev/null | grep -q "running"; then
    echo "[!] ERROR: Container '$CONTAINER_NAME' is not running."
    exit 1
fi

mkdir -p "$USB_MOUNT_DIR"
mkdir -p "$USB_MOUNT_DIR/QUARANTINE_AREA"
echo "[+] Quarantine folder ready: $USB_MOUNT_DIR/QUARANTINE_AREA"

echo "[*] Scanning $USB_MOUNT_DIR ..."
docker exec $CONTAINER_NAME clamscan -r /mnt/usb \
    --move=/mnt/usb/QUARANTINE_AREA \
    --log=$LOG_FILE \
    --infected

EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
    echo "[✔] SCAN COMPLETE: No threats detected. Drive is clean."
elif [ $EXIT_CODE -eq 1 ]; then
    echo "[!] SCAN COMPLETE: THREATS DETECTED! Files quarantined."
else
    echo "[!] SCAN ERROR: Unexpected error code ($EXIT_CODE)."
fi

echo "[*] Full log saved to $LOG_FILE"
exit $EXIT_CODE
