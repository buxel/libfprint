#!/bin/bash
# Record a test session for goodixtls511 umockdev replay.
# Run as: sudo bash tests/goodixtls511/record.sh
# Touch sensor 20x for enroll, then once for verify.
set -e

BASEDIR="$(cd "$(dirname "$0")/../.." && pwd)"
TESTDIR="$BASEDIR/tests/goodixtls511"
SHIM="$BASEDIR/build/tests/libgetrandom-seed.so"
BELL=/usr/share/sounds/freedesktop/stereo/bell.oga
DONE=/usr/share/sounds/freedesktop/stereo/complete.oga

# Play a sound as the calling user (paplay needs PulseAudio session)
beep() {
    sudo -u chris XDG_RUNTIME_DIR=/run/user/$(id -u chris) paplay "$1" 2>/dev/null &
}

echo "=== goodixtls511 test recorder ==="
echo "Base: $BASEDIR"

# 1. Kill fprintd
killall -9 fprintd 2>/dev/null || true

# 2. Find device
DEV=$(lsusb | grep "27c6:5110" | head -1)
if [ -z "$DEV" ]; then
    echo "ERROR: device 27c6:5110 not found"
    exit 1
fi
BUS=$(echo "$DEV" | awk '{print $2}')
DEVNUM=$(echo "$DEV" | awk '{print $4}' | tr -d ':')
DEVPATH="/dev/bus/usb/$BUS/$DEVNUM"
echo "Device: $DEVPATH"

# 3. Record device file
umockdev-record "$DEVPATH" > "$TESTDIR/device"
echo "Device file recorded."

# 4. Start tshark
rm -f /tmp/capture-raw.pcapng
tshark -q -i usbmon1 -w /tmp/capture-raw.pcapng &
TSHARK_PID=$!
sleep 2
echo "tshark capturing (PID $TSHARK_PID)"

# 5. Run test with deterministic RNG (unbuffered output)
echo ""
echo "========================================"
echo "  Touch sensor 20x for enroll"
echo "  Then once more for verify"
echo "========================================"
echo ""
beep "$BELL"

env \
    LD_PRELOAD="$SHIM" \
    LD_LIBRARY_PATH="$BASEDIR/build/libfprint" \
    GI_TYPELIB_PATH="$BASEDIR/build/libfprint" \
    FP_DEVICE_EMULATION=1 \
    FP_DRIVERS_ALLOWLIST=goodixtls511 \
    PYTHONUNBUFFERED=1 \
    /usr/bin/python3 "$TESTDIR/custom.py"

TEST_RC=$?

# 6. Stop tshark and filter
kill "$TSHARK_PID" 2>/dev/null
wait "$TSHARK_PID" 2>/dev/null || true
sleep 1
chmod 644 /tmp/capture-raw.pcapng

# Get device address for filtering
ADDR=$(echo "$DEV" | awk '{print $4}' | tr -d ':' | sed 's/^0*//')
rm -f /tmp/custom-filtered.pcapng
tshark -r /tmp/capture-raw.pcapng \
    -Y "usb.bus_id == ${BUS#0} && usb.device_address == $ADDR" \
    -w /tmp/custom-filtered.pcapng

cp /tmp/custom-filtered.pcapng "$TESTDIR/custom.pcapng"
chown chris:chris "$TESTDIR/custom.pcapng" "$TESTDIR/device"

PKTS=$(tshark -r "$TESTDIR/custom.pcapng" 2>/dev/null | wc -l)
echo ""
echo "=== Recording complete! ==="
beep "$DONE"
echo "Packets: $PKTS"
echo "Test exit code: $TEST_RC"
echo "Files: $TESTDIR/device, $TESTDIR/custom.pcapng"
echo ""
echo "Test replay with: meson test -C build -v goodixtls511"
