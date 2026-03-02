# goodixtls511 — Test Data Recording

This directory contains the test infrastructure for the Goodix GF511
(USB 27c6:5110) TLS fingerprint sensor driver (`goodixtls511`).

## Files

| File              | Description                                     |
|-------------------|-------------------------------------------------|
| `custom.py`       | Python GI test script (open/enroll/verify/close) |
| `device`          | umockdev sysfs recording of the USB device       |
| `custom.pcapng`   | Recorded USB traffic for pcap replay             |

## Recording Test Data

Test data **must be recorded from real hardware** using the steps below.
The recording procedure sets `FP_DEVICE_EMULATION=1`, which activates
deterministic TLS in the driver (PSK-only cipher, fixed server random)
so that pcap replay produces identical handshake bytes.

### Prerequisites

- Physical 27c6:5110 sensor plugged in
- Sensor provisioned with the all-zeros PSK (via `goodix-fp-dump`)
- `tshark` (Wireshark CLI) installed
- `umockdev-record` installed
- Built libfprint (debug build recommended)

### Option A: Using `create-driver-test.py` (recommended)

From the build directory, run as root:

```bash
sudo python3 build/tests/create-driver-test.py goodixtls511
```

This will:
1. Set `FP_DEVICE_EMULATION=1`
2. Record the `device` file via `umockdev-record`
3. Start USB capture via `tshark` on the appropriate usbmon interface
4. Run `custom.py` — place and lift your finger as prompted (20 times
   for enroll, once for verify)
5. Save `custom.pcapng` filtered to the target device

### Option B: Manual recording

```bash
# 1. Find the device
BUS=$(lsusb -d 27c6:5110 | awk '{print $2}')
DEV=$(lsusb -d 27c6:5110 | awk '{print $4}' | tr -d ':')

# 2. Record sysfs device description
sudo umockdev-record /dev/bus/usb/$BUS/$DEV > tests/goodixtls511/device

# 3. Start USB capture (in another terminal)
sudo tshark -q -i usbmon${BUS#0} -w /tmp/capture-raw.pcapng

# 4. Run the test with emulation enabled
export LD_LIBRARY_PATH=build/libfprint
export GI_TYPELIB_PATH=build/libfprint
export FP_DEVICE_EMULATION=1
export FP_DRIVERS_ALLOWLIST=goodixtls511
python3 tests/goodixtls511/custom.py

# 5. Stop tshark (Ctrl+C), then filter the capture
tshark -r /tmp/capture-raw.pcapng \
    -Y "usb.bus_id == ${BUS#0} and usb.device_address == $DEV" \
    -w tests/goodixtls511/custom.pcapng
```

### After Recording

1. Verify the test replay works:
   ```bash
   meson test -C build goodixtls511
   ```

2. Run the full test suite to check for regressions:
   ```bash
   meson test -C build
   ```

## TLS Determinism

The driver's TLS handshake uses GnuTLS DHE-PSK by default. Under
`FP_DEVICE_EMULATION=1`, two changes make it deterministic for
pcap record/replay:

1. **PSK-only cipher** (no DHE) — eliminates the ephemeral DH private
   key, which is the main source of non-determinism
2. **Fixed server random** — `gnutls_handshake_set_random()` sets a
   constant 32-byte value for the ServerHello

Both recording and replay must use `FP_DEVICE_EMULATION=1` so the
same TLS parameters are negotiated.
