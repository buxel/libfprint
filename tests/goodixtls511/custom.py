#!/usr/bin/python3

"""
Umockdev-based test for the goodixtls511 (Goodix GF511 / 27c6:5110) driver.

This is an FpImageDevice with SIGFM (Signal-Feature Matching) for
on-host template matching.  The test exercises:
  1. Device open / feature flag validation
  2. Enroll (20-stage image capture → SIGFM feature extraction → print build)
  3. Verify (single capture → SIGFM compare against enrolled print)
  4. Print serialization round-trip
  5. Device close
"""

import traceback
import sys
import gi

gi.require_version('FPrint', '2.0')
from gi.repository import FPrint, GLib

# Exit with error on any exception, including those in async callbacks
sys.excepthook = lambda *args: (traceback.print_exception(*args), sys.exit(1))

ctx = GLib.main_context_default()

c = FPrint.Context()
c.enumerate()
devices = c.get_devices()

d = devices[0]
del devices

# -- Driver identity checks --------------------------------------------------
assert d.get_driver() == "goodixtls511"

# FpImageDevice provides CAPTURE, VERIFY, IDENTIFY; temp_hot_seconds=-1 → ALWAYS_ON
assert d.has_feature(FPrint.DeviceFeature.CAPTURE)
assert d.has_feature(FPrint.DeviceFeature.VERIFY)
assert d.has_feature(FPrint.DeviceFeature.IDENTIFY)
assert d.has_feature(FPrint.DeviceFeature.ALWAYS_ON)

# No on-chip storage
assert not d.has_feature(FPrint.DeviceFeature.STORAGE)
assert not d.has_feature(FPrint.DeviceFeature.STORAGE_LIST)
assert not d.has_feature(FPrint.DeviceFeature.STORAGE_DELETE)
assert not d.has_feature(FPrint.DeviceFeature.STORAGE_CLEAR)

# -- Open device --------------------------------------------------------------
d.open_sync()

template = FPrint.Print.new(d)

enroll_progress_count = 0

def enroll_progress(*args):
    global enroll_progress_count
    enroll_progress_count += 1
    print('enroll progress: ' + str(args))

# -- Enroll (20 stages) -------------------------------------------------------
print("enrolling")
assert d.get_finger_status() == FPrint.FingerStatusFlags.NONE
p = d.enroll_sync(template, None, enroll_progress, None)
assert d.get_finger_status() == FPrint.FingerStatusFlags.NONE
print("enroll done (progress callbacks: %d)" % enroll_progress_count)

# Verify the print can be serialized and deserialized
serialized = p.serialize()
p2 = FPrint.Print.deserialize(serialized)
assert p2 is not None

# -- Verify (match) -----------------------------------------------------------
# SIGFM has a non-trivial FRR (~30%), so retry up to 3 times to get a
# successful match during recording.  During replay the captured session
# is deterministic, so only the last (successful) attempt matters.
for attempt in range(1, 6):
    print(f"verifying (attempt {attempt}/5)")
    assert d.get_finger_status() == FPrint.FingerStatusFlags.NONE
    verify_res, verify_print = d.verify_sync(p)
    assert d.get_finger_status() == FPrint.FingerStatusFlags.NONE
    print(f"verify attempt {attempt}: match={verify_res}")
    if verify_res:
        break
assert verify_res == True, "Verify failed after 5 attempts — try better finger placement"

# -- Close device --------------------------------------------------------------
d.close_sync()

print("Test passed")
