#!/usr/bin/python3

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

# FpDevice with enroll/verify/identify vfuncs; temp_hot_seconds=-1 → ALWAYS_ON
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
print("verifying")
assert d.get_finger_status() == FPrint.FingerStatusFlags.NONE
verify_res, verify_print = d.verify_sync(p)
assert d.get_finger_status() == FPrint.FingerStatusFlags.NONE
print("verify done")
assert verify_res == True

# -- Close device --------------------------------------------------------------
d.close_sync()
del d
del c

print("Test passed")
