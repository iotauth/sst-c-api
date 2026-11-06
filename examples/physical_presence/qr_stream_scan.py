#!/usr/bin/env python3
# Continuous-stream QR scan for the robot's QR proximity check.
#
# Usage: qr_stream_scan.py <expected_hex> <timeout_ms>
#
# Two modes:
#  * ATTACH (preferred): if a persistent camera daemon is already writing frames
#    to QR_STREAM_DIR (default /tmp/qrstream) -- detected by a frame whose mtime
#    is within ATTACH_FRESH_S -- this just decodes the newest frames until the
#    payload equals <expected_hex> or <timeout_ms> elapses. No camera start-up is
#    paid inside the timed window, so the measured interval tracks the display's
#    update latency (incl. a relay's propagation), not rpicam-vid's ~0.6s cold
#    start. Start the daemon out of band (qr_cam_daemon.sh) before timing.
#  * LEGACY (fallback): no live daemon -> start one warm rpicam-vid stream here
#    (old behaviour), so the tool still works standalone.
#
# Prints the matched payload (or the last decoded one on timeout) to stdout and
# exits 0 on match, 1 otherwise.
import glob
import os
import subprocess
import sys
import time

expected = sys.argv[1] if len(sys.argv) > 1 else ""
timeout_ms = int(sys.argv[2]) if len(sys.argv) > 2 else 20000
D = os.environ.get("QR_STREAM_DIR", "/tmp/qrstream")
ATTACH_FRESH_S = 1.5   # a daemon is "live" if its newest frame is this recent
os.makedirs(D, exist_ok=True)


def newest(dirpath):
    # The very last file may still be mid-write; prefer the last COMPLETE one.
    fs = sorted(glob.glob(dirpath + "/f*.jpg"))
    if len(fs) >= 2:
        return fs[-2]
    return fs[-1] if fs else None


def prune(dirpath, keep=4):
    fs = sorted(glob.glob(dirpath + "/f*.jpg"))
    for f in fs[:-keep]:
        try:
            os.remove(f)
        except OSError:
            pass


def live_daemon():
    f = newest(D)
    if not f:
        return False
    try:
        return (time.time() - os.path.getmtime(f)) < ATTACH_FRESH_S
    except OSError:
        return False


attach = live_daemon()
p = None
if not attach:
    # LEGACY: clear stale frames and start our own warm stream.
    for f in glob.glob(D + "/f*.jpg"):
        try:
            os.remove(f)
        except OSError:
            pass
    args = ["rpicam-vid", "-t", str(timeout_ms + 2000), "--codec", "mjpeg",
            "--segment", "1", "--width", "1280", "--height", "720",
            "--framerate", "20", "--nopreview",
            "--shutter", "8000", "--gain", "2.0", "--awbgains", "1.5,1.5",
            "--denoise", "off", "--autofocus-mode", "manual",
            "--lens-position", "0", "-o", D + "/f%05d.jpg"]
    p = subprocess.Popen(args, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)

t0 = time.time()
last = ""
matched = False
seen = None
try:
    while (time.time() - t0) * 1000 < timeout_ms:
        f = newest(D)
        if f and f != seen:
            seen = f
            r = subprocess.run(["zbarimg", "--quiet", "--raw", f],
                               capture_output=True)
            d = r.stdout.decode(errors="replace").strip()
            if d:
                last = d
                if d == expected:
                    matched = True
                    break
            if attach:
                prune(D)
        time.sleep(0.010)
finally:
    if p is not None:
        p.terminate()
        try:
            p.wait(timeout=3)
        except subprocess.TimeoutExpired:
            p.kill()

sys.stdout.write(last)
sys.stdout.flush()
sys.exit(0 if matched else 1)
