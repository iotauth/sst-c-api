#!/bin/bash
# Usage:
#   ./calibrate.sh -m <mic_device> -p <spk_device> [-d dist_cm] [-s speed] [-i iters]

# Arguments:
#   -m <mic_device>     : ALSA capture device (e.g., plughw:3,0) [REQUIRED]
#   -p <spk_device>     : ALSA playback device (e.g., plughw:4,0) [REQUIRED]
#   -d <dist_cm>        : Physical distance to the Prover in cm (Default: 61)
#   -s <speed_of_sound> : Speed of sound in m/s (Default: 343)
#   -i <iterations>     : Number of calibration pings to run (Default: 10)

# Default values
TARGET_DIST_CM=61
SPEED_OF_SOUND_M_S=343
ITERATIONS=10
MIC_DEVICE=""
SPK_DEVICE=""

# Parse arguments
while getopts "d:s:i:m:p:" opt; do
  case ${opt} in
    d ) TARGET_DIST_CM=$OPTARG ;;
    s ) SPEED_OF_SOUND_M_S=$OPTARG ;;
    i ) ITERATIONS=$OPTARG ;;
    m ) MIC_DEVICE=$OPTARG ;;
    p ) SPK_DEVICE=$OPTARG ;;
    \? ) echo "Usage: cmd [-d dist_cm] [-s speed_of_sound] [-i iterations] -m <mic_device> -p <spk_device>"
         exit 1 ;;
  esac
done

if [ -z "$MIC_DEVICE" ] || [ -z "$SPK_DEVICE" ]; then
    echo "Error: You must provide a capture device (-m) and playback device (-p)."
    exit 1
fi

echo "========================================="
echo " Starting Calibration (Ping-Pong Mode)   "
echo "========================================="
echo " Target Distance : $TARGET_DIST_CM cm"
echo " Speed of Sound  : $SPEED_OF_SOUND_M_S m/s"
echo " Iterations      : $ITERATIONS"
echo "-----------------------------------------"

sum_rtt=0
success_count=0
min_rtt=999999
max_rtt=0

for (( i=1; i<=$ITERATIONS; i++ ))
do
    echo -n "Run $i/$ITERATIONS - Initiating Ping-Pong... "

    # We pass 65535 (max dist) so it always accepts it and prints the RTT
    # We grep strictly for the RTT(actual) line to parse the value
    OUTPUT=$(./echo_protocol verifier "$MIC_DEVICE" "$SPK_DEVICE" 65535 2>&1)

    # Check if we got a valid echo
    RTT=$(echo "$OUTPUT" | grep -oP 'RTT\(actual\): \K[0-9.]+')

    if [ -n "$RTT" ]; then
        echo "$RTT seconds"
        sum_rtt=$(awk "BEGIN {print $sum_rtt + $RTT}")
        success_count=$((success_count + 1))

        if (( $(echo "$RTT < $min_rtt" | bc -l) )); then min_rtt=$RTT; fi
        if (( $(echo "$RTT > $max_rtt" | bc -l) )); then max_rtt=$RTT; fi
    else
        echo "FAILED."
        echo "Debug Output:"
        echo "$OUTPUT"
    fi

    sleep 0.5
done

echo "-----------------------------------------"
echo " Calibration Complete ($success_count/$ITERATIONS successful)"
echo "========================================="

if [ $success_count -gt 0 ]; then
    avg_rtt=$(awk "BEGIN {print $sum_rtt / $success_count}")

    target_dist_m=$(awk "BEGIN {print $TARGET_DIST_CM / 100}")
    ideal_rtt=$(awk "BEGIN {print ($target_dist_m * 2) / $SPEED_OF_SOUND_M_S}")

    overhead=$(awk "BEGIN {print $avg_rtt - $ideal_rtt}")
    jitter=$(awk "BEGIN {print $max_rtt - $min_rtt}")

    # Calculate recommended tolerance margin in meters based on the jitter
    margin_m=$(awk "BEGIN {print ($jitter * $SPEED_OF_SOUND_M_S) / 2.0}")

    echo " Average RTT(actual) : $avg_rtt seconds"
    echo " Max RTT             : $max_rtt seconds"
    echo " Min RTT             : $min_rtt seconds"
    echo " Jitter (Max - Min)  : $jitter seconds"
    echo " Rec. Margin (Meters): $margin_m m"
    echo " Ideal RTT(theory)   : $ideal_rtt seconds"
    echo "========================================="
    echo " Software Overhead   : $overhead seconds"
    echo "========================================="
    echo "Update SOFTWARE_OVERHEAD_SEC and TOLERANCE_MARGIN_M in echo_protocol.c with these values."
else
    echo "Calibration failed completely. No successful runs."
fi
