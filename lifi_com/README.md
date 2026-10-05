# LiFi transport and mutual HK prototype

Visible-light counterpart of `../ir_com`: an LED on one side and a TEMT6000
phototransistor on the other carry the SST handshake (`--comm_type lifi`)
and the mutual HK-style CO_LOCATION check (Auth
`verificationPlan.CO_LOCATION.selectedMethod.method = LIFI`). As with IR,
`--comm_type` only selects the handshake transport; a LiFi HK plan also runs
after a TCP, IR or ultrasound handshake. Both endpoints need an LED and a
sensor. Like the IR version, this is HK-inspired, not an implementation with a
proved Hancke–Kuhn bound.

The HK protocol and plan reading are shared with IR in `../physical_com/hk.c`
(the `HK_LIFI` medium: the `LIFI` method and LiFi pacing); only the physical
layer lives here. The register-derivation domain is `LHK-REG1` (IR:
`IHK-REG1`), so the two media never derive the same registers even under the
same key and nonces.

## Files

| File | Role | IR counterpart |
|---|---|---|
| `../physical_com/hk.h` / `hk.c` | Authenticated mutual HK protocol and plan reader (transport-agnostic), shared | same file, `HK_IR` |
| `lifi_sst_handshake.h` / `.c` | pigpio physical layer, byte framing, SST handshake over light, HK GPIO adapter, runtime wiring | `ir_sst_handshake.h` / `.c` |
| `lifi_test.c` | Bench RTT test with a fixed secret (initiator / responder / loopback) | `ir_test.c` |
| `lifi_bitbang.c` | Bench 8N1 serial link test | — |
| `run_lifi_test.sh`, `test_lifi_multihost.sh` | Bench launchers | `run_ir_test.sh`, `test_ir_multihost.sh` |
| `../tests/hk_test.c` | Portable protocol unit test over a simulated link, both media | same file |
| `pi42_initiator_600_1200.txt`, `pi43_responder_600_1200.txt` | Recorded bench run (600/1200 µs) showing the sensor's width narrowing | — |

## Physical layer

The LED is ON at idle (mark) and a symbol is a DARK interval; the TEMT6000 is
non-inverting so the sensor GPIO reads 0 during a pulse. There is no carrier
and no demodulating receiver. Relative to IR this changes three things,
beyond the numbers:

- **The line is only at mark while the peer's LED is lit.** Dark for longer
  than any symbol (`LIFI_LINE_LOST_US`, 10 ms) means the peer is off,
  misaligned or too dim, not a frame. The receiver logs that once, drops any
  partial frame, waits for light to return and resumes; it does not fail.
  Both sides keep their LED lit across every phase (`lifi_deinit()` leaves
  it on, `lifi_init()` sets the level before the mode) so the peer never sees
  a false symbol at the handshake → HK transition.
- **Received symbols are narrower than sent.** The sensor falls slower
  than it rises: on the recorded 600/1200 µs run, 600 µs arrived as ~420 µs
  and 1200 µs as ~1020 µs (~180 µs less). The IR 300/600 µs symbols would
  both decode as 0, and 350/890 µs mostly failed (short bits land at the
  glitch floor). LiFi uses the settings that ran 224/224 clean on the
  pi42/pi43 pair: 600/1200 µs symbols, a 900 µs decode split, a 300 µs
  glitch floor, a 2000 µs sync marker with a 1500 µs sync threshold.
- **No AGC.** The per-bit settle gap in the byte framing only has to cover
  the sensor's recovery, so it could be far below IR's 25 ms; it is 5 ms
  (`LIFI_INTER_BIT_GAP_US`) for now, untested and deliberately generous.
  The HK inter-bit pause (`HK_LIFI.inter_bit_us`) stays at the 50 ms round
  gap the clean bench run used; the only shorter run (5 ms) also had
  unworkable widths, so nothing shorter is validated.

Ambient light matters: the sensor feeds a bare GPIO input, so the Pi's logic
threshold is the comparator. Bright rooms pin the input high (pulses
invisible); a dim or misaligned LED leaves it low. Both the handshake and
the bench tools print the idle sensor level up front.

Symbols are one-shot pigpio waves (dark for the width, then relight) like
the IR bursts, so widths are DMA-timed and the RTT's "TX finished" boundary
(`gpioWaveTxBusy()` clearing) is defined the same way as for IR.

Self-illumination (your own LED reaching your own sensor) is not handled:
the intended setup is a Z across a wall, one LED→sensor pair per side. The
recorded run's `recovery_us` column (0–12 µs) confirms the initiator's
sensor was never lit by its own LED.

### Wiring

Unlike IR, pins and polarity are runtime settings, because the bench Pis are
not wired identically. `lifi_configure(tx_gpio, rx_gpio, led_active_low)` is
called by `robot` / `locker` from `--lifi-tx-gpio N`, `--lifi-rx-gpio N`,
`--lifi-led-active-low`. Defaults are BCM TX 23 / RX 22, LED active HIGH
(KS0032 with R to GND, V from the GPIO) — the pi42 wiring; pi43 is wired the
other way round (TX 22 / RX 23). A KS0016 between its + rail and S is active
LOW. The sensor pin uses no
internal pull (the module has its own 10k load). pigpio: Pi 4 and earlier
only, root required.

## Protocol and timing

Identical to `../ir_com/README_HK.md`: A (handshake client) sends
authenticated `HK_INIT` (key ID + nonce A), B replies with authenticated
`HK_READY` (nonce B, tag bound to nonce A), then N mutual challenge/response
rounds with response-then-challenge serialisation, per-direction scoring,
and no completion exchange. A successful round needs the expected bit and
`complete_rtt_us <= max_delay_us`; each direction needs
`ceil(rounds * threshold)` successes.

Byte framing (`lifi_tx_buf` / `lifi_rx_buf`): sync marker, 1-byte length,
payload, 8 pulse-width bits per byte, MSB first, 255-byte cap — the same
frame as IR. At ~6 ms per bit a 49-byte INIT is ~2.4 s and an 80-byte
handshake message ~4 s (IR: ~10 s and ~32 s). Timeouts: handshake2/3 15 s,
HK controls 60 s, HK bit leading edge 1.1 s.

What RTT means here: light covers a metre and back in 6.7 ns, below the 1 µs
tick. RTT is sensor rise time + responder software latency + jitter — a
latency budget, not metres. The recorded 600/1200 µs run measured
210–305 µs to the response's leading edge. `complete_rtt_us` in the
production path additionally includes the response symbol's own width as
received (~420 or ~1020 µs), so a long-bit response completes ~1300 µs
after the challenge. The `max_delay_us` in Auth's catalog must be
calibrated against that: the IR value of 1000 µs would reject every honest
long-bit response; `challenges_lifi.json` uses 2000. Everything in the IR
README about jitter, missing hardware timestamps, and the 0.8 threshold
being a demo choice applies here too.

## Auth configuration (parent repository)

Nothing in this repository generates plans; Auth does. The parent `iotauth`
repository carries, mirroring IR:

- `examples/physical_context_challenges/challenges_lifi.json`: `LIFI` as the
  only CO_LOCATION mechanism, `topology: MUTUAL`, requiring `LiFi` sensors
  and actuators on both requester and target, with
  `{"rounds": 128, "max_delay_us": 2000, "success_threshold": 0.8}`.
  `hk_plan_config(plan, &HK_LIFI, ...)` validates the same ranges as IR: rounds in
  `{32,64,128}`, threshold in `(0,1]` with at most six decimals, delay in
  `[1,1000000]` µs. (Auth's own `validateIRParameters` only runs for the
  `IR` method; the C side is the validator for `LIFI`.)
- `LiFi` sensor/actuator capabilities on robot1 and locker1 in
  `examples/configs/physical_presence_remote.graph` (already present).
- `examples/test_physical_presence_multihost.sh --lifi-hk`, passing
  `--require-lifi-hk` to both executables and the per-Pi wiring from
  `ROBOT_LIFI_ARGS` / `LOCKER_LIFI_ARGS`; `--comm_type lifi` is accepted and
  runs both under sudo.

`verify_co_location()` in `examples/physical_presence/hk_check.h` dispatches
on the plan: `IR` → `ir_hk_run_gpio`, `LIFI` → `lifi_hk_run_gpio`, DUMMY or
absent → pass, anything else → fail closed. `--require-ir-hk` /
`--require-lifi-hk` make any other selection fail, so a stale DUMMY catalog
cannot make an intended hardware test look successful.

## Build and run

Library and portable tests (any machine):

```sh
cmake -S . -B /tmp/sst-build && cmake --build /tmp/sst-build -j
ctest --test-dir /tmp/sst-build --output-on-failure   # hk_test covers IR and LiFi
```

Physical-presence examples (Raspberry Pi with pigpio installed; CMake
enables both IR and LiFi when it finds pigpio):

```sh
cmake -S examples/physical_presence -B /tmp/pp-build && cmake --build /tmp/pp-build -j
sudo ./locker locker_pi43.config --comm_type lifi --require-lifi-hk --lifi-tx-gpio 22 --lifi-rx-gpio 23
sudo ./robot  robot_pi42.config  --comm_type lifi --require-lifi-hk     # defaults: TX 23 / RX 22
```

Run both under sudo even with `--comm_type tcp` when the plan selects LiFi.
Start the locker first; it reports a dark sensor and waits for the robot's
LED rather than failing.

Bench tools, no SST/Auth involved:

```sh
./run_lifi_test.sh loopback                              # sensor latency and width fidelity
./run_lifi_test.sh responder --tx-gpio 22 --rx-gpio 23   # on pi43
./run_lifi_test.sh initiator                             # on pi42 (defaults: TX 23 / RX 22)
./test_lifi_multihost.sh                                 # both, over SSH; pins per host built in
```

`../tests/hk_test.c` runs both protocol roles through a simulated link
with virtual timestamps, once per medium (round counts,
threshold boundaries in both directions, late-but-correct responses, timer
wrap, key/key-ID mismatch, expired keys, tampered INIT/READY, READY replay,
malformed plans), plus an IR-vs-LiFi run showing the labels keep the
registers apart. It verifies protocol logic, not GPIO timing or relay
resistance.

## Not yet validated on hardware

The handshake and HK adapter in `lifi_sst_handshake.c` reuse the symbol
widths, thresholds and 50 ms pause from the clean bench run of
`lifi_test.c`, but the byte framing gap and the timeouts were chosen
from the measured sensor latency, not tuned on the Pis. First hardware run: `--comm_type lifi` with a
DUMMY catalog (handshake only), then the LiFi HK plan.
