# Mutual IR HK prototype

The physical-presence Robot and Locker run this exchange **after the SST
handshake**, when Auth selects `verificationPlan.CO_LOCATION.selectedMethod.method
= IR`. `--comm_type` only selects the preceding SST handshake transport. IR HK
therefore also runs after a TCP or ultrasound handshake. Both endpoints need an
IR transmitter and receiver. This is an HK-inspired mutual extension, not an
implementation with a proved Hancke–Kuhn security bound.

## Auth configuration

In the root repository, `examples/physical_context_challenges/challenges_ir.json`
selects IR as the only CO_LOCATION mechanism, with:

```json
{"rounds": 128, "success_threshold": 0.8, "max_delay_us": 1000}
```

Auth validates rounds in `{32,64,128}`, a threshold in `(0,1]` with at most six
decimal places, and an integer delay in `[1,1000000]` microseconds. Each endpoint
must have both IR capabilities. Explicitly empty runtime capabilities mean
unavailable. Group capability unions cannot stand in for a duplex endpoint.

The plan is persisted in the session key's cached crypto spec. Key-ID retrieval
returns that same plan; it does not generate a new challenge for the Locker.
Legacy cached crypto-spec strings remain readable. Old keys without a plan must
be replaced for this demo. Updating a catalog requires updating the Auth DB and
requesting new session keys; it does not change plans on already issued keys.

The ordinary `challenges.json` still selects DUMMY first for hardware-free demos.
`HUMAN_PRESENCE` is also still DUMMY in the IR catalog: this change implements
CO_LOCATION only, not camera verification or physical locker actuation.

## Protocol and timing

1. The SST handshake client (Robot A) is the fixed initiator.
2. A sends authenticated `HK_INIT`: protocol version, session key ID, Auth's
   settings, and a new 128-bit nonce A.
3. B checks its own Auth settings/key ID, generates nonce B, derives response
   registers, and sends authenticated `HK_READY` echoing nonce A and adding B.
4. A validates READY and precomputes its registers/random challenges. It then
   waits **2 ms** before its first challenge. B listens immediately after READY.
5. Each side issues N challenges, with the response to a received challenge
   followed by its own challenge:

```text
A -> B : cA[0]
B -> A : rB[0], cB[0]
A -> B : rA[0], cA[1]
...
B -> A : rB[N-1], cB[N-1]
A -> B : rA[N-1]
```

The two bits are two serialized pulse-width symbols, response first. The first
and last messages have one bit. There are 4N bits overall and N scored responses
per direction. Each prover has separate `R0/R1` registers derived with
HMAC-SHA256 from the session MAC key, session key ID, both nonces, settings, and
its direction. Challenges/nonces use OpenSSL `RAND_bytes`; no `rand()` or fixed
shared test secret is used. Setup/control MACs and register derivation have
separate domains.

6. Each side sends a MAC-protected completion decision bound to the same nonce
   pair/settings, with different message types for each direction and PASS/FAIL.
   An endpoint returns PASS only after its local check and the peer's reported
   check pass. A peer report assumes the authenticated endpoint is honest; it is
   not evidence that a compromised endpoint measured correctly. As with any
   final message, its sender cannot know whether the receiver accepted it.

A successful round requires **both** the expected bit and
`complete_rtt_us <= max_delay_us`. RTT runs from the software observation that
challenge transmission finished to the complete decoding of the response bit,
not just its leading edge. Each direction needs `ceil(rounds * threshold)`
successes, e.g. 26/32, 52/64, or 103/128 at 0.8. No averaging between directions;
no shrinking the denominator. Wrong or late bits count as failures. A missing
bit, invalid pulse, framing/MAC error, timeout, or setting mismatch aborts the
run; a retry must start a new run with fresh nonces. Expired keys are rejected.

GPIO wiring is BCM TX 27 / RX 14, active-low RX, approximately 38 kHz carrier.
Bit bursts are 300/600 us (wave generation rounds to whole carrier cycles),
decode split 450 us, accepted received widths 150–900 us. There is no intentional
sleep before the rapid response. The existing **50 ms receiver recovery gap**
is retained between a response and the next challenge, outside the measured
challenge/response interval. Logs are emitted only after the exchange.

Slow setup/completion controls use the existing IR byte framing and its 50 ms
per-bit spacing. Each 86-byte control takes approximately 35 seconds; four
controls take about 140 seconds, plus roughly 3–13 seconds for the alternating
exchange and the preceding SST handshake. The 2 ms READY guard does not remove
these framing costs. Completion delivery therefore also adds delay after the
last physical measurement; a freshness-sensitive actuator must account for
that age. Optimizing these slow controls is a separate hardware task.

The old approximately 450 us leading-edge RTT is not directly comparable to
`complete_rtt_us`. The 1000 us catalog limit is an experimental starting value,
not calibrated for this new encoder/measurement boundary. Linux scheduling and
GPIO polling introduce jitter, including uncertainty in the observed TX end.
This implementation has no hardware timestamping or formal room-scale distance
bound. Hardware evaluation must establish the honest latency distribution and
which additional relay delays are rejected. Noise tolerance reduces rejection
of honest devices and also increases attack acceptance; 0.8 is a demo choice,
not a security recommendation. The original HK `(3/4)^N` claim must not be
applied to this mutual, error-tolerant variant without analysis.

## Build and run

From the root `iotauth` repository:

```sh
mvn -f auth/pom.xml test
cmake -S entity/c/examples/physical_presence -B /tmp/iotauth-hk-build
cmake --build /tmp/iotauth-hk-build -j
ctest --test-dir /tmp/iotauth-hk-build --output-on-failure
```

On the Raspberry Pis, install pigpio as described in `run_ir_test.sh`. The
physical-presence CMake build automatically enables the GPIO adapter on Linux
when pigpio is found. Run both entities under sudo even with `--comm_type tcp`
when verification uses IR. A build without pigpio rejects an IR plan explicitly.

After synchronizing the changed root repository **and `entity/c` submodule** to
all three configured hosts, the existing multihost script supports:

```sh
# First run: regenerate the demo Auth DB/credentials using the IR catalog.
./examples/test_physical_presence_multihost.sh --comm_type tcp --ir-hk --generate
# Reuse that DB for subsequent runs:
./examples/test_physical_presence_multihost.sh --comm_type tcp --ir-hk
# Carry the preceding SST handshake over IR too:
./examples/test_physical_presence_multihost.sh --comm_type ir --ir-hk
```

`--generate` runs the script's existing cleanup/regeneration and credential
redistribution. Review its host/address settings for your environment.
`--ir-hk` also supplies `--require-ir-hk` to both executables, so a stale DUMMY
catalog cannot make an intended IR test appear successful. It enables sudo and
allows 450 seconds. An existing DB configured for IR should always use this
script flag, even though the executables dispatch IR automatically from Auth.
The script propagates the Robot's failure status.

The portable test runs both protocol roles through a simulated link with
virtual timestamps. It tests all round counts, threshold boundaries in both
directions, late-but-correct responses, timer wrap, key/setting mismatches,
expired keys, tampered setup/completion controls, READY replay, and malformed
plans. These tests verify protocol logic; they do not validate GPIO timing or
real relay resistance.
