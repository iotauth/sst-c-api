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
2. A sends authenticated `HK_INIT`: session key ID and a new 64-bit nonce A.
   Rounds/threshold/max_delay are not sent -- both sides already parsed them,
   matching by construction, from Auth's persisted plan (see above), so
   resending them over IR would be pure overhead.
3. B checks the key ID against its own session key, generates nonce B,
   derives response registers, and sends authenticated `HK_READY` carrying
   nonce B. Nonce A is not resent (B already has it from INIT) but the
   READY tag is still computed over it, so a captured old READY can't be
   replayed against a new INIT.
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
HMAC-SHA256 from the session MAC key and both nonces, and its direction (not
from rounds/threshold/max_delay, which don't need to be part of this -- nonce
freshness alone already makes every run's registers unique). Challenges/nonces
use OpenSSL `RAND_bytes`; no `rand()` or fixed shared test secret is used.
Control MACs and register derivation have separate domains.

There is no completion exchange: each endpoint's result reflects only its own
measurement of the peer (successes against the challenges it issued), not a
mutual, cross-reported verdict. One endpoint can locally pass while the other
fails (e.g. if only one direction's responses were corrupted or delayed); each
endpoint gates its own action on its own result only. An application that
needs a joint, mutually-confirmed outcome would have to add that exchange back
itself.

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

The slow INIT/READY controls use the existing IR byte framing, whose per-bit
spacing (`IR_INTER_BIT_GAP_US`) was empirically tuned down on the real
Robot/Locker pair from the original 50 ms to 25 ms (10/15/20 ms all failed --
20 ms failed asymmetrically, Locker->Robot only). At 25 ms/bit, INIT (49
bytes) takes about 10 s and READY (41 bytes) about 8.4 s, roughly 18-19 s for
both -- down from the original ~140 s for four 86-byte messages at 50 ms/bit,
from a combination of dropping the completion exchange (4 messages -> 2),
shrinking each message (86 -> 49/41 bytes), and the halved per-bit spacing.
The 2 ms READY guard does not remove these framing costs. Optimizing this
further (e.g. tuning the per-bit spacing per direction, since the 20 ms
failure was asymmetric) is a separate hardware task.

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
directions (including the case where only one side's tally crosses the
threshold, since there's no longer a completion exchange to couple the two
outcomes), late-but-correct responses, timer wrap, key/key-ID mismatches,
expired keys, tampered INIT/READY controls, READY replay, and malformed
plans. These tests verify protocol logic; they do not validate GPIO timing or
real relay resistance.
