# SST UWB Location Verification

This example extends SST authorization with physical location verification using ultra-wideband (UWB) ranging. The system allows a Resource to require verification of a Robot's physical location before authorizing an action.

The prototype combines SST secure communication, JSON-based verification policies, UWB ranging, and multilateration to support physical-context-aware authorization.

---

## System Overview

The system consists of three primary entities:

- **Robot (Prover):** Requests authorization and determines its position using UWB ranging.
- **Resource (Robot Arm):** Enforces the authorization policy and performs physical-context verification.
- **Auth:** Provides SST session credentials and, in the proposed architecture, the verification policy associated with the authorization request.

UWB anchors provide physical ranging information used to determine and verify the Robot's position.

---

## Authorization Protocol

The authorization process extends the existing SST session establishment with physical-context verification.

1. The Robot requests authorization from Auth.
2. Auth provides a session key and session key ID.
3. The Robot begins an SST connection with the Resource using the session key ID.
4. The Resource retrieves the corresponding session key and verification policy from Auth.
5. The Resource parses the verification policy and requests the Robot's location.
6. The Robot obtains UWB ranges and calculates its position using multilateration.
7. The Robot sends its position to the Resource over the secure SST/TCP channel.
8. The Resource independently verifies the Robot's physical location.
9. The Resource compares the claimed and verified positions and evaluates the required location policy.
10. The requested action is allowed or denied.

<p align="center">
  <img src="Robot%20UWB%20Authorization%20Flow-2026-10-18-205123.png"
       alt="UWB Authorization Protocol"
       width="550">
</p>

---

## Verification Policy

Physical verification requirements are represented using a JSON policy.

The policy currently specifies:

- Verification method
- Ranging method
- UWB anchor IDs
- UWB anchor coordinates
- Required physical zone
- Maximum permitted location error

The current prototype loads this policy locally on the Resource. The intended architecture associates the verification policy with the authorization information supplied by Auth.

---

## UWB Localization

The localization system uses Qorvo DWM3001CDK devices and DS-TWR ranging.

```text
                         UWB Tag
                            │
          ┌─────────────────┼─────────────────┐
          │                 │                 │
          ▼                 ▼                 ▼                 ▼
      Anchor 1          Anchor 2          Anchor 3          Anchor 4
      distance          distance          distance          distance
          │                 │                 │                 │
          └─────────────────┴────────┬────────┴─────────────────┘
                                    │
                                    ▼
                            Multilateration
                                    │
                                    ▼
                                  (x,y)
```

Four anchors are used to provide an overdetermined 2D localization system. The implementation uses least-squares multilateration to estimate the position that best fits the measured UWB ranges.

---

## Building

### Dependencies

The example requires:

- CMake 3.19 or later
- SST C API dependencies
- pthreads
- cJSON
- pkg-config

On Debian/Raspberry Pi OS:

```bash
sudo apt update
sudo apt install libcjson-dev pkg-config
```

### Configure and Build

From the SST C API directory:

```bash
cd examples/location_proof_Example

mkdir -p build
cd build

cmake ..
make -j4
```

The build produces:

```text
prover
robot_arm
trilateration_test
```

---

## Testing Multilateration

Run:

```bash
./trilateration_test
```

The synthetic test uses four anchors surrounding a tag at `(1,1)`:

```text
A3 (0,2) ---------------- A4 (2,2)
    |                         |
    |          Tag            |
    |         (1,1)           |
    |                         |
A1 (0,0) ---------------- A2 (2,0)
```

Expected output:

```text
Estimated position: (1.000, 1.000) m
Expected position:  (1.000, 1.000) m
Error:              (0.000000, 0.000000) m
```

---

## Remaining Work

### Completed

- [x] Implement SST action and location challenge-response protocol
- [x] Define and parse JSON verification policies
- [x] Implement policy-based location authorization
- [x] Establish four-anchor UWB DS-TWR ranging
- [x] Implement and validate least-squares multilateration

### To Do

- [ ] Read and parse live UWB ranging data over serial
- [ ] Integrate real UWB measurements with multilateration and SST
- [ ] Implement independent Resource-side location verification
- [ ] Integrate verification-policy delivery into Auth
- [ ] Convert the Resource into a persistent authorization service
- [ ] Perform end-to-end testing and evaluate accuracy and latency
- [ ] Complete deployment and technical documentation