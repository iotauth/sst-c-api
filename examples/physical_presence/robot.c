#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../../src/c_api.h"
#include "../../src/c_common.h"
#include "physical_options.h"
#include "qr_io.h"

#ifdef HAVE_GGWAVE_TRANSPORT
#include "../../ultrasonic_com/ggwave_sst_handshake.h"
#endif
#ifdef HAVE_IR_TRANSPORT
#include "../../ir_com/ir_sst_handshake.h"
#endif
#ifdef HAVE_LIFI_TRANSPORT
#include "../../lifi_com/lifi_sst_handshake.h"
#endif
#ifdef HAVE_BT_TRANSPORT
#include "../../bluetooth_com/bt_sst_handshake.h"
#endif

// Executes one named check's selected verification method from the physical
// presence verification plan received from Auth (e.g. "HUMAN_PRESENCE" or
// "CO_LOCATION"), and reports whether it passed.
//
// This currently only supports the "DUMMY" method, which requires no real
// sensor/actuator interaction. It records no evidence, so the action gate
// denies any action that requires it. Real local sensors (camera,
// thermometer) would run here and record timed evidence once implemented;
// any other selected method is treated as not implemented and fails closed.
//
// This is separate from the handshake transport decision (which channel
// carries the SST handshake with a target entity, e.g. "TCP" for now):
// secure_connect_to_server() resolves that on its own from the same
// challenge, independently of the checks executed here.
// @param challenge The physical presence verification plan JSON (the whole
// plan, covering every required check).
// @param check_id The check to execute, e.g. "CO_LOCATION". If the plan has
// no such check, this is a no-op success (the action didn't require it).
// @return true if the check passed (or was absent from the plan), false if
// present but failed or its method is not implemented in this demo.
static bool execute_check(const char* challenge, const char* check_id) {
    char check_obj[512];
    if (extract_json_object_value(challenge, check_id, check_obj,
                                  sizeof(check_obj)) != 0) {
        // This check isn't part of the plan; the action didn't require it.
        return true;
    }
    SST_print_log("%s: selected verification method: %s", check_id, check_obj);

    char method[64] = {0};
    if (parse_json_string_value(check_obj, "method", method, sizeof(method)) !=
        0) {
        SST_print_error("%s: plan has no selected method.", check_id);
        return false;
    }

    if (strcmp(method, "DUMMY") == 0) {
        SST_print_log(
            "%s: DUMMY method (no sensor): no evidence recorded, so an action "
            "requiring it will be denied.",
            check_id);
        return true;
    }

    SST_print_error(
        "%s: verification method %s is not implemented in this demo.", check_id,
        method);
    return false;
}

// Resolves the Locker's address on the direct Wi-Fi link for --comm_type wifi.
// Mirrors c_api.c's TCP resolve_target_server_address: the WIFI handshake
// transport method in the plan Auth sent (s_key->challenge.handshakeTransport)
// carries the Locker's Wi-Fi-link host/port, filled from the Wi-Fi challenge
// catalog. Falls back to --wifi-peer and the config port when the plan carries
// no WIFI address (e.g. an older catalog with empty WIFI parameters).
static void resolve_wifi_peer_address(const session_key_t* s_key,
                                      const SST_ctx_t* ctx,
                                      const char* fallback_host,
                                      char* out_host, size_t out_host_size,
                                      int* out_port) {
    char check_obj[512];
    char method[64] = {0};
    char port_str[16] = {0};
    if (extract_json_object_value(s_key->challenge, "handshakeTransport",
                                  check_obj, sizeof(check_obj)) == 0 &&
        parse_json_string_value(check_obj, "method", method, sizeof(method)) ==
            0 &&
        strcmp(method, "WIFI") == 0 &&
        parse_json_string_value(check_obj, "host", out_host, out_host_size) ==
            0 &&
        parse_json_string_value(check_obj, "port", port_str,
                                sizeof(port_str)) == 0) {
        *out_port = atoi(port_str);
        SST_print_log(
            "WIFI PEER: resolved from Auth plan (handshakeTransport WIFI) "
            "host=%s port=%d",
            out_host, *out_port);
        return;
    }
    snprintf(out_host, out_host_size, "%s", fallback_host);
    *out_port = ctx->config.entity_server_port_num;
    SST_print_log(
        "WIFI PEER: plan carries no WIFI address; using --wifi-peer fallback "
        "host=%s port=%d",
        out_host, *out_port);
}

// Reads the target locker's entity ID via the robot's camera (e.g., a QR
// code on the locker). Camera-based scanning is not implemented here; this
// simply stands in for it and returns as if "net1.locker1" had been scanned.
// @return The scanned locker's entity name.
static const char* scan_locker_id_from_qr_code(void) { return "net1.locker1"; }

int main(int argc, char* argv[]) {
    physical_options opts;
    physical_options_parse(argc, argv, 1, &opts);
    const char* comm_type = opts.comm_type;

    // The Auth-provisioned measurement Wi-Fi link is established after the
    // handshake, so a Wi-Fi handshake transport cannot bootstrap from it (its
    // credentials arrive only in the plan the handshake delivers). The proximity
    // check therefore runs TCP-first; this combination is rejected rather than
    // run a different way.
    if (physical_requires_wifi_rssi(&opts) && !strcmp(comm_type, "wifi")) {
        SST_print_error_exit(
            "--require-wifi-rssi uses a separate Auth-provisioned measurement "
            "link established after the handshake; use --comm_type tcp (not "
            "wifi).");
    }

    // Initialize SST context with configuration file
    SST_ctx_t* ctx = init_SST(opts.config_path);
    if (ctx == NULL) {
        SST_print_error_exit("init_SST() failed.");
    }
    // --benchmark measures RETRIEVE_ITEM alone, from a fresh SST context.
    benchmark_trace bench;
    physical_benchmark_init(&bench, &opts, ctx, 1);
    bench_arm(&bench);

    // Case 1: solo action, no target entity. Request authorization for
    // gripping an item on the floor (purpose index 0: "action":"GRIP_ITEM").
    // Runs first since it needs no peer entity to be reachable. A benchmark
    // run skips it, so it cannot change the key state RETRIEVE_ITEM starts
    // from.
    // Whether Auth granted this robot a camera (read from the GRIP_ITEM plan's
    // effectiveCapabilities), gating the QR scan below.
    int camera_granted = 0;
    if (!opts.benchmark) {
        session_key_list_t* grip_s_key_list =
            get_session_key_with_index(ctx, 0, NULL);
        if (grip_s_key_list == NULL) {
            SST_print_error_exit(
                "Failed get_session_key_with_index() for GRIP_ITEM.");
        }
        SST_print_log("Received authorization for GRIP_ITEM successfully!");
        camera_granted =
            opts.scan_qr && plan_grants_capability(
                                grip_s_key_list->s_key[0].challenge,
                                "requester", "CAMERA");
        action_evidence grip_evidence;
        if (action_evidence_init(&grip_evidence, "GRIP_ITEM",
                                 &grip_s_key_list->s_key[0])) {
            SST_print_error_exit("Failed to start GRIP_ITEM evidence.");
        }

        if (!execute_check(grip_s_key_list->s_key[0].challenge,
                           "HUMAN_PRESENCE")) {
            SST_print_error_exit(
                "Physical presence verification failed for GRIP_ITEM.");
        }
        physical_action_gate(&opts, &grip_s_key_list->s_key[0], "GRIP_ITEM",
                             &grip_evidence, NULL);
        free_session_key_list_t(grip_s_key_list);
    }

    // Case 2: interactive action, targeting a specific locker identified at
    // runtime (not known ahead of time, so it can't live in a static config
    // purpose slot). The purpose is built dynamically with the scanned ID.
    static char scanned_id[MAX_ENTITY_NAME_LENGTH + 1];
    const char* target_locker;
    if (camera_granted &&
        qr_scan_entity_id(scanned_id, sizeof(scanned_id)) == 0) {
        target_locker = scanned_id;
        SST_print_log(
            "Scanned locker ID from camera QR (Auth-granted Camera): %s",
            target_locker);
    } else {
        if (opts.scan_qr && !camera_granted)
            SST_print_log(
                "QR scan requested but Auth did not grant Camera; using "
                "default locker ID.");
        else if (opts.scan_qr)
            SST_print_error("QR scan failed; using default locker ID.");
        target_locker = scan_locker_id_from_qr_code();
        SST_print_log("Locker ID: %s", target_locker);
    }

    char retrieve_purpose[MAX_PURPOSE_LENGTH + 1];
    snprintf(retrieve_purpose, sizeof(retrieve_purpose),
             "{\"action\":\"RETRIEVE_ITEM\",\"target\":\"%s\"}", target_locker);

    // Everything above is setup; the measured operation starts here.
    bench_stage(&bench, "authorization");
    bench_mark(&bench, &bench.authorization_start_us);
    session_key_list_t* s_key_list =
        get_session_key_with_purpose(ctx, retrieve_purpose, NULL);
    bench_mark(&bench, &bench.authorization_end_us);
    if (s_key_list == NULL) {
        SST_print_error_exit(
            "Failed get_session_key_with_purpose() for RETRIEVE_ITEM.");
    }
    SST_print_log("Received session key for RETRIEVE_ITEM successfully!");
    // Fresh evidence for this operation only, bound to this key.
    action_evidence retrieve_evidence;
    if (action_evidence_init(&retrieve_evidence, "RETRIEVE_ITEM",
                             &s_key_list->s_key[0])) {
        SST_print_error_exit("Failed to start RETRIEVE_ITEM evidence.");
    }
    bench.key = &s_key_list->s_key[0];
    bench.evidence = &retrieve_evidence;
    bench_stage(&bench, "local_checks");

    // Local checks can run before the handshake; mutual IR verification must
    // wait until both entities have authenticated with the same session key.
    if (!execute_check(s_key_list->s_key[0].challenge, "HUMAN_PRESENCE")) {
        SST_print_error_exit("HUMAN_PRESENCE verification failed.");
    }

    // Securely connect to target Locker server. --comm_type picks the
    // transport for this robot<->Locker handshake only; the session key
    // itself was still obtained from Auth over TCP either way.
    SST_session_ctx_t* session_ctx = NULL;
    bench_stage(&bench, "peer_handshake");
    bench_mark(&bench, &bench.peer_handshake_start_us);
    if (strcmp(comm_type, "tcp") == 0) {
        session_ctx = secure_connect_to_server(&s_key_list->s_key[0], ctx);
        if (session_ctx == NULL) {
            SST_print_error_exit("Failed secure_connect_to_server().");
        }
    } else if (strcmp(comm_type, "wifi") == 0) {
        /* The same TCP handshake, routed over the direct Wi-Fi link to the
         * Locker's address on it, so the session runs on that link. Auth puts
         * that address in the WIFI handshake transport plan; --wifi-peer is the
         * fallback. */
        char wifi_host[INET_ADDRSTRLEN] = {0};
        int wifi_port = 0;
        resolve_wifi_peer_address(&s_key_list->s_key[0], ctx, opts.wifi_peer,
                                  wifi_host, sizeof(wifi_host), &wifi_port);
        int sock;
        if (connect_as_client(wifi_host, wifi_port, &sock) < 0) {
            SST_print_error_exit("Failed to connect to %s:%d over Wi-Fi.",
                                 wifi_host, wifi_port);
        }
        session_ctx =
            secure_connect_to_server_with_socket(&s_key_list->s_key[0], sock);
        if (session_ctx == NULL) {
            SST_print_error_exit(
                "Failed secure_connect_to_server_with_socket() over Wi-Fi.");
        }
    } else if (strcmp(comm_type, "ultrasound") == 0) {
#ifdef HAVE_GGWAVE_TRANSPORT
        session_ctx = secure_connect_to_server_via_ggwave(
            &s_key_list->s_key[0], opts.co.mic_device, opts.co.spk_device);
        if (session_ctx == NULL) {
            SST_print_error_exit(
                "Failed secure_connect_to_server_via_ggwave().");
        }
        SST_print_log(
            "Robot: GGWAVE handshake with Locker succeeded. (Ongoing secure "
            "messaging over ultrasound is not implemented yet in this demo.)");
#else
        SST_print_error_exit(
            "This build has no ggwave/ALSA support (Linux only). Rebuild on "
            "the Raspberry Pi to use --comm_type ultrasound.");
#endif
    } else if (strcmp(comm_type, "ir") == 0) {
#ifdef HAVE_IR_TRANSPORT
        session_ctx = secure_connect_to_server_via_ir(&s_key_list->s_key[0]);
        if (session_ctx == NULL) {
            SST_print_error_exit("Failed secure_connect_to_server_via_ir().");
        }
        SST_print_log(
            "Robot: IR handshake with Locker succeeded. (Ongoing secure "
            "messaging over IR is not implemented yet in this demo.)");
#else
        SST_print_error_exit(
            "This build has no pigpio/IR support (Linux only). Rebuild on "
            "the Raspberry Pi to use --comm_type ir.");
#endif
    } else if (strcmp(comm_type, "lifi") == 0) {
#ifdef HAVE_LIFI_TRANSPORT
        session_ctx = secure_connect_to_server_via_lifi(&s_key_list->s_key[0]);
        if (session_ctx == NULL) {
            SST_print_error_exit("Failed secure_connect_to_server_via_lifi().");
        }
        SST_print_log(
            "Robot: LiFi handshake with Locker succeeded. (Ongoing secure "
            "messaging over LiFi is not implemented yet in this demo.)");
#else
        SST_print_error_exit(
            "This build has no pigpio/LiFi support (Linux only). Rebuild on "
            "the Raspberry Pi to use --comm_type lifi.");
#endif
    } else if (strcmp(comm_type, "bluetooth") == 0) {
#ifdef HAVE_BT_TRANSPORT
        if (opts.bt_peer == NULL) {
            SST_print_error_exit("--comm_type bluetooth needs --bt-peer.");
        }
        session_ctx = secure_connect_to_server_via_bt(&s_key_list->s_key[0],
                                                      opts.bt_peer);
        if (session_ctx == NULL) {
            SST_print_error_exit("Failed secure_connect_to_server_via_bt().");
        }
#else
        SST_print_error_exit(
            "This build has no BlueZ/Bluetooth support (Linux only). Rebuild "
            "on the Raspberry Pi to use --comm_type bluetooth.");
#endif
    } else {
        SST_print_error_exit(
            "Unknown --comm_type '%s'. Expected tcp, wifi, ir, lifi, "
            "ultrasound, or bluetooth.",
            comm_type);
    }

    bench_mark(&bench, &bench.peer_handshake_end_us);

    opts.co.local_name = ctx->config.name;
    opts.co.expected_peer = target_locker;
    if (bench.enabled) {
        opts.co.observations = bench.observations;
        opts.co.observations_size = sizeof(bench.observations);
    }

    // After the TCP handshake, join the Locker's Auth-provisioned measurement
    // Wi-Fi link (separate from the handshake): wait for the Locker's AP-ready
    // signal over the session, then connect the dedicated measurement socket.
    if (physical_requires_wifi_rssi(&opts) &&
        physical_wifi_measure_setup_robot(&opts, session_ctx)) {
        SST_print_error_exit("Failed to set up the measurement Wi-Fi link.");
    }

    bench_stage(&bench, "cooperative_verification");
    bench_mark(&bench, &bench.cooperative_start_us);
    int co_passed =
        verify_co_location(session_ctx, 1, &opts.co, &retrieve_evidence);
    bench_mark(&bench, &bench.cooperative_end_us);
    physical_wifi_measure_cleanup(&opts);
    if (!co_passed) {
        SST_print_log("Robot: CO_LOCATION did not pass here.");
    }
    // The gate alone decides, over every check the plan requires.
    bench_stage(&bench, "action_gate");
    gate_decision decision =
        physical_action_gate(&opts, &session_ctx->s_key, "RETRIEVE_ITEM",
                             &retrieve_evidence, &bench);
    if (bench.enabled) {
        // The measured run ends at the gate; no example messaging after it.
        bench.stage = NULL;
        int written = bench_write(&bench);
        free_session_ctx(session_ctx);
        free_session_key_list_t(s_key_list);
        free_SST_ctx_t(ctx);
        return written ? 4 : decision == GATE_ALLOW ? 0 : 3;
    }

    if (physical_options_has_socket(&opts)) {
        sleep(1);
        pthread_t thread;
        pthread_create(&thread, NULL, &receive_thread_read_one_each,
                       (void*)session_ctx);

        // Send secure messages to Locker
        int msg =
            send_secure_message("Robot: Hello Locker!",
                                strlen("Robot: Hello Locker!"), session_ctx);
        if (msg < 0) {
            SST_print_error_exit("Failed send_secure_message().");
        }
        sleep(1);

        msg = send_secure_message("Robot: Physical presence verified.",
                                  strlen("Robot: Physical presence verified."),
                                  session_ctx);
        if (msg < 0) {
            SST_print_error_exit("Failed send_secure_message().");
        }
        sleep(1);

        pthread_cancel(thread);
        pthread_join(thread, NULL);
    }
    free_session_ctx(session_ctx);
    free_session_key_list_t(s_key_list);
    free_SST_ctx_t(ctx);

    return 0;
}
