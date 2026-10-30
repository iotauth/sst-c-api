#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../../src/c_api.h"
#include "physical_options.h"
#include "qr_io.h"
#include "temp_sensor.h"

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

// Listens on the given TCP port and accepts one incoming connection.
// @param serv_sock Receives the listening socket, so the caller can close it.
// @return The accepted client socket, or -1 on error.
static int accept_tcp_connection(int port, int* serv_sock) {
    struct sockaddr_in serv_addr, clnt_addr;
    socklen_t clnt_addr_size;
    *serv_sock = socket(PF_INET, SOCK_STREAM, 0);
    if (*serv_sock == -1) {
        SST_print_error("socket() error in %s", __FILE__);
        return -1;
    }
    int on = 1;
    if (setsockopt(*serv_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
        SST_print_error("socket option set error");
        return -1;
    }
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(port);

    if (bind(*serv_sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) ==
        -1) {
        SST_print_error("bind() error in %s", __FILE__);
        return -1;
    }

    if (listen(*serv_sock, 5) == -1) {
        SST_print_error("listen() error in %s", __FILE__);
        return -1;
    }

    SST_print_log("Locker server listening on port %d (TCP)...", port);

    clnt_addr_size = sizeof(clnt_addr);
    int clnt_sock =
        accept(*serv_sock, (struct sockaddr*)&clnt_addr, &clnt_addr_size);
    if (clnt_sock == -1) {
        SST_print_error("accept() error in %s", __FILE__);
        return -1;
    }
    return clnt_sock;
}

int main(int argc, char* argv[]) {
    const int PORT_NUM = 21100;
    physical_options opts;
    physical_options_parse(argc, argv, 0, &opts);
    const char* comm_type = opts.comm_type;

    // See robot.c: the measurement Wi-Fi link is Auth-provisioned and comes up
    // after the handshake, so it cannot also carry the handshake.
    if (physical_requires_wifi_rssi(&opts) && !strcmp(comm_type, "wifi")) {
        SST_print_error_exit(
            "--require-wifi-rssi uses a separate Auth-provisioned measurement "
            "link established after the handshake; use --comm_type tcp (not "
            "wifi).");
    }

    // Initialize SST context for Locker. This is used to talk to Auth over
    // TCP regardless of --comm_type: only the handshake/communication with
    // the robot itself is affected by that choice.
    SST_ctx_t* ctx = init_SST(opts.config_path);
    if (ctx == NULL) {
        SST_print_error_exit("init_SST() failed.");
    }
    benchmark_trace bench;
    physical_benchmark_init(&bench, &opts, ctx, 0);
    bench_arm(&bench);

    // Show this locker's own ID as a QR on the framebuffer, so the robot's
    // camera can scan it to discover the target before requesting the session.
    if (opts.show_qr) {
        qr_display_entity_id(ctx->config.name);
    }

    int serv_sock = -1;
    int clnt_sock = -1;
    session_key_list_t* s_key_list = init_empty_session_key_list();
    SST_session_ctx_t* session_ctx = NULL;

    /* Wi-Fi is the TCP handshake over the direct link: the listener accepts
     * on every interface, and the WIFI_RSSI check later confirms the session
     * arrived over the Wi-Fi link. */
    /* Other transports accept inside their handshake call, so their
     * handshake time cannot be separated from waiting for the robot. */
    bench_stage(&bench, "accept_and_peer_handshake");
    if (strcmp(comm_type, "tcp") == 0 || strcmp(comm_type, "wifi") == 0) {
        bench_stage(&bench, "accept");
        clnt_sock = accept_tcp_connection(PORT_NUM, &serv_sock);
        if (clnt_sock == -1) {
            SST_print_error_exit("Failed accept_tcp_connection().");
        }
        /* The Locker's handshake interval starts once the connection is
         * accepted: it excludes waiting for the robot to show up, and
         * includes this side's session-key lookup with Auth. */
        bench_stage(&bench, "peer_handshake");
        bench_mark(&bench, &bench.peer_handshake_start_us);
        session_ctx = server_secure_comm_setup(ctx, clnt_sock, s_key_list);
        bench_mark(&bench, &bench.peer_handshake_end_us);
        if (session_ctx == NULL) {
            SST_print_error_exit("Failed server_secure_comm_setup().");
        }
    } else if (strcmp(comm_type, "ultrasound") == 0) {
#ifdef HAVE_GGWAVE_TRANSPORT
        session_ctx = server_secure_comm_setup_via_ggwave(
            ctx, opts.co.mic_device, opts.co.spk_device, s_key_list);
        if (session_ctx == NULL) {
            SST_print_error_exit(
                "Failed server_secure_comm_setup_via_ggwave().");
        }
        SST_print_log(
            "Locker: GGWAVE handshake with Robot succeeded. (Ongoing secure "
            "messaging over ultrasound is not implemented yet in this demo.)");
#else
        SST_print_error_exit(
            "This build has no ggwave/ALSA support (Linux only). Rebuild on "
            "the Raspberry Pi to use --comm_type ultrasound.");
#endif
    } else if (strcmp(comm_type, "ir") == 0) {
#ifdef HAVE_IR_TRANSPORT
        session_ctx = server_secure_comm_setup_via_ir(ctx, s_key_list);
        if (session_ctx == NULL) {
            SST_print_error_exit("Failed server_secure_comm_setup_via_ir().");
        }
        SST_print_log(
            "Locker: IR handshake with Robot succeeded. (Ongoing secure "
            "messaging over IR is not implemented yet in this demo.)");
#else
        SST_print_error_exit(
            "This build has no pigpio/IR support (Linux only). Rebuild on "
            "the Raspberry Pi to use --comm_type ir.");
#endif
    } else if (strcmp(comm_type, "lifi") == 0) {
#ifdef HAVE_LIFI_TRANSPORT
        session_ctx = server_secure_comm_setup_via_lifi(ctx, s_key_list);
        if (session_ctx == NULL) {
            SST_print_error_exit("Failed server_secure_comm_setup_via_lifi().");
        }
        SST_print_log(
            "Locker: LiFi handshake with Robot succeeded. (Ongoing secure "
            "messaging over LiFi is not implemented yet in this demo.)");
#else
        SST_print_error_exit(
            "This build has no pigpio/LiFi support (Linux only). Rebuild on "
            "the Raspberry Pi to use --comm_type lifi.");
#endif
    } else if (strcmp(comm_type, "bluetooth") == 0) {
#ifdef HAVE_BT_TRANSPORT
        session_ctx = server_secure_comm_setup_via_bt(ctx, s_key_list);
        if (session_ctx == NULL) {
            SST_print_error_exit("Failed server_secure_comm_setup_via_bt().");
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

    // The plan is the requester's operation plan, carried by the session
    // key; the Locker checks its own evidence for every check it requires
    // before its own action, LOCKER_OPEN.
    action_evidence open_evidence;
    if (action_evidence_init(&open_evidence, "LOCKER_OPEN",
                             &session_ctx->s_key)) {
        SST_print_error_exit("Failed to start LOCKER_OPEN evidence.");
    }
    bench.key = &session_ctx->s_key;
    bench.evidence = &open_evidence;
    opts.co.local_name = ctx->config.name;
    opts.co.expected_peer = NULL;
    if (bench.enabled) {
        opts.co.observations = bench.observations;
        opts.co.observations_size = sizeof(bench.observations);
    }

    // After the handshake, start the Auth-provisioned measurement Wi-Fi AP,
    // signal the robot over the session, and accept its measurement socket
    // (separate from the handshake).
    if (physical_requires_wifi_rssi(&opts) &&
        physical_wifi_measure_setup_locker(&opts, session_ctx)) {
        SST_print_error_exit("Failed to set up the measurement Wi-Fi link.");
    }

    bench_stage(&bench, "cooperative_verification");
    bench_mark(&bench, &bench.cooperative_start_us);
    int co_passed =
        verify_co_location(session_ctx, 0, &opts.co, &open_evidence);
    bench_mark(&bench, &bench.cooperative_end_us);
    physical_wifi_measure_cleanup(&opts);
    if (!co_passed) {
        SST_print_log("Locker: CO_LOCATION did not pass here.");
    }
    // Target-local verification: the locker owns the thermometer (ESP32 on its
    // USB serial), so it enforces TEMPERATURE_CHECK itself before opening. Auth
    // provisions the threshold in the plan but keeps it out of requiredChecks,
    // so this does not burden the sensor-less requester. Fail-closed.
    if (!verify_temperature_local(session_ctx->s_key.challenge, opts.temp_dev)) {
        SST_print_error_exit(
            "LOCKER_OPEN denied: temperature local verification failed.");
    }
    if (!verify_humidity_local(session_ctx->s_key.challenge, opts.temp_dev)) {
        SST_print_error_exit(
            "LOCKER_OPEN denied: humidity local verification failed.");
    }

    bench_stage(&bench, "action_gate");
    gate_decision decision = physical_action_gate(
        &opts, &session_ctx->s_key, "LOCKER_OPEN", &open_evidence, &bench);
    if (bench.enabled) {
        bench.stage = NULL;
        int written = bench_write(&bench);
        free_session_ctx(session_ctx);
        free_session_key_list_t(s_key_list);
        if (clnt_sock != -1) close(clnt_sock);
        if (serv_sock != -1) close(serv_sock);
        free_SST_ctx_t(ctx);
        return written ? 4 : decision == GATE_ALLOW ? 0 : 3;
    }

    if (session_ctx != NULL && physical_options_has_socket(&opts)) {
        pthread_t thread;
        pthread_create(&thread, NULL, &receive_thread_read_one_each,
                       (void*)session_ctx);
        sleep(1);

        int msg =
            send_secure_message("Locker: Hello Robot!",
                                strlen("Locker: Hello Robot!"), session_ctx);
        if (msg < 0) {
            SST_print_error_exit("Failed send_secure_message().");
        }
        sleep(2);

        pthread_cancel(thread);
        pthread_join(thread, NULL);
        SST_print_log("Locker: Finished secure communication with Robot.");
    }
    if (session_ctx != NULL) {
        free_session_ctx(session_ctx);
    }

    free_session_key_list_t(s_key_list);
    if (clnt_sock != -1) close(clnt_sock);
    if (serv_sock != -1) close(serv_sock);
    free_SST_ctx_t(ctx);

    return 0;
}
