#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../../src/c_api.h"

#ifdef HAVE_GGWAVE_TRANSPORT
#include "../../ultrasonic_com/ggwave_sst_handshake.h"
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
    const char* comm_type = "tcp";
    const char* mic_device = "plughw:1,0";
    const char* spk_device = "plughw:2,0";
    if (argc < 2) {
        SST_print_error_exit(
            "Usage: %s <config_file_path> [--comm_type tcp|ir|ultrasound] "
            "[--mic <alsa_device>] [--spk <alsa_device>]",
            argv[0]);
    }
    char* config_path = argv[1];
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--comm_type") == 0 && i + 1 < argc) {
            comm_type = argv[i + 1];
            i++;
        } else if (strcmp(argv[i], "--mic") == 0 && i + 1 < argc) {
            mic_device = argv[i + 1];
            i++;
        } else if (strcmp(argv[i], "--spk") == 0 && i + 1 < argc) {
            spk_device = argv[i + 1];
            i++;
        }
    }

    // Initialize SST context for Locker. This is used to talk to Auth over
    // TCP regardless of --comm_type: only the handshake/communication with
    // the robot itself is affected by that choice.
    SST_ctx_t* ctx = init_SST(config_path);
    if (ctx == NULL) {
        SST_print_error_exit("init_SST() failed.");
    }

    int serv_sock = -1;
    int clnt_sock = -1;
    session_key_list_t* s_key_list = init_empty_session_key_list();
    SST_session_ctx_t* session_ctx = NULL;

    if (strcmp(comm_type, "tcp") == 0) {
        clnt_sock = accept_tcp_connection(PORT_NUM, &serv_sock);
        if (clnt_sock == -1) {
            SST_print_error_exit("Failed accept_tcp_connection().");
        }
        session_ctx = server_secure_comm_setup(ctx, clnt_sock, s_key_list);
        if (session_ctx == NULL) {
            SST_print_error_exit("Failed server_secure_comm_setup().");
        }
    } else if (strcmp(comm_type, "ultrasound") == 0) {
#ifdef HAVE_GGWAVE_TRANSPORT
        session_ctx = server_secure_comm_setup_via_ggwave(
            ctx, mic_device, spk_device, s_key_list);
        if (session_ctx == NULL) {
            SST_print_error_exit("Failed server_secure_comm_setup_via_ggwave().");
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
        // TODO: Listen for and accept a connection over IR once that
        // transport is implemented.
        SST_print_error_exit("--comm_type ir is not implemented yet in this demo.");
    } else {
        SST_print_error_exit(
            "Unknown --comm_type '%s'. Expected tcp, ir, or ultrasound.",
            comm_type);
    }

    if (session_ctx != NULL && strcmp(comm_type, "tcp") == 0) {
        pthread_t thread;
        pthread_create(&thread, NULL, &receive_thread_read_one_each,
                       (void*)session_ctx);
        sleep(1);

        int msg = send_secure_message("Locker: Hello Robot!",
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
