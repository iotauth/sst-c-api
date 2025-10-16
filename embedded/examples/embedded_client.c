#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "c_api.h"
#include "lwip/netdb.h"
#include "lwip/sockets.h"     // BSD socket API
#include "pico/cyw43_arch.h"  // Wi-Fi driver + lwIP init
#include "pico/stdlib.h"

#define WIFI_SSID "YOUR_WIFI_NAME"
#define WIFI_PASS "YOUR_WIFI_PASSWORD"

// #define SERVER_IP "192.168.0.10"
// #define SERVER_PORT 5000

int main(int argc, char* argv[]) {
    if (argc != 2) {
        SST_print_error_exit("Usage: %s <config_file_path>", argv[0]);
    }

    stdio_init_all();

    // Initialize CYW43 Wi-Fi + lwIP stack
    if (cyw43_arch_init()) {
        printf("Wi-Fi init failed\n");
        return -1;
    }
    cyw43_arch_enable_sta_mode();

    printf("Connecting to Wi-Fi: %s ...\n", WIFI_SSID);
    int rc = cyw43_arch_wifi_connect_timeout_ms(WIFI_SSID, WIFI_PASS,
                                                CYW43_AUTH_WPA2_AES_PSK, 30000);
    if (rc != 0) {
        printf("Wi-Fi connect failed: %d\n", rc);
        cyw43_arch_deinit();
        return -1;
    }
    printf("Wi-Fi connected!\n");

    char* config_path = argv[1];
    SST_ctx_t* ctx = init_SST(config_path);
    if (ctx == NULL) {
        SST_print_error_exit("init_SST() failed.");
    }

    session_key_list_t* s_key_list = get_session_key(ctx, NULL);
    if (s_key_list == NULL) {
        SST_print_error_exit("Failed get_session_key().");
    }
    SST_session_ctx_t* session_ctx =
        secure_connect_to_server(&s_key_list->s_key[0], ctx);
    if (session_ctx == NULL) {
        SST_print_error_exit("Failed secure_connect_to_server().");
    }
    free_session_ctx(session_ctx);

    free_session_key_list_t(s_key_list);
    free_SST_ctx_t(ctx);
}
