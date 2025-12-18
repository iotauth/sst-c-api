#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "c_api.h"
#include "lwip/netdb.h"
#include "lwip/sockets.h"     // BSD socket API
#include "pico/cyw43_arch.h"  // Wi-Fi driver + lwIP init
#include "pico/stdlib.h"

#include "FreeRTOS.h"
#include "task.h"

#define WIFI_SSID "204_office"
#define WIFI_PASSWORD "hkim2010"

#define TEST_TASK_PRIORITY ( tskIDLE_PRIORITY + 2UL )
#define TEST_TASK_STACK_SIZE 1024

// #define SERVER_IP "192.168.0.10"
// #define SERVER_PORT 5000

static const char default_config_text[] =
    "entityInfo.name=net1.client\n"
    "entityInfo.purpose={\"group\":\"Servers\"}\n"
    "entityInfo.number_key=3\n"
    "authInfo.id=101\n"
    "auth.ip.address=10.218.100.95\n"
    "auth.port.number=21800\n"
    "entity.server.ip.address=10.218.100.95\n"
    "entity.server.port.number=21200\n"
    "network.protocol=TCP\n"
    "authInfo.pubkey.path=\n"
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDWjCCAkICFAzOlPI6THQ5t/L40v6XU4VaN3uFMA0GCSqGSIb3DQEBCwUAMHEx\n"
    "CzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTERMA8GA1UEBwwIQmVya2VsZXkxDTAL\n"
    "BgNVBAoMBEVFQ1MxHTAbBgNVBAsMFENlcnRpZmljYXRlQXV0aG9yaXR5MRQwEgYD\n"
    "VQQDDAtpb3RhdXRoLm9yZzAeFw0yNTEyMTgyMDAxNDRaFw0yNzEyMTgyMDAxNDRa\n"
    "MGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTERMA8GA1UEBwwIQmVya2VsZXkx\n"
    "DTALBgNVBAoMBEVFQ1MxEDAOBgNVBAsMB0F1dGgxMDExEjAQBgNVBAMMCWxvY2Fs\n"
    "aG9zdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAPdQbrZfbaKo7oDs\n"
    "SI8fsmBKfBaLL/ny8xyPt+tXsNOqbizG6n1F7+NcYatHLekyLtWq52I4/IW+4hfh\n"
    "ttFLt6ysrrt70cPC/Kw20mORRHDdXL3nYl4RkYINShE89fWjFcADRak2q81ylef+\n"
    "Cubg45b54Crax07kajIXctJIX9Fehdo7KJajylhev/Lk3erUWX0aTCqK4EWXsdKD\n"
    "urjJZPOutAZ1htSTaxBycelquPwx6Dc2Kdi0L7fki7uKtKbds7HangIoRpmSB3oY\n"
    "PzLbun4MK4bgGIr+uJbKO8HZGb6b1iBo3fzuK8rExeWLzKBElzMx+F8RKy9sqkKy\n"
    "MS5jZ3kCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAVyJb+ixbur6PSrR8QbnEzEeY\n"
    "01uBZaksGBnXCphQJ4zrRqVA3f/FVmh2Vgc2DuCylVUd3fjm+akTtBEUxm0orRyy\n"
    "wopN5q9iX0nXN1XS9lktyCFVNTqRj4bK5M901I6FMS5XCHPDk0bzccpAIx5flQ1o\n"
    "aQg9prABIoedHLcFLZSaMprpB18QCFSDO9kBDkJdiNiPlsW01M/S1vus35wosoDv\n"
    "HzcovdskC5CK00e9uLv8mRL/3wjmnRhEphj2PnPLbFFlfYl1/UI5uDDqCuDo+a6r\n"
    "g9cqiNwuzYRDNlZDYyfYMndedo10XOck1FeI7PsGRODBWxiE9pppanU665BJJg==\n"
    "-----END CERTIFICATE-----\n"
    "entityInfo.privkey.path=\n"
    "-----BEGIN PRIVATE KEY-----\n"
    "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCrqA01Apl9r6LT\n"
    "puDRQLt3kc+V/FdZeD/TZglqtHTDXp61wmyNRev5CK2stajisU+/07d4ufuA9Ddu\n"
    "uH1ABtniOR8AWAzYQERZzy8K98+b1fUDdERCY+sGbyarvW8o/tJh5067Ms1EvpJw\n"
    "g9AOyGyqkkZrAQyqd9SudZ1GhA6o86mF7ozVVl+zKmm1r9XGp+j99VXi+lV9QQow\n"
    "FJEJQJZgfH0mP6vLACpi4RaO1yckiVm3KsY4zReiTeSD+ZWqC3/h2xpJRKDBrwPL\n"
    "9WNAd3rZpvMwvRXE/g9gn0d1mWN++mdbCagAz3YrIYiunqcTWqtQDc1ZbmhzTAVf\n"
    "RHh6H31LAgMBAAECggEAF5a6aeR3j0wJhihSkK7ilCXXbvcEUekybCyDcsRln0tr\n"
    "Z/LV0/wd11UX+LnmAXD4UpYXimGUbD4jN/XmUFwgqPPMjNGMwlLikazk/A7d2r5m\n"
    "MxlRIAZ3D6VKnSMlGW8bHhUZPqRWjPHbUdbrSnzEYhRD1QSJ5wsckPTcrgoLsa/A\n"
    "SW6PzAF/vwkzjoVXoCwOlN7A2/rgPpuO1c6f5wp+Q7k6JeQIWOeyf6cnLYcZ98PT\n"
    "b6byXASrWF3gTJCuGrfQBlwXCNxf0GErBSr8JxY3Ckqm4AzjWPQNlSTeda1k+AfC\n"
    "mFyT2DVFD/12aQdlmM9o53Y2Sa0FykOZck9sAr4xwQKBgQC7HilZPKOJIbhgd6iG\n"
    "BotiwwmILgNwZs/iU/Owf9uaXpOPRObxLfTu4ZO8RVQFD0H5cr3Sr75yMIHiQySi\n"
    "LXpU8IYkbpa/q13SkWFXAkPbWlFp3iOyVmsnMeSDGkm0ws7aZH4qXIhm1avZVHDB\n"
    "UhHeHvctXhUnmNlouu0JeMS72wKBgQDq2NKj6vtjFq1fJuvnuhggGXRslaWl/2xI\n"
    "SHHl4+PWtQFD3TD7vO+eq/NG8D+NOPyyUW7/Y8pi5j/3RLoKpF14FagJcNboDvSZ\n"
    "XsrQjCJHpfHX7XfOfKISKVDdaZXC7vlj6cbk6ulj5GzOCa8LjhcCGGIhUi4BQeCD\n"
    "WIjT98w3UQKBgBECzvOD5cIjxKVQe4ujsKxL2uP8euePETscMr1LAmXoTzXpJ62p\n"
    "ZekJrOqiyt6i4naRDdzHiWLMMiKlxADSbZqnOyq4uw+1vpPUD6tfU1fvwBMF1Ozz\n"
    "mk435PReQXEjfLayCB5Fx0jCCBt757xLf8BXxFTlhrrQ1IMG62G/DvOdAoGAcrLC\n"
    "7dvuO07wDfDsdpik/8hu3DmaVaCSOhtnxWev90UgAQ0ex1RXk59XieX8o/SZNl4f\n"
    "YAxU5EigJRwj4N6159hr4XCDBYOIYv+w/nnypBugKl2IjgjA/y2+mOTgh/w/QVUE\n"
    "FvnEU01U9qw0GeijxBo0kyGX5nVOOdgbu6riyoECgYB2olYihWN//wynrz4wwu62\n"
    "O8qW7pSz90m8FyZ70Q6bDsMvOM/WQ5iS7BQipDQeg9wmkbU8DVbGB5Y8ZjZ7PNP2\n"
    "N7gTEYZyDJparOA5ZJfGKfObndN27fLEMiL6voVr4ceW3mYpAmlfo7pg+3eGfiVo\n"
    "UWo74pQah3huBU0XkYZ9dA==\n"
    "-----END PRIVATE KEY-----\n";


void main_task(__unused void* params) {
    // Initialize CYW43 Wi-Fi + lwIP stack
    printf("0.54!\n");
    if (cyw43_arch_init()) {
        printf("failed to initialise\n");
        return;
    }
    // printf("0.56!\n");
    // cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 1);
    // sleep_ms(250);
    // cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 0);
    // sleep_ms(250);
    // cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 1);
    // sleep_ms(250);
    // cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 0);
    // sleep_ms(250);
    // cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 1);
    // sleep_ms(250);
    // cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 0);
    // sleep_ms(250);

    // printf("1!\n");
    // printf("1!\n");
    // printf("1!\n");
    // printf("1!\n");
    // printf("1!\n");
    // printf("1!\n");
    // printf("1!\n");
    // printf("1!\n");

    // printf("2!\n");
    cyw43_arch_enable_sta_mode();
    printf("3!\n");
    printf("Connecting to Wi-Fi: %s ...\n", WIFI_SSID);
    int rc = cyw43_arch_wifi_connect_timeout_ms(WIFI_SSID, WIFI_PASSWORD,
                                                CYW43_AUTH_WPA2_AES_PSK, 30000);
    printf("4!\n");
    if (rc != 0) {
        printf("Wi-Fi connect failed: %d\n", rc);
        cyw43_arch_deinit();
        return;
    }
    printf("Wi-Fi connected!\n");

    // cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 1);
    // sleep_ms(250);
    // cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 0);
    // sleep_ms(250);
    // cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 1);
    // sleep_ms(250);
    // cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 0);
    // sleep_ms(250);
    // cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 1);
    // sleep_ms(250);
    // cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 0);
    // sleep_ms(250);
    // printf("5!\n");


    SST_ctx_t* ctx = init_SST(default_config_text);
    if (ctx == NULL) {
        SST_print_error_exit("init_SST() failed.");
    }
    printf("init_SST done.");

    session_key_list_t* s_key_list = get_session_key(ctx, NULL);
    if (s_key_list == NULL) {
        SST_print_error_exit("Failed get_session_key().");
    }
    printf("get_session_key done.");
    // SST_session_ctx_t* session_ctx =
    //     secure_connect_to_server(&s_key_list->s_key[0], ctx);
    // if (session_ctx == NULL) {
    //     SST_print_error_exit("Failed secure_connect_to_server().");
    // }
    // print("secure_connect_to_server done.");
    // free_session_ctx(session_ctx);

    free_session_key_list_t(s_key_list);
    free_SST_ctx_t(ctx);

    cyw43_arch_deinit();
    panic("Test passed");
}

void vLaunch(void) {
    TaskHandle_t task;
    xTaskCreate(main_task, "TestMainThread", TEST_TASK_STACK_SIZE, NULL,
                TEST_TASK_PRIORITY, &task);

#if NO_SYS && configUSE_CORE_AFFINITY && configNUM_CORES > 1
    // we must bind the main task to one core (well at least while the init is
    // called) (note we only do this in NO_SYS mode, because cyw43_arch_freertos
    // takes care of it otherwise)
    vTaskCoreAffinitySet(task, 1);
#endif

    /* Start the tasks and timer running. */
    vTaskStartScheduler();
}

int main(int argc, char* argv[]) {
    stdio_init_all();
    // sleep_ms(3000);
    // printf("0!\n");
    /* Configure the hardware ready to run the demo. */
    const char* rtos_name;
#if (portSUPPORT_SMP == 1)
    rtos_name = "FreeRTOS SMP";
#else
    rtos_name = "FreeRTOS";
#endif

#if (portSUPPORT_SMP == 1) && (configNUM_CORES == 2)
    printf("Starting %s on both cores:\n", rtos_name);
    vLaunch();
#elif (RUN_FREERTOS_ON_CORE == 1)
    printf("Starting %s on core 1:\n", rtos_name);
    multicore_launch_core1(vLaunch);
    while (true);
#else
    printf("Starting %s on core 0:\n", rtos_name);
    vLaunch();
#endif
    return 0;


}
