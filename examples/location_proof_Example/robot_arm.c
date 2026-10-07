#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "location_verifier.h"
#include "../../src/c_api.h"
#include "protocol.h"
#include "verification_policy.h"

#define PORT_NUM 21100


/*
 * Temporary location verification.
 *
 * Later this becomes:
 *
 * ADS-TWR
 *     ↓
 * distances
 *     ↓
 * trilateration
 *     ↓
 * current zone
 */
static Zone get_current_zone(void)
{
    /*
     * HARD-CODED FOR PROTOTYPE.
     */
    return ZONE_A;
}


static bool location_allows_action(
    Zone current_zone,
    Zone required_zone)
{
    return current_zone == required_zone;
}


int main(int argc, char *argv[])
{
    if (argc != 2) {

        SST_print_error_exit(
            "Usage: %s <config_file_path>",
            argv[0]
        );
    }


    /*
     * --------------------------------
     * Create TCP server
     * --------------------------------
     */

    int serv_sock;

    serv_sock = socket(
        PF_INET,
        SOCK_STREAM,
        0
    );

    if (serv_sock == -1) {

        SST_print_error_exit(
            "socket() error in %s",
            __FILE__
        );
    }


    int on = 1;

    if (setsockopt(
            serv_sock,
            SOL_SOCKET,
            SO_REUSEADDR,
            &on,
            sizeof(on)) < 0) {

        SST_print_error_exit(
            "setsockopt() failed."
        );
    }


    struct sockaddr_in serv_addr;

    memset(
        &serv_addr,
        0,
        sizeof(serv_addr)
    );

    serv_addr.sin_family = AF_INET;

    serv_addr.sin_addr.s_addr =
        htonl(INADDR_ANY);

    serv_addr.sin_port =
        htons(PORT_NUM);


    if (bind(
            serv_sock,
            (struct sockaddr *)&serv_addr,
            sizeof(serv_addr)) == -1) {

        SST_print_error_exit(
            "bind() error in %s",
            __FILE__
        );
    }


    if (listen(serv_sock, 5) == -1) {

        SST_print_error_exit(
            "listen() error in %s",
            __FILE__
        );
    }


    printf(
        "[ROBOT ARM] Waiting for connection "
        "on port %d...\n",
        PORT_NUM
    );


    /*
     * --------------------------------
     * Wait for Prover
     * --------------------------------
     */

    struct sockaddr_in clnt_addr;

    socklen_t clnt_addr_size =
        sizeof(clnt_addr);


    int clnt_sock = accept(
        serv_sock,
        (struct sockaddr *)&clnt_addr,
        &clnt_addr_size
    );


    if (clnt_sock == -1) {

        SST_print_error_exit(
            "accept() error in %s",
            __FILE__
        );
    }


    printf(
        "[ROBOT ARM] TCP connection accepted\n"
    );


    /*
     * --------------------------------
     * Initialize SST
     * --------------------------------
     */

    char *config_path = argv[1];

    SST_ctx_t *ctx =
        init_SST(config_path);


    if (ctx == NULL) {

        SST_print_error_exit(
            "init_SST() failed."
        );
    }

    char *verification_policy = load_verification_policy("../verification_policy.json");

    if(verification_policy == NULL){
        SST_print_error_exit("Failed to load verification policy");
    }

    printf("[ROBOT ARM] Verification policy recieved:\n%s\n", verification_policy);


    /*
     * Cache of session keys.
     *
     * SST will obtain the appropriate
     * session key from Auth during the
     * secure handshake if necessary.
     */
    session_key_list_t *s_key_list =
        init_empty_session_key_list();


    /*
     * --------------------------------
     * Establish secure SST session
     * --------------------------------
     */

    SST_session_ctx_t *session_ctx =
        server_secure_comm_setup(
            ctx,
            clnt_sock,
            s_key_list
        );


    if (session_ctx == NULL) {

        SST_print_error_exit(
            "Failed server_secure_comm_setup()."
        );
    }


    printf(
        "[ROBOT ARM] Secure SST session established\n"
    );


    /*
     * --------------------------------
     * Receive ActionRequest
     * --------------------------------
     */

    ActionRequest request;


    int bytes_read =
        read_secure_message(
            (unsigned char *)&request,
            session_ctx
        );


    if (bytes_read < 0) {

        SST_print_error_exit(
            "Failed read_secure_message()."
        );
    }


    if (bytes_read == 0) {

        SST_print_error_exit(
            "Prover disconnected."
        );
    }


    if (bytes_read != sizeof(ActionRequest)) {

        SST_print_error_exit(
            "Invalid ActionRequest size."
        );
    }


    printf(
        "[ROBOT ARM] Received action request\n"
    );

    printf(
        "[ROBOT ARM] Action: %d\n",
        request.action
    );

    printf(
        "[ROBOT ARM] Required zone: %d\n",
        request.required_zone
    );

    LocationRequest location_request;
    location_request.requested = true;

    int result = send_secure_message(
        (char *)&location_request,
        sizeof(location_request),
        session_ctx
    );

    if(result < 0){
        SST_print_error_exit("Failed to send location request");
    }

    printf("[ROBOT_ARM] Requested robot location\n");


    LocationResponse location_response;

    bytes_read = read_secure_message(
        (unsigned char *)&location_response,
        session_ctx
    );

    if(bytes_read < 0){
        SST_print_error_exit("Failed to read location response");
    }

    if(bytes_read == 0) {
        SST_print_error_exit("Robot disconnected");
    }

    if(bytes_read != sizeof(LocationResponse)){
        SST_print_error_exit("Invalid LocationResponse size");
    }

    printf(
        "[ROBOT ARM] Robot claims position: "
        "(%.2f, %.2f)\n",
        location_response.x,
        location_response.y
    );
    /*
     * --------------------------------
     * Verify physical context
     * --------------------------------
     */

    bool allowed = verify_location(request.required_zone);

    /*
     * --------------------------------
     * Build response
     * --------------------------------
     */

    ActionResponse response;
    response.allowed = allowed;
    


    if (allowed) {

        printf(
            "[ROBOT ARM] Movement allowed\n"
        );

    } else {

        printf(
            "[ROBOT ARM] Movement denied\n"
        );
    }


    /*
     * --------------------------------
     * Return decision to Prover
     * --------------------------------
     */

    result =
        send_secure_message(
            (char *)&response,
            sizeof(response),
            session_ctx
        );


    if (result < 0) {

        SST_print_error_exit(
            "Failed send_secure_message()."
        );
    }


    printf(
        "[ROBOT ARM] Response sent\n"
    );


    /*
     * --------------------------------
     * Cleanup
     * --------------------------------
     */

    free_session_ctx(session_ctx);

    free_session_key_list_t(
        s_key_list
    );

    free_verification_policy(
        verification_policy
    );

    close(clnt_sock);
    close(serv_sock);

    free_SST_ctx_t(ctx);


    return 0;
}