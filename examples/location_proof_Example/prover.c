#include <stdio.h>
#include <stdlib.h>

#include "../../src/c_api.h"
#include "protocol.h"

int main(int argc, char *argv[])
{
    if (argc != 2) {
        SST_print_error_exit(
            "Usage: %s <config_file_path>",
            argv[0]
        );
    }

    char *config_path = argv[1];

    /*
     * Initialize SST using prover.config.
     */
    SST_ctx_t *ctx = init_SST(config_path);

    if (ctx == NULL) {
        SST_print_error_exit("init_SST() failed.");
    }

    printf("[PROVER] SST initialized\n");

    /*
     * Request a session key from Auth.
     */
    session_key_list_t *s_key_list =
        get_session_key(ctx, NULL);

    if (s_key_list == NULL) {
        SST_print_error_exit(
            "Failed get_session_key()."
        );
    }

    printf("[PROVER] Received session key\n");

    /*
     * Establish secure SST connection
     * with the Robot Arm / Resource.
     */
    SST_session_ctx_t *session_ctx =
        secure_connect_to_server(
            &s_key_list->s_key[0],
            ctx
        );

    if (session_ctx == NULL) {
        SST_print_error_exit(
            "Failed secure_connect_to_server()."
        );
    }

    printf(
        "[PROVER] Secure connection established\n"
    );

    /*
     * Build our protocol request.
     *
     * For the prototype:
     *
     * Robot wants to MOVE
     * and movement requires Zone A.
     */
    ActionRequest request;

    request.action = ACTION_MOVE;
    request.required_zone = ZONE_A;

    printf(
        "[PROVER] Sending MOVE request "
        "requiring ZONE_A\n"
    );

    /*
     * Send ActionRequest through SST.
     *
     * SST encrypts/authenticates the bytes.
     */
    int result = send_secure_message(
        (char *)&request,
        sizeof(request),
        session_ctx
    );

    if (result < 0) {
        SST_print_error_exit(
            "Failed send_secure_message()."
        );
    }

    /*
     * Wait for the location request.
     */
    LocationRequest location_request;

    int bytes_read = read_secure_message(
        (unsigned char *)&location_request,
        session_ctx
    );

    if(bytes_read < 0){
        SST_print_error_exit("Failed to read location request");
    }

    if(bytes_read == 0){
        SST_print_error_exit("Robot Arm disconnected");
    }

    if(bytes_read != sizeof(LocationRequest)){
        SST_print_error_exit("Invalid LocationRequest size");
    }

    printf("[PROVER] Robot Arm requested location\n");

    /* 
    *Obtain the robots location
    *hard coded for now
    *then we will do Ranging to trilateration to coordinates
    */

    LocationResponse location_response;
    location_response.x = 0.50;
    location_response.y = 0.50;

    printf("[PROVER] Current position: (%.2f, %.2f)\n", location_response.x, location_response.y);

    /* send Location to ARM*/

    result = send_secure_message(
        (char *)&location_response,
        sizeof(location_response),
        session_ctx
    );

    if (result < 0) {
        SST_print_error_exit(
            "Failed to send location response."
        );
    }

    printf(
        "[PROVER] Location response sent\n"
    );

        /*
    * --------------------------------
    * Wait for final action decision
    * --------------------------------
    */

    ActionResponse response;

    bytes_read = read_secure_message(
        (unsigned char *)&response,
        session_ctx
    );

    if (bytes_read < 0) {
        SST_print_error_exit(
            "Failed to read action response."
        );
    }

    if (bytes_read == 0) {
        SST_print_error_exit(
            "Robot Arm disconnected."
        );
    }

    if (bytes_read != sizeof(ActionResponse)) {
        SST_print_error_exit(
            "Invalid ActionResponse size."
        );
    }
    if(response.allowed){
        printf("[PROVER] ACTION ALLOWED\n");
    }   else {
        printf("[PROVER] ACTION DENIED\n");
    }

        
        /*
     * Cleanup.
     */
    free_session_ctx(session_ctx);
    free_session_key_list_t(s_key_list);
    free_SST_ctx_t(ctx);

    return 0;
}