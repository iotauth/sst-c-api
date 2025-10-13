extern "C" {
#include "../../c_api.h"
}

#include <unistd.h>

#include <fstream>
#include <iostream>
#include <thread>

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <config_path>"
                  << std::endl;
        exit(1);
    }

    // Standard SST initialization
    char* config_path = argv[1];
    SST_ctx_t* ctx = init_SST(config_path);

    session_key_list_t* s_key_list = get_session_key(ctx, NULL);
    if (s_key_list == NULL) {
        std::cerr << "Client failed to get session key.\n" << ::std::endl;
        exit(1);
    }
}