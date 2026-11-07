#include <atomic>
#include <barrier>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <thread>

extern "C" {
#include "../../../src/c_api.h"
}
#include "check.hpp"

static std::atomic<int>& handshake_count() {
    static std::atomic<int> count{0};
    return count;
}

static SST_session_ctx_t* fake_handshake(SST_ctx_t* ctx, int sock,
                                         session_key_list_t* keys) {
    check(sock == 42 && keys->num_key == 0);
    ++keys->num_key;
    check(std::strcmp(ctx->purpose_for_requesting_key, "idle") == 0);
    std::strcpy(ctx->purpose_for_requesting_key, "requesting");
    const auto validity = ctx->dist_key.abs_validity;
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    check(ctx->dist_key.abs_validity == validity);
    ctx->dist_key.abs_validity = validity + 1;
    std::strcpy(ctx->purpose_for_requesting_key, "idle");
    ++handshake_count();
    return nullptr;  // The lock must also be released when setup fails.
}

#define server_secure_comm_setup fake_handshake
#define main testbed_server_main
#include "../server.cpp"
#undef main
#undef server_secure_comm_setup

int main() {
    auto* context = static_cast<SST_ctx_t*>(std::calloc(1, sizeof(SST_ctx_t)));
    check(context != nullptr);
    ServerState state(context);
    std::strcpy(context->purpose_for_requesting_key, "idle");
    std::barrier start(2);
    auto handshake = [&] {
        session_key_list_t keys{};
        start.arrive_and_wait();
        check(setup_session(state, 42, &keys) == nullptr);
    };
    std::jthread first(handshake);
    std::jthread second(handshake);
    first.join();
    second.join();
    check(handshake_count() == 2 && context->dist_key.abs_validity == 2);
    check(std::strcmp(context->purpose_for_requesting_key, "idle") == 0);
}
