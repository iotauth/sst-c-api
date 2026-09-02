// SST handshake (SKEY_HANDSHAKE_1/2/3) carried over ultrasound via ggwave,
// instead of a TCP socket. Linux/ALSA/ggwave only.
//
// Compilation (from ultrasonic_com/):
//   gcc -I../.. ggwave_sst_handshake.c ... -lasound -lggwave

#include "ggwave_sst_handshake.h"

#include <alsa/asoundlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "ggwave/ggwave.h"

#include "../src/c_common.h"
#include "../src/c_crypto.h"
#include "../src/c_secure_comm.h"

#define GGWAVE_SAMPLE_RATE 48000
#define GGWAVE_CHANNELS 1
#define GGWAVE_TARGET_BIN 224  // centered at 10.5KHz, same as echo_protocol.c
#define GGWAVE_MAX_PAYLOAD 140  // hard cap of GGWAVE_PROTOCOL_ULTRASOUND_FAST

static void setup_ggwave_freq(void) {
    ggwave_txProtocolSetFreqStart(GGWAVE_PROTOCOL_ULTRASOUND_FAST, GGWAVE_TARGET_BIN);
    ggwave_rxProtocolSetFreqStart(GGWAVE_PROTOCOL_ULTRASOUND_FAST, GGWAVE_TARGET_BIN);
}

static snd_pcm_t* open_playback(const char* device) {
    snd_pcm_t* pcm_handle;
    if (snd_pcm_open(&pcm_handle, device, SND_PCM_STREAM_PLAYBACK, 0) < 0) {
        SST_print_error("Error opening ALSA playback device '%s'.", device);
        return NULL;
    }
    snd_pcm_set_params(pcm_handle, SND_PCM_FORMAT_S16_LE,
                      SND_PCM_ACCESS_RW_INTERLEAVED, GGWAVE_CHANNELS,
                      GGWAVE_SAMPLE_RATE, 1, 500000);
    return pcm_handle;
}

static snd_pcm_t* open_capture(const char* device) {
    snd_pcm_t* pcm_handle;
    if (snd_pcm_open(&pcm_handle, device, SND_PCM_STREAM_CAPTURE, 0) < 0) {
        SST_print_error("Error opening ALSA capture device '%s'.", device);
        return NULL;
    }
    snd_pcm_set_params(pcm_handle, SND_PCM_FORMAT_S16_LE,
                      SND_PCM_ACCESS_RW_INTERLEAVED, GGWAVE_CHANNELS,
                      GGWAVE_SAMPLE_RATE, 1, 500000);
    return pcm_handle;
}

// Encodes and plays buf over spk, then flushes mic so the sender doesn't
// decode its own transmission on the next read.
static int ggwave_tx_buf(ggwave_Instance instance, snd_pcm_t* spk,
                         snd_pcm_t* mic, const unsigned char* buf, int len) {
    if (len > GGWAVE_MAX_PAYLOAD) {
        SST_print_error(
            "ggwave_tx_buf(): payload of %d bytes exceeds the %d-byte "
            "GGWAVE_PROTOCOL_ULTRASOUND_FAST cap.",
            len, GGWAVE_MAX_PAYLOAD);
        return -1;
    }
    int buffer_size_bytes = ggwave_encode(instance, (const char*)buf, len,
                                          GGWAVE_PROTOCOL_ULTRASOUND_FAST, 100,
                                          NULL, 1);
    if (buffer_size_bytes <= 0) {
        SST_print_error("ggwave_encode() size query failed.");
        return -1;
    }
    char* waveform = (char*)malloc(buffer_size_bytes);
    ggwave_encode(instance, (const char*)buf, len,
                 GGWAVE_PROTOCOL_ULTRASOUND_FAST, 100, waveform, 0);

    int total_frames = buffer_size_bytes / 2;
    int frames_written_total = 0;
    int chunk_size = 1024;
    int16_t* audio_ptr = (int16_t*)waveform;

    snd_pcm_prepare(spk);
    while (frames_written_total < total_frames) {
        int frames_to_write = total_frames - frames_written_total;
        if (frames_to_write > chunk_size) frames_to_write = chunk_size;

        snd_pcm_sframes_t frames = snd_pcm_writei(spk, audio_ptr, frames_to_write);
        if (frames == -EPIPE) {
            snd_pcm_prepare(spk);
        } else if (frames < 0) {
            SST_print_error("ALSA write error: %s", snd_strerror(frames));
            break;
        } else {
            audio_ptr += frames;
            frames_written_total += frames;
        }
    }
    snd_pcm_drain(spk);
    free(waveform);

    // Flush the microphone buffer so we don't decode our own transmission.
    snd_pcm_drop(mic);
    snd_pcm_prepare(mic);
    return 0;
}

// Reads from mic and attempts to decode a message for up to timeout_sec
// seconds. @return decoded byte length (>0) on success, 0 on timeout, -1 on
// ALSA error.
static int ggwave_rx_buf(ggwave_Instance instance, snd_pcm_t* mic,
                         unsigned char* out_buf, int out_buf_size,
                         double timeout_sec) {
    int frames_to_read = 1024;
    char* buffer = (char*)malloc(frames_to_read * 2);
    struct timeval loop_start, now;
    gettimeofday(&loop_start, NULL);

    int result = 0;
    while (1) {
        gettimeofday(&now, NULL);
        double elapsed = (now.tv_sec - loop_start.tv_sec) +
                         (now.tv_usec - loop_start.tv_usec) / 1000000.0;
        if (timeout_sec > 0 && elapsed > timeout_sec) {
            result = 0;
            break;
        }

        snd_pcm_sframes_t frames_read = snd_pcm_readi(mic, buffer, frames_to_read);
        if (frames_read == -EPIPE) {
            snd_pcm_prepare(mic);
            continue;
        } else if (frames_read < 0) {
            SST_print_error("ALSA read error: %s", snd_strerror(frames_read));
            result = -1;
            break;
        }

        char decoded[256];
        int decoded_bytes = ggwave_decode(instance, buffer, frames_read * 2, decoded);
        if (decoded_bytes > 0) {
            if (decoded_bytes > out_buf_size) {
                SST_print_error(
                    "ggwave_rx_buf(): decoded %d bytes, exceeds caller's "
                    "buffer of %d bytes.",
                    decoded_bytes, out_buf_size);
                result = -1;
                break;
            }
            memcpy(out_buf, decoded, decoded_bytes);
            result = decoded_bytes;
            break;
        }
    }
    free(buffer);
    return result;
}

SST_session_ctx_t* secure_connect_to_server_via_ggwave(
    session_key_t* s_key, const char* mic_device, const char* spk_device) {
    ggwave_Parameters parameters = ggwave_getDefaultParameters();
    parameters.sampleRate = GGWAVE_SAMPLE_RATE;
    parameters.sampleFormatInp = GGWAVE_SAMPLE_FORMAT_I16;
    parameters.sampleFormatOut = GGWAVE_SAMPLE_FORMAT_I16;
    setup_ggwave_freq();
    ggwave_Instance instance = ggwave_init(parameters);

    snd_pcm_t* mic = open_capture(mic_device);
    snd_pcm_t* spk = open_playback(spk_device);
    if (mic == NULL || spk == NULL) {
        return NULL;
    }

    unsigned char entity_nonce[HS_NONCE_SIZE];
    unsigned int hs1_length;
    unsigned char* hs1 = parse_handshake_1(s_key, entity_nonce, &hs1_length);
    if (hs1 == NULL) {
        SST_print_error("Failed parse_handshake_1().");
        return NULL;
    }

    unsigned char hs2[256];
    int hs2_length = 0;
    // A single ggwave_encode()'d payload of this size takes several seconds
    // to physically play through the speaker, and the peer needs at least
    // that long again to receive+decode it before it can reply -- so this
    // needs generous headroom, not a "network RTT"-scale timeout.
    const double HS2_TIMEOUT_SEC = 20.0;
    const int MAX_RETRIES = 5;
    for (int attempt = 0; attempt < MAX_RETRIES; attempt++) {
        SST_print_log(
            "GGWAVE handshake: broadcasting handshake1 (attempt %d/%d, %u "
            "bytes)...",
            attempt + 1, MAX_RETRIES, hs1_length);
        if (ggwave_tx_buf(instance, spk, mic, hs1, hs1_length) < 0) {
            free(hs1);
            return NULL;
        }
        hs2_length = ggwave_rx_buf(instance, mic, hs2, sizeof(hs2), HS2_TIMEOUT_SEC);
        if (hs2_length > 0) {
            break;
        } else if (hs2_length < 0) {
            free(hs1);
            return NULL;
        }
        SST_print_log("GGWAVE handshake: timed out waiting for handshake2, retrying...");
    }
    free(hs1);
    if (hs2_length <= 0) {
        SST_print_error("GGWAVE handshake: no handshake2 received after %d attempts.",
                        MAX_RETRIES);
        return NULL;
    }
    SST_print_log("GGWAVE handshake: received handshake2 (%d bytes).", hs2_length);

    unsigned int hs3_length;
    unsigned char* hs3 = check_handshake_2_send_handshake_3(
        hs2, hs2_length, entity_nonce, s_key, &hs3_length);
    if (hs3 == NULL) {
        SST_print_error("Failed check_handshake_2_send_handshake_3().");
        return NULL;
    }
    SST_print_log("GGWAVE handshake: broadcasting handshake3 (%u bytes)...", hs3_length);
    if (ggwave_tx_buf(instance, spk, mic, hs3, hs3_length) < 0) {
        free(hs3);
        return NULL;
    }
    free(hs3);

    update_validity(s_key);
    SST_session_ctx_t* session_ctx = malloc(sizeof(SST_session_ctx_t));
    session_ctx->sock = -1;
    session_ctx->sent_seq_num = 0;
    session_ctx->received_seq_num = 0;
    memcpy(&session_ctx->s_key, s_key, sizeof(session_key_t));

    snd_pcm_close(mic);
    snd_pcm_close(spk);
    ggwave_free(instance);
    return session_ctx;
}

SST_session_ctx_t* server_secure_comm_setup_via_ggwave(
    SST_ctx_t* ctx, const char* mic_device, const char* spk_device,
    session_key_list_t* existing_s_key_list) {
    ggwave_Parameters parameters = ggwave_getDefaultParameters();
    parameters.sampleRate = GGWAVE_SAMPLE_RATE;
    parameters.sampleFormatInp = GGWAVE_SAMPLE_FORMAT_I16;
    parameters.sampleFormatOut = GGWAVE_SAMPLE_FORMAT_I16;
    setup_ggwave_freq();
    ggwave_Instance instance = ggwave_init(parameters);

    snd_pcm_t* mic = open_capture(mic_device);
    snd_pcm_t* spk = open_playback(spk_device);
    if (mic == NULL || spk == NULL) {
        return NULL;
    }

    unsigned char hs1[256];
    int hs1_length = 0;
    SST_print_log("GGWAVE handshake: listening for handshake1 (Ctrl+C to stop)...");
    while (hs1_length <= 0) {
        hs1_length = ggwave_rx_buf(instance, mic, hs1, sizeof(hs1), 0);
        if (hs1_length < 0) {
            return NULL;
        }
    }
    SST_print_log("GGWAVE handshake: received handshake1 (%d bytes).", hs1_length);

    if (hs1_length <= SESSION_KEY_ID_SIZE) {
        SST_print_error("GGWAVE handshake: handshake1 too short (%d bytes).", hs1_length);
        return NULL;
    }
    unsigned char target_session_key_id[SESSION_KEY_ID_SIZE];
    memcpy(target_session_key_id, hs1, SESSION_KEY_ID_SIZE);

    session_key_t* s_key =
        get_session_key_by_ID(target_session_key_id, ctx, existing_s_key_list);
    if (s_key == NULL) {
        SST_print_error("Failed to get_session_key_by_ID().");
        return NULL;
    }

    unsigned char server_nonce[HS_NONCE_SIZE];
    unsigned int hs2_length;
    unsigned char* hs2 = check_handshake1_send_handshake2(
        hs1, (unsigned int)hs1_length, server_nonce, s_key, &hs2_length);
    if (hs2 == NULL) {
        SST_print_error("Failed check_handshake1_send_handshake2().");
        return NULL;
    }
    SST_print_log("GGWAVE handshake: broadcasting handshake2 (%u bytes)...", hs2_length);
    if (ggwave_tx_buf(instance, spk, mic, hs2, hs2_length) < 0) {
        free(hs2);
        return NULL;
    }
    free(hs2);

    unsigned char hs3[256];
    int hs3_length = ggwave_rx_buf(instance, mic, hs3, sizeof(hs3), 30.0);
    if (hs3_length <= 0) {
        SST_print_error("GGWAVE handshake: no handshake3 received.");
        return NULL;
    }
    SST_print_log("GGWAVE handshake: received handshake3 (%d bytes).", hs3_length);

    // Verify handshake3: decrypt and check the reply nonce matches server_nonce
    // (mirrors the inline check in server_secure_comm_setup()'s socket path).
    unsigned int decrypted_length;
    unsigned char* decrypted = NULL;
    if (symmetric_decrypt_authenticate(
            hs3, (unsigned int)hs3_length, s_key->mac_key, MAC_KEY_SIZE,
            s_key->cipher_key, CIPHER_KEY_SIZE, AES_128_CBC_IV_SIZE,
            s_key->enc_mode, s_key->no_hmac, &decrypted, &decrypted_length) < 0) {
        SST_print_error("Failed symmetric_decrypt_authenticate() on handshake3.");
        return NULL;
    }
    HS_nonce_t hs;
    parse_handshake(decrypted, &hs);
    free(decrypted);
    if (strncmp((const char*)hs.reply_nonce, (const char*)server_nonce, HS_NONCE_SIZE) != 0) {
        SST_print_error("GGWAVE handshake: peer NOT verified, nonce did NOT match.");
        return NULL;
    }
    SST_print_log("GGWAVE handshake: peer authenticated, nonce matched!");

    update_validity(s_key);
    SST_session_ctx_t* session_ctx = malloc(sizeof(SST_session_ctx_t));
    session_ctx->sock = -1;
    session_ctx->sent_seq_num = 0;
    session_ctx->received_seq_num = 0;
    memcpy(&session_ctx->s_key, s_key, sizeof(session_key_t));

    snd_pcm_close(mic);
    snd_pcm_close(spk);
    ggwave_free(instance);
    return session_ctx;
}
