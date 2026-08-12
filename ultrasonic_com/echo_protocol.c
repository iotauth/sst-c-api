/*
 * Ultrasonic Communication using GGWave and ALSA
 *
 * Compilation:
 *   gcc echo_protocol.c -o echo_protocol -lasound -lggwave
 *
 * Usage:
 *   Verifier (TX):
 *     ./echo_protocol verifier plughw:3,0 plughw:4,0 <permitted_distance>
 *
 *   Prover (RX):
 *     ./echo_protocol prover plughw:3,0 plughw:4,0
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <alsa/asoundlib.h>
#include "ggwave/ggwave.h"

// -----------------------------------------------------------------------------
// Configuration Constants
// -----------------------------------------------------------------------------

// ggwave protocol constants
#define SAMPLE_RATE 48000 //sampling rate for receide auido
#define CHANNELS 1 //mono channel audio
#define TARGET_BIN 224 // 224th bin - centered at 10.5KHz



#define SOFTWARE_OVERHEAD_SEC 0.0 // processing time for the prove (calculate avarage by testing)
#define TOLERANCE_MARGIN_M 00.0  // Margin in meters to account for timing jitter

void setup_ggwave_freq() {
    ggwave_txProtocolSetFreqStart(GGWAVE_PROTOCOL_ULTRASOUND_FAST, TARGET_BIN);
    ggwave_rxProtocolSetFreqStart(GGWAVE_PROTOCOL_ULTRASOUND_FAST, TARGET_BIN);
}

// -----------------------------------------------------------------------------
// Helper Functions
// -----------------------------------------------------------------------------

// Generates a 4-byte random alphanumeric nonce using /dev/urandom
void generate_nonce(char *nonce) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        perror("Failed to open /dev/urandom");
        exit(1);
    }
    unsigned char rand_bytes[4];
    read(fd, rand_bytes, 4);
    close(fd);

    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (int i = 0; i < 4; i++) {
        nonce[i] = charset[rand_bytes[i] % (sizeof(charset) - 1)];
    }
    nonce[4] = '\0';
}

// -----------------------------------------------------------------------------
// Audio Transmission Functions
// -----------------------------------------------------------------------------

snd_pcm_t* open_playback(const char* device) {
    snd_pcm_t *pcm_handle;
    if (snd_pcm_open(&pcm_handle, device, SND_PCM_STREAM_PLAYBACK, 0) < 0) {
        fprintf(stderr, "Error opening ALSA playback device '%s'.\n", device);
        exit(1);
    }
    snd_pcm_set_params(pcm_handle, SND_PCM_FORMAT_S16_LE, SND_PCM_ACCESS_RW_INTERLEAVED, CHANNELS, SAMPLE_RATE, 1, 500000);
    return pcm_handle;
}

snd_pcm_t* open_capture(const char* device) {
    snd_pcm_t *pcm_handle;
    if (snd_pcm_open(&pcm_handle, device, SND_PCM_STREAM_CAPTURE, 0) < 0) {
        fprintf(stderr, "Error opening ALSA capture device '%s'.\n", device);
        exit(1);
    }
    snd_pcm_set_params(pcm_handle, SND_PCM_FORMAT_S16_LE, SND_PCM_ACCESS_RW_INTERLEAVED, CHANNELS, SAMPLE_RATE, 1, 500000);
    return pcm_handle;
}

void tx_message(ggwave_Instance instance, snd_pcm_t *pcm_handle, const char *payload, int payload_len) {
    int buffer_size_bytes = ggwave_encode(instance, payload, payload_len, GGWAVE_PROTOCOL_ULTRASOUND_FAST, 100, NULL, 1);
    char *waveform = (char *)malloc(buffer_size_bytes);
    ggwave_encode(instance, payload, payload_len, GGWAVE_PROTOCOL_ULTRASOUND_FAST, 100, waveform, 0);

    int total_frames = buffer_size_bytes / 2;
    int frames_written_total = 0;
    int chunk_size = 1024;
    int16_t *audio_ptr = (int16_t *)waveform;

    // Prepare the device in case it was drained from a previous transmission
    snd_pcm_prepare(pcm_handle);

    while (frames_written_total < total_frames) {
        int frames_to_write = total_frames - frames_written_total;
        if (frames_to_write > chunk_size) frames_to_write = chunk_size;

        snd_pcm_sframes_t frames = snd_pcm_writei(pcm_handle, audio_ptr, frames_to_write);
        if (frames == -EPIPE) {
            snd_pcm_prepare(pcm_handle);
        } else if (frames < 0) {
            fprintf(stderr, "ALSA write error: %s\n", snd_strerror(frames));
            break;
        } else {
            audio_ptr += frames;
            frames_written_total += frames;
        }
    }
    snd_pcm_drain(pcm_handle);
    free(waveform);
}

// -----------------------------------------------------------------------------
// Prover and Verifier Logic
// -----------------------------------------------------------------------------

void run_prover(const char *mic_device, const char *spk_device) {
    ggwave_Parameters parameters = ggwave_getDefaultParameters();
    parameters.sampleRate = SAMPLE_RATE;
    parameters.sampleFormatInp = GGWAVE_SAMPLE_FORMAT_I16;
    parameters.sampleFormatOut = GGWAVE_SAMPLE_FORMAT_I16;

    setup_ggwave_freq();
    ggwave_Instance instance = ggwave_init(parameters);

    snd_pcm_t *mic = open_capture(mic_device);
    snd_pcm_t *spk = open_playback(spk_device);

    int frames_to_read = 1024;
    char *buffer = (char *)malloc(frames_to_read * 2);
    char rx_payload[256];

    printf("PROVER: Starting Ping-Pong Mode.\n");
    printf("PROVER: Listening for Challenge from Verifier (Ctrl+C to stop)...\n");

    while (1) {

        snd_pcm_sframes_t frames_read = snd_pcm_readi(mic, buffer, frames_to_read);
        if (frames_read == -EPIPE) {
            snd_pcm_prepare(mic);
            continue;
        } else if (frames_read < 0) {
            fprintf(stderr, "ALSA read error: %s\n", snd_strerror(frames_read));
            break;
        }

        int decoded_bytes = ggwave_decode(instance, buffer, frames_read * 2, rx_payload);
        if (decoded_bytes > 0) {
            rx_payload[decoded_bytes] = '\0';

            if (rx_payload[0] == 'N' && decoded_bytes == 5) {
                printf("PROVER: Received Nonce '%s', echoing immediately!\n", rx_payload + 1);

                // Immediately echo the exact payload back
                tx_message(instance, spk, rx_payload, 5);

                // Flush the microphone buffer so we don't decode our own transmission
                snd_pcm_drop(mic);
                snd_pcm_prepare(mic);

                printf("PROVER: Listening for next Challenge...\n");
            }
        }
    }

    free(buffer);
    snd_pcm_close(mic);
    snd_pcm_close(spk);
    ggwave_free(instance);
}

void run_verifier(const char* mic_device, const char* spk_device, uint16_t permitted_dist_cm) {
    ggwave_Parameters parameters = ggwave_getDefaultParameters();
    parameters.sampleRate = SAMPLE_RATE;
    parameters.sampleFormatInp = GGWAVE_SAMPLE_FORMAT_I16;
    parameters.sampleFormatOut = GGWAVE_SAMPLE_FORMAT_I16;

    setup_ggwave_freq();
    ggwave_Instance instance = ggwave_init(parameters);

    snd_pcm_t* mic = open_capture(mic_device);
    snd_pcm_t* spk = open_playback(spk_device);

    int frames_to_read = 1024;
    char* buffer = (char *)malloc(frames_to_read * 2);
    char rx_payload[256];

    char expected_nonce[5];
    struct timeval t_start, t_end, loop_start;

    printf("VERIFIER: Starting Ping-Pong Mode. Permitted Distance: %u cm\n", permitted_dist_cm);

    // Initial broadcast
    generate_nonce(expected_nonce);
    char msg_nonce[6];
    msg_nonce[0] = 'N';
    strcpy(msg_nonce + 1, expected_nonce);

    printf("VERIFIER: Broadcasting Nonce '%s' and starting 1s timer...\n", expected_nonce);
    gettimeofday(&t_start, NULL);
    tx_message(instance, spk, msg_nonce, 5);

    // Flush the microphone buffer so we don't hear our own broadcast!
    snd_pcm_drop(mic);
    snd_pcm_prepare(mic);

    gettimeofday(&loop_start, NULL); // start timer

    while (1) {
        struct timeval now;
        gettimeofday(&now, NULL);
        double elapsed = (now.tv_sec - loop_start.tv_sec) + (now.tv_usec - loop_start.tv_usec) / 1000000.0;

        // 1-second timeout to retry broadcast
        if (elapsed > 1.0) {
            printf("VERIFIER: Timeout waiting for echo. Broadcasting new Nonce...\n");
            generate_nonce(expected_nonce); //generate new nonce for next bradcast
            strcpy(msg_nonce + 1, expected_nonce);

            gettimeofday(&t_start, NULL);
            tx_message(instance, spk, msg_nonce, 5);

            // Flush the microphone buffer
            snd_pcm_drop(mic);
            snd_pcm_prepare(mic);

            gettimeofday(&loop_start, NULL);
            continue;
        }

        snd_pcm_sframes_t frames_read = snd_pcm_readi(mic, buffer, frames_to_read);
        if (frames_read == -EPIPE) {
            snd_pcm_prepare(mic);
            continue;
        } else if (frames_read < 0) {
            fprintf(stderr, "ALSA read error: %s\n", snd_strerror(frames_read));
            break;
        }

        int decoded_bytes = ggwave_decode(instance, buffer, frames_read * 2, rx_payload);
        if (decoded_bytes > 0) {
            rx_payload[decoded_bytes] = '\0';

            if (rx_payload[0] == 'N' && decoded_bytes == 5) {
                // Ensure it's the nonce we actually sent
                if (strncmp(rx_payload + 1, expected_nonce, 4) == 0) {
                    gettimeofday(&t_end, NULL);

                    double rtt = (t_end.tv_sec - t_start.tv_sec) +
                                 (t_end.tv_usec - t_start.tv_usec) / 1000000.0;

                    printf("VERIFIER: Valid Echo Received! RTT(actual): %f seconds\n", rtt);

                    double flight_time = rtt - SOFTWARE_OVERHEAD_SEC;
                    if (flight_time < 0) flight_time = 0.0;

                    double measured_dist_m = (flight_time * 343.0) / 2.0;
                    double permitted_dist_m = permitted_dist_cm / 100.0;

                    if (measured_dist_m <= permitted_dist_m + TOLERANCE_MARGIN_M) {
                        printf("VERIFIER: ACCEPTED! Measured Dist: %.2fm <= Permitted Dist: %.2fm (Margin: %.1fm)\n",
                                measured_dist_m, permitted_dist_m, TOLERANCE_MARGIN_M);
                    } else {
                        printf("VERIFIER: REJECTED! Measured Dist: %.2fm exceeds Permitted Dist: %.2fm\n",
                                measured_dist_m, permitted_dist_m);
                    }
                    break; // End session after verification
                }
            }
        }
    }

    free(buffer);
    snd_pcm_close(mic);
    snd_pcm_close(spk);
    ggwave_free(instance);
}

// positional arguments
// 1 - mode = "prover" or "verifier"
// 2 - capture device (mic)
// 3 - playback device (speaker)
// 4 - Only for verifier - Allow range in cm
int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <prover|verifier> [args...]\n", argv[0]);
        return 1;
    }

    const char* mode = argv[1];

    if (strcmp(mode, "prover") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Usage: %s prover <capture_device> <playback_device>\n", argv[0]);
            return 1;
        }
        run_prover(argv[2], argv[3]);

    } else if (strcmp(mode, "verifier") == 0) {
        if (argc < 5) {
            fprintf(stderr, "Usage: %s verifier <capture_device> <playback_device> <permitted_dist_cm>\n", argv[0]);
            return 1;
        }
        uint16_t dist_cm = (uint16_t)atoi(argv[4]);
        run_verifier(argv[2], argv[3], dist_cm);

    } else {
        fprintf(stderr, "Unknown mode: %s\n", mode);
        return 1;
    }

    return 0;
}
