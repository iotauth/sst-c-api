/*
 * Ultrasonic RTT Verifier (Initiator) using GGWave and ALSA
 *
 * Compilation:
 *   gcc -O3 rtt_verifier.c -o rtt_verifier -lasound -lggwave -lm
 *
 * Usage:
 *   ./rtt_verifier <mic_device> <spk_device> [permitted_dist_cm] [iterations]
 * [software_overhead_sec] Example:
 *     ./rtt_verifier plughw:3,0 plughw:4,0 100 10 2.1125
 */

#include <alsa/asoundlib.h>
#include <fcntl.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "ggwave/ggwave.h"

// Configuration Constants
#define SAMPLE_RATE 48000  // 48 kHz sampling rate
#define CHANNELS 1         // Mono channel audio
#define TARGET_BIN 224     // 224th FFT bin -> ~10.5 kHz center frequency

#define ALSA_LATENCY_US 50000  // 50ms buffer latency for lower delay & jitter
#define SPEED_OF_SOUND_M_S 343.0  // Speed of sound in air (m/s)

// Monotonic Nanosecond Timer
static inline double get_time_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

void setup_ggwave_freq(void) {
    ggwave_txProtocolSetFreqStart(GGWAVE_PROTOCOL_ULTRASOUND_FAST, TARGET_BIN);
    ggwave_rxProtocolSetFreqStart(GGWAVE_PROTOCOL_ULTRASOUND_FAST, TARGET_BIN);
}

// Generates 4-byte random alphanumeric nonce prefixed with 'N' (e.g. "N7K9A")
void generate_nonce(char* nonce_out) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        perror("Failed to open /dev/urandom");
        exit(1);
    }
    unsigned char rand_bytes[4];
    if (read(fd, rand_bytes, 4) != 4) {
        perror("Failed to read random bytes");
        close(fd);
        exit(1);
    }
    close(fd);

    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    nonce_out[0] = 'N';
    for (int i = 0; i < 4; i++) {
        nonce_out[i + 1] = charset[rand_bytes[i] % (sizeof(charset) - 1)];
    }
    nonce_out[5] = '\0';
}

snd_pcm_t* open_playback(const char* device) {
    snd_pcm_t* pcm_handle;
    int err = snd_pcm_open(&pcm_handle, device, SND_PCM_STREAM_PLAYBACK, 0);
    if (err < 0) {
        fprintf(stderr, "Error opening ALSA playback device '%s': %s\n", device,
                snd_strerror(err));
        exit(1);
    }
    err = snd_pcm_set_params(pcm_handle, SND_PCM_FORMAT_S16_LE,
                             SND_PCM_ACCESS_RW_INTERLEAVED, CHANNELS,
                             SAMPLE_RATE, 1, ALSA_LATENCY_US);
    if (err < 0) {
        fprintf(stderr, "Error setting playback params on device '%s': %s\n",
                device, snd_strerror(err));
        exit(1);
    }
    return pcm_handle;
}

snd_pcm_t* open_capture(const char* device) {
    snd_pcm_t* pcm_handle;
    int err = snd_pcm_open(&pcm_handle, device, SND_PCM_STREAM_CAPTURE, 0);
    if (err < 0) {
        fprintf(stderr, "Error opening ALSA capture device '%s': %s\n", device,
                snd_strerror(err));
        exit(1);
    }
    err = snd_pcm_set_params(pcm_handle, SND_PCM_FORMAT_S16_LE,
                             SND_PCM_ACCESS_RW_INTERLEAVED, CHANNELS,
                             SAMPLE_RATE, 1, ALSA_LATENCY_US);
    if (err < 0) {
        fprintf(stderr, "Error setting capture params on device '%s': %s\n",
                device, snd_strerror(err));
        exit(1);
    }
    return pcm_handle;
}

void tx_message(ggwave_Instance instance, snd_pcm_t* pcm_handle,
                const char* payload, int payload_len) {
    int buffer_size_bytes =
        ggwave_encode(instance, payload, payload_len,
                      GGWAVE_PROTOCOL_ULTRASOUND_FAST, 100, NULL, 1);
    if (buffer_size_bytes <= 0) {
        fprintf(stderr, "ggwave_encode error during calculation\n");
        return;
    }

    char* waveform = (char*)malloc(buffer_size_bytes);
    ggwave_encode(instance, payload, payload_len,
                  GGWAVE_PROTOCOL_ULTRASOUND_FAST, 100, waveform, 0);

    int total_frames = buffer_size_bytes / 2;  // 16-bit PCM = 2 bytes/sample
    int frames_written_total = 0;
    int chunk_size = 1024;
    int16_t* audio_ptr = (int16_t*)waveform;

    snd_pcm_prepare(pcm_handle);

    while (frames_written_total < total_frames) {
        int frames_to_write = total_frames - frames_written_total;
        if (frames_to_write > chunk_size) frames_to_write = chunk_size;

        snd_pcm_sframes_t frames =
            snd_pcm_writei(pcm_handle, audio_ptr, frames_to_write);
        if (frames == -EPIPE) {
            snd_pcm_prepare(pcm_handle);
        } else if (frames < 0) {
            fprintf(stderr, "ALSA write error: %s\n",
                    snd_strerror((int)frames));
            break;
        } else {
            audio_ptr += frames;
            frames_written_total += (int)frames;
        }
    }

    snd_pcm_drain(pcm_handle);
    free(waveform);
}

void flush_mic(snd_pcm_t* mic) {
    snd_pcm_drop(mic);
    snd_pcm_prepare(mic);
}

int main(int argc, char** argv) {
    if (argc < 3) {
        fprintf(stderr,
                "Usage: %s <capture_mic> <playback_spk> [permitted_dist_cm] "
                "[iterations] [software_overhead_sec]\n",
                argv[0]);
        fprintf(stderr, "Example: %s plughw:3,0 plughw:4,0 100 10 0.0\n",
                argv[0]);
        return 1;
    }

    const char* mic_device = argv[1];
    const char* spk_device = argv[2];
    uint16_t permitted_dist_cm = (argc >= 4) ? (uint16_t)atoi(argv[3]) : 100;
    int target_iterations = (argc >= 5) ? atoi(argv[4]) : 10;
    double software_overhead_sec = (argc >= 6) ? atof(argv[5]) : 0.0;

    ggwave_Parameters parameters = ggwave_getDefaultParameters();
    parameters.sampleRate = SAMPLE_RATE;
    parameters.sampleFormatInp = GGWAVE_SAMPLE_FORMAT_I16;
    parameters.sampleFormatOut = GGWAVE_SAMPLE_FORMAT_I16;

    setup_ggwave_freq();
    ggwave_Instance instance = ggwave_init(parameters);

    snd_pcm_t* mic = open_capture(mic_device);
    snd_pcm_t* spk = open_playback(spk_device);

    int frames_to_read = 1024;
    char* buffer = (char*)malloc(frames_to_read * 2);
    char rx_payload[256];

    char nonce[6];
    double rtt_sum = 0.0;
    double rtt_min = 1e9;
    double rtt_max = 0.0;
    int success_count = 0;

    printf("====================================================\n");
    printf(" VERIFIER: Ultrasonic RTT Measurement\n");
    printf(" Permitted Distance: %u cm\n", permitted_dist_cm);
    printf(" Target Iterations : %d\n", target_iterations);
    printf(" Overhead Offset   : %.6f s\n", software_overhead_sec);
    printf(" Playback Device   : %s\n", spk_device);
    printf(" Capture Device    : %s\n", mic_device);
    printf("====================================================\n\n");

    for (int iter = 1; iter <= target_iterations; iter++) {
        generate_nonce(nonce);
        printf("[%d/%d] VERIFIER: Sending Nonce '%s'...\n", iter,
               target_iterations, nonce);

        // Record precise start time right before transmission
        double t_start = get_time_sec();
        tx_message(instance, spk, nonce, 5);

        // Flush local microphone buffer to prevent decoding speaker playback
        flush_mic(mic);

        double t_listen_start = get_time_sec();
        const double TIMEOUT_SEC = 2.5;  // 2.5s timeout waiting for reply

        while (1) {
            double current_time = get_time_sec();
            if (current_time - t_listen_start > TIMEOUT_SEC) {
                printf(
                    "    VERIFIER: TIMEOUT (%.2f s) waiting for echo of "
                    "'%s'\n\n",
                    TIMEOUT_SEC, nonce);
                break;
            }

            snd_pcm_sframes_t frames_read =
                snd_pcm_readi(mic, buffer, frames_to_read);
            if (frames_read == -EPIPE) {
                snd_pcm_prepare(mic);
                continue;
            } else if (frames_read < 0) {
                fprintf(stderr, "ALSA read error: %s\n",
                        snd_strerror((int)frames_read));
                break;
            }

            int decoded_bytes = ggwave_decode(instance, buffer,
                                              (int)frames_read * 2, rx_payload);
            if (decoded_bytes > 0) {
                rx_payload[decoded_bytes] = '\0';

                // Check if decoded payload matches transmitted nonce
                if (rx_payload[0] == 'N' && decoded_bytes == 5 &&
                    strcmp(rx_payload, nonce) == 0) {
                    double t_end = get_time_sec();
                    double raw_rtt_sec = t_end - t_start;
                    double net_flight_time_sec =
                        raw_rtt_sec - software_overhead_sec;
                    if (net_flight_time_sec < 0) net_flight_time_sec = 0.0;

                    double measured_dist_m =
                        (net_flight_time_sec * SPEED_OF_SOUND_M_S) / 2.0;
                    double permitted_dist_m = permitted_dist_cm / 100.0;

                    printf("    VERIFIER: Valid Echo Received!\n");
                    printf("    - Raw RTT (total)    : %.6f s (%.2f ms)\n",
                           raw_rtt_sec, raw_rtt_sec * 1000.0);
                    if (software_overhead_sec > 0.0) {
                        printf("    - Net Flight Time    : %.6f s (%.2f ms)\n",
                               net_flight_time_sec,
                               net_flight_time_sec * 1000.0);
                    }
                    printf("    - Measured Distance  : %.3f m (%.1f cm)\n",
                           measured_dist_m, measured_dist_m * 100.0);

                    if (measured_dist_m <= permitted_dist_m) {
                        printf(
                            "    - Result             : ACCEPTED (within %.2fm "
                            "limit)\n",
                            permitted_dist_m);
                    } else {
                        printf(
                            "    - Result             : REJECTED (exceeds "
                            "%.2fm limit)\n",
                            permitted_dist_m);
                    }
                    printf("\n");

                    rtt_sum += raw_rtt_sec;
                    if (raw_rtt_sec < rtt_min) rtt_min = raw_rtt_sec;
                    if (raw_rtt_sec > rtt_max) rtt_max = raw_rtt_sec;
                    success_count++;
                    break;
                }
            }
        }

        usleep(300000);  // 300 ms inter-ping delay
    }

    printf("====================================================\n");
    printf(" SUMMARY RTT STATISTICS (%d/%d Successful)\n", success_count,
           target_iterations);
    printf("====================================================\n");
    if (success_count > 0) {
        double avg_raw_rtt = rtt_sum / success_count;
        double jitter = rtt_max - rtt_min;
        double target_dist_m = permitted_dist_cm / 100.0;
        double ideal_flight_rtt = (target_dist_m * 2.0) / SPEED_OF_SOUND_M_S;
        double rec_overhead = avg_raw_rtt - ideal_flight_rtt;

        printf(" Average Raw RTT  : %.6f s (%.2f ms)\n", avg_raw_rtt,
               avg_raw_rtt * 1000.0);
        printf(" Min Raw RTT      : %.6f s (%.2f ms)\n", rtt_min,
               rtt_min * 1000.0);
        printf(" Max Raw RTT      : %.6f s (%.2f ms)\n", rtt_max,
               rtt_max * 1000.0);
        printf(" Jitter (Max-Min) : %.6f s (%.2f ms)\n", jitter,
               jitter * 1000.0);
        printf("----------------------------------------------------\n");
        printf(" Theoretical Air RTT (for %.2fm) : %.6f s (%.2f ms)\n",
               target_dist_m, ideal_flight_rtt, ideal_flight_rtt * 1000.0);
        printf(" Calibrated Software Overhead    : %.6f s\n", rec_overhead);
        printf(" (Run with 5th argument: '%.6f' to calibrate distance)\n",
               rec_overhead);
    } else {
        printf(" No valid echoes received across iterations.\n");
    }
    printf("====================================================\n");

    free(buffer);
    snd_pcm_close(mic);
    snd_pcm_close(spk);
    ggwave_free(instance);
    return 0;
}
