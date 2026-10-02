/*
 * Ultrasonic RTT Prover (Responder / Echo Node) using GGWave and ALSA
 *
 * Compilation:
 *   gcc -O3 rtt_prover.c -o rtt_prover -lasound -lggwave -lm
 *
 * Usage:
 *   ./rtt_prover <mic_device> <spk_device>
 *   Example:
 *     ./rtt_prover plughw:3,0 plughw:4,0
 */

#include <alsa/asoundlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "ggwave/ggwave.h"

#define SAMPLE_RATE 48000      // 48 kHz sampling rate
#define CHANNELS 1             // Mono channel audio
#define TARGET_BIN 224         // 224th FFT bin -> ~10.5 kHz center frequency
#define ALSA_LATENCY_US 50000  // 50ms buffer latency for lower delay & jitter

static inline double get_time_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

void setup_ggwave_freq(void) {
    ggwave_txProtocolSetFreqStart(GGWAVE_PROTOCOL_ULTRASOUND_FAST, TARGET_BIN);
    ggwave_rxProtocolSetFreqStart(GGWAVE_PROTOCOL_ULTRASOUND_FAST, TARGET_BIN);
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

    int total_frames = buffer_size_bytes / 2;
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
        fprintf(stderr, "Usage: %s <capture_mic> <playback_spk>\n", argv[0]);
        fprintf(stderr, "Example: %s plughw:3,0 plughw:4,0\n", argv[0]);
        return 1;
    }

    const char* mic_device = argv[1];
    const char* spk_device = argv[2];

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

    printf("====================================================\n");
    printf(" PROVER: Ultrasonic Echo Responder Active\n");
    printf(" Capture Device : %s\n", mic_device);
    printf(" Playback Device: %s\n", spk_device);
    printf(" Listening for Challenge (Nonce)... Press Ctrl+C to stop.\n");
    printf("====================================================\n\n");

    int echo_count = 0;

    while (1) {
        snd_pcm_sframes_t frames_read =
            snd_pcm_readi(mic, buffer, frames_to_read);
        if (frames_read == -EPIPE) {
            snd_pcm_prepare(mic);
            continue;
        } else if (frames_read < 0) {
            fprintf(stderr, "PROVER ALSA read error: %s\n",
                    snd_strerror((int)frames_read));
            break;
        }

        int decoded_bytes =
            ggwave_decode(instance, buffer, (int)frames_read * 2, rx_payload);
        if (decoded_bytes > 0) {
            rx_payload[decoded_bytes] = '\0';

            if (rx_payload[0] == 'N' && decoded_bytes == 5) {
                echo_count++;
                double echo_time = get_time_sec();
                printf(
                    "[%d] PROVER: Received Nonce '%s' at %.6f s -> Echoing "
                    "back!\n",
                    echo_count, rx_payload, echo_time);

                // Echo the received nonce verbatim back to Verifier
                tx_message(instance, spk, rx_payload, 5);

                // Flush microphone buffer to prevent hearing own transmission
                flush_mic(mic);
                ggwave_rxProtocolSetFreqStart(GGWAVE_PROTOCOL_ULTRASOUND_FAST,
                                              TARGET_BIN);

                printf(
                    "    PROVER: Echo sent successfully. Waiting for next "
                    "Challenge...\n\n");
            }
        }
    }

    free(buffer);
    snd_pcm_close(mic);
    snd_pcm_close(spk);
    ggwave_free(instance);
    return 0;
}
