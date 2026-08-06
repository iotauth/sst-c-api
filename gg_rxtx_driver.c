/*
 * Ultrasonic Communication using GGWave and ALSA
 *
 * Compilation:
 *   gcc -O3 -o gg_driver gg_rxtx_driver.c -lggwave -lasound
 *
 * Usage:
 *   Transmit (TX):
 *     ./gg_driver tx <device> "Message to send"
 *     Example: ./gg_driver tx plughw:3,0 "Hello Pi"
 *
 *   Receive (RX):
 *     ./gg_driver rx <device>
 *     Example: ./gg_driver rx plughw:4,0
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <alsa/asoundlib.h>
#include <ggwave/ggwave.h>

#define SAMPLE_RATE 48000
#define CHANNELS 1

// Shift frequency to 10.5 kHz (10500 / (48000 / 1024) = 224)
#define TARGET_BIN 224

void setup_ggwave_freq() {
    ggwave_txProtocolSetFreqStart(GGWAVE_PROTOCOL_ULTRASOUND_FAST, TARGET_BIN);
    ggwave_rxProtocolSetFreqStart(GGWAVE_PROTOCOL_ULTRASOUND_FAST, TARGET_BIN);
}

void run_tx(const char* device, const char* payload) {
    // 1. Setup GGWave
    ggwave_Parameters params = ggwave_getDefaultParameters();
    params.sampleRate = SAMPLE_RATE;
    params.sampleFormatOut = GGWAVE_SAMPLE_FORMAT_I16;

    setup_ggwave_freq(); // run this befor initilizing the ggwave, for custome configuration
    ggwave_Instance instance = ggwave_init(params);

    // 2. Encode Payload to Audio
    int payload_len = strlen(payload);

    // Set volume to 100 for near-ultrasound to maximize signal strength
    int buffer_size_bytes = ggwave_encode(instance, payload, payload_len, GGWAVE_PROTOCOL_ULTRASOUND_FAST, 100, NULL, 1);

    char *waveform = (char *)malloc(buffer_size_bytes);
    ggwave_encode(instance, payload, payload_len, GGWAVE_PROTOCOL_ULTRASOUND_FAST, 100, waveform, 0);

    // 3. Setup ALSA Playback
    snd_pcm_t *pcm_handle;
    if (snd_pcm_open(&pcm_handle, device, SND_PCM_STREAM_PLAYBACK, 0) < 0) {
        fprintf(stderr, "Error opening ALSA playback device '%s'.\n", device);
        exit(1);
    }

    snd_pcm_set_params(pcm_handle, SND_PCM_FORMAT_S16_LE, SND_PCM_ACCESS_RW_INTERLEAVED, CHANNELS, SAMPLE_RATE, 1, 500000);

    // 4. Play the Audio in Chunks (Like your test script)
    int total_frames = buffer_size_bytes / 2; // 16-bit = 2 bytes per frame
    int frames_written_total = 0;
    int chunk_size = 1024;
    int16_t *audio_ptr = (int16_t *)waveform;

    printf("Transmitting '%s' over ultrasound on device %s...\n", payload, device);

    while (frames_written_total < total_frames) {
        int frames_to_write = total_frames - frames_written_total;
        if (frames_to_write > chunk_size) {
            frames_to_write = chunk_size;
        }

        snd_pcm_sframes_t frames = snd_pcm_writei(pcm_handle, audio_ptr, frames_to_write);

        if (frames == -EPIPE) {
            snd_pcm_prepare(pcm_handle); // Recover from buffer underrun
        } else if (frames < 0) {
            fprintf(stderr, "ALSA write error: %s\n", snd_strerror(frames));
            break;
        } else {
            // Advance the pointer by the number of frames actually written
            audio_ptr += frames;
            frames_written_total += frames;
        }
    }

    // 5. Cleanup
    snd_pcm_drain(pcm_handle);
    snd_pcm_close(pcm_handle);
    free(waveform);
    ggwave_free(instance);
}
void run_rx(const char* device) {
    // 1. Setup GGWave
    ggwave_Parameters params = ggwave_getDefaultParameters();
    params.sampleRate = SAMPLE_RATE;
    params.sampleFormatInp = GGWAVE_SAMPLE_FORMAT_I16;

    setup_ggwave_freq(); // run this befor initilizing the ggwave, for custome configuration
    ggwave_Instance instance = ggwave_init(params);


    // 2. Setup ALSA Capture using the provided device string
    snd_pcm_t *pcm_handle;
    if (snd_pcm_open(&pcm_handle, device, SND_PCM_STREAM_CAPTURE, 0) < 0) {
        fprintf(stderr, "Error opening ALSA capture device '%s'.\n", device);
        exit(1);
    }

    snd_pcm_set_params(pcm_handle, SND_PCM_FORMAT_S16_LE, SND_PCM_ACCESS_RW_INTERLEAVED, CHANNELS, SAMPLE_RATE, 1, 500000);

    // 3. Listen Loop
    printf("Listening for ultrasound on 10.5 kHz - 15 kHz band on device %s...\n", device);
    printf("Press Ctrl+C to stop.\n");

    int frames_to_read = 1024;
    int buffer_size = frames_to_read * 2; // 16-bit = 2 bytes
    char *buffer = (char *)malloc(buffer_size);
    char rx_payload[256];

    while (1) {
        snd_pcm_sframes_t frames_read = snd_pcm_readi(pcm_handle, buffer, frames_to_read);

        if (frames_read == -EPIPE) {
            snd_pcm_prepare(pcm_handle); // Handle overrun
            continue;
        } else if (frames_read < 0) {
            fprintf(stderr, "ALSA read error: %s\n", snd_strerror(frames_read));
            continue;
        }

        // Pass captured audio to ggwave
        int decoded_bytes = ggwave_decode(instance, buffer, frames_read * 2, rx_payload);

        if (decoded_bytes > 0) {
            rx_payload[decoded_bytes] = '\0';
            printf("\n--- Payload Received ---\n");
            printf("%s\n", rx_payload);
            printf("------------------------\n\n");
        }
    }

    // Cleanup
    free(buffer);
    snd_pcm_close(pcm_handle);
    ggwave_free(instance);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        printf("Usage:\n");
        printf("  Transmit: %s tx <device> \"Message to send\"\n", argv[0]);
        printf("  Receive:  %s rx <device>\n", argv[0]);
        printf("\nExamples:\n");
        printf("  %s rx plughw:1,0\n", argv[0]);
        printf("  %s tx plughw:2,0 \"Hello Pi\"\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "tx") == 0) {
        if (argc < 4) {
            printf("Error: Missing message to transmit.\n");
            return 1;
        }
        run_tx(argv[2], argv[3]);
    } else if (strcmp(argv[1], "rx") == 0) {
        run_rx(argv[2]);
    } else {
        printf("Invalid mode. Use 'tx' or 'rx'.\n");
    }

    return 0;
}
