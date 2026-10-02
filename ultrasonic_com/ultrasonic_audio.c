#include "ultrasonic_audio.h"

#include <alsa/asoundlib.h>
#include <stdlib.h>
#include <string.h>

#include "../src/c_common.h"
#include "ggwave/ggwave.h"

#define SAMPLE_RATE 48000
#define TARGET_BIN 224 /* ~10.5 kHz start, as in ggwave_sst_handshake.c */
#define PROTOCOL GGWAVE_PROTOCOL_ULTRASOUND_FAST
#define VOLUME 100
/* Short buffers, so a decode is reported within tens of milliseconds of the
 * response's end marker rather than after a half-second ALSA period. */
#define LATENCY_US 100000
#define FRAMES_PER_READ 1024
#define WARMUP_MS 300

struct ultrasonic_audio {
    snd_pcm_t* mic;
    snd_pcm_t* spk;
    ggwave_Instance gg;
};

static int play(snd_pcm_t* spk, const int16_t* p, snd_pcm_sframes_t left);

static ggwave_Instance new_instance(void) {
    ggwave_Parameters p = ggwave_getDefaultParameters();
    p.sampleRate = SAMPLE_RATE;
    p.sampleRateInp = SAMPLE_RATE;
    p.sampleRateOut = SAMPLE_RATE;
    p.sampleFormatInp = GGWAVE_SAMPLE_FORMAT_I16;
    p.sampleFormatOut = GGWAVE_SAMPLE_FORMAT_I16;
    return ggwave_init(p);
}

static snd_pcm_t* open_pcm(const char* device, snd_pcm_stream_t stream) {
    const char* kind =
        stream == SND_PCM_STREAM_CAPTURE ? "capture" : "playback";
    snd_pcm_t* h = NULL;
    int rc = snd_pcm_open(&h, device, stream, 0);
    if (rc < 0) {
        SST_print_error("ALSA: cannot open %s device '%s': %s", kind, device,
                        snd_strerror(rc));
        return NULL;
    }
    rc = snd_pcm_set_params(h, SND_PCM_FORMAT_S16_LE,
                            SND_PCM_ACCESS_RW_INTERLEAVED, 1, SAMPLE_RATE, 1,
                            LATENCY_US);
    if (rc < 0) {
        SST_print_error("ALSA: cannot configure %s device '%s': %s", kind,
                        device, snd_strerror(rc));
        snd_pcm_close(h);
        return NULL;
    }
    return h;
}

void ultrasonic_audio_close(ultrasonic_audio* a) {
    if (!a) return;
    if (a->gg >= 0) ggwave_free(a->gg);
    if (a->mic) snd_pcm_close(a->mic);
    if (a->spk) snd_pcm_close(a->spk);
    free(a);
}

ultrasonic_audio* ultrasonic_audio_open(const char* mic_device,
                                        const char* spk_device) {
    ultrasonic_audio* a = calloc(1, sizeof(*a));
    if (!a) return NULL;
    a->gg = -1;
    /* ggwave otherwise prints progress to stdout while decoding, i.e.
     * inside the verifier's timed window. */
    ggwave_setLogFile(NULL);
    ggwave_txProtocolSetFreqStart(PROTOCOL, TARGET_BIN);
    ggwave_rxProtocolSetFreqStart(PROTOCOL, TARGET_BIN);
    a->mic = open_pcm(mic_device, SND_PCM_STREAM_CAPTURE);
    a->spk = open_pcm(spk_device, SND_PCM_STREAM_PLAYBACK);
    a->gg = new_instance();
    if (!a->mic || !a->spk || a->gg < 0) {
        if (a->gg < 0) SST_print_error("ggwave: cannot create an instance.");
        ultrasonic_audio_close(a);
        return NULL;
    }
    /* The first playback after opening the USB speaker loses its start
     * (measured on the Pis: a fresh process playing once was decoded as
     * little as 4/10, vs 10/10 for later playbacks), which costs ggwave its
     * start marker. Spend that first playback on silence, here, outside
     * any timed window. */
    static const int16_t silence[SAMPLE_RATE * WARMUP_MS / 1000];
    if (play(a->spk, silence,
             (snd_pcm_sframes_t)(sizeof(silence) / sizeof(silence[0])))) {
        SST_print_error("ALSA: speaker warm-up playback failed.");
        ultrasonic_audio_close(a);
        return NULL;
    }
    return a;
}

/* A fresh decoder and an emptied, running capture stream: nothing played
 * or heard before this point can be decoded afterwards. */
static int rx_begin(void* ctx) {
    ultrasonic_audio* a = ctx;
    ggwave_free(a->gg);
    a->gg = new_instance();
    if (a->gg < 0) return -1;
    snd_pcm_drop(a->mic);
    if (snd_pcm_prepare(a->mic) < 0 || snd_pcm_start(a->mic) < 0) return -1;
    return 0;
}

static int rx_until(void* ctx, unsigned char* buf, unsigned capacity,
                    uint64_t deadline_us) {
    ultrasonic_audio* a = ctx;
    int16_t frames[FRAMES_PER_READ];
    unsigned char decoded[256]; /* above ggwave's 140-byte payload cap */
    while (ultrasonic_echo_now_us() < deadline_us) {
        snd_pcm_sframes_t n = snd_pcm_readi(a->mic, frames, FRAMES_PER_READ);
        if (n == -EPIPE) {
            if (snd_pcm_prepare(a->mic) < 0 || snd_pcm_start(a->mic) < 0)
                return -1;
            continue;
        }
        if (n == -EAGAIN || n == -EINTR) continue;
        if (n < 0) {
            SST_print_error("ALSA read error: %s", snd_strerror((int)n));
            return -1;
        }
        int got = ggwave_ndecode(a->gg, frames, (int)n * (int)sizeof(int16_t),
                                 decoded, (int)sizeof(decoded));
        if (got > 0) {
            unsigned len = (unsigned)got < capacity ? (unsigned)got : capacity;
            memcpy(buf, decoded, len);
            return (int)len;
        }
    }
    return 0;
}

/* Plays frames and returns once they have finished playing. */
static int play(snd_pcm_t* spk, const int16_t* p, snd_pcm_sframes_t left) {
    if (snd_pcm_prepare(spk) < 0) return -1;
    while (left > 0) {
        snd_pcm_sframes_t n = snd_pcm_writei(
            spk, p, left > FRAMES_PER_READ ? FRAMES_PER_READ : left);
        if (n == -EPIPE) {
            if (snd_pcm_prepare(spk) < 0) return -1;
            continue;
        }
        if (n == -EAGAIN || n == -EINTR) continue;
        if (n < 0) {
            SST_print_error("ALSA write error: %s", snd_strerror((int)n));
            return -1;
        }
        p += n;
        left -= n;
    }
    return snd_pcm_drain(spk) < 0 ? -1 : 0;
}

static int tx(void* ctx, const unsigned char* buf, unsigned len) {
    ultrasonic_audio* a = ctx;
    int size = ggwave_encode(a->gg, buf, (int)len, PROTOCOL, VOLUME, NULL, 1);
    if (size <= 0) return -1;
    char* wave = malloc((size_t)size);
    if (!wave) return -1;
    int rc =
        ggwave_encode(a->gg, buf, (int)len, PROTOCOL, VOLUME, wave, 0) > 0
            ? play(a->spk, (const int16_t*)wave, size / (int)sizeof(int16_t))
            : -1;
    free(wave);
    return rc;
}

void ultrasonic_audio_bind(ultrasonic_audio* a, ultrasonic_echo_audio* io) {
    io->ctx = a;
    io->rx_begin = rx_begin;
    io->rx_until = rx_until;
    io->tx = tx;
}
