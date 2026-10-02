#ifndef SST_ULTRASONIC_AUDIO_H
#define SST_ULTRASONIC_AUDIO_H

#include "ultrasonic_echo.h"

/* ALSA/ggwave implementation of ultrasonic_echo_audio (Linux only). Uses
 * the same 48 kHz mono 16-bit PCM and ggwave ULTRASOUND_FAST protocol
 * shifted to start at ~10.5 kHz as ggwave_sst_handshake.c -- audible-range
 * despite the protocol's name. */
typedef struct ultrasonic_audio ultrasonic_audio;

/* Opens both devices and sets them up; done outside any timed window.
 * @return NULL (after logging why) if either device can't be opened. */
ultrasonic_audio* ultrasonic_audio_open(const char* mic_device,
                                        const char* spk_device);
void ultrasonic_audio_close(ultrasonic_audio* audio);
void ultrasonic_audio_bind(ultrasonic_audio* audio, ultrasonic_echo_audio* io);

#endif
