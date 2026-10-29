#ifndef SST_AMBIENT_AUDIO_DEVICE_H
#define SST_AMBIENT_AUDIO_DEVICE_H

#include "ambient_audio.h"

/* Device implementation of ambient_audio_io (Linux only): captures with ALSA
 * `arecord` and runs the Python ambient_audio compare tool. `mic_device` is an
 * ALSA capture device (e.g. plughw:3,0). The compare command prefix comes from
 * $AMBIENT_AUDIO_CMD (default "python3 -m ambient_audio"); set PYTHONPATH so it
 * resolves to entity/python. */
typedef struct ambient_audio_device ambient_audio_device;

ambient_audio_device* ambient_audio_device_open(const char* mic_device);
void ambient_audio_device_close(ambient_audio_device* device);
void ambient_audio_device_bind(ambient_audio_device* device,
                               ambient_audio_io* io);

#endif
