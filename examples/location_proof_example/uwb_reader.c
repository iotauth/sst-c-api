/**
 * @file uwb_reader.c
 * @brief Reads and parses DWM3001 UWB ranging measurements.
 */

#include "uwb_reader.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#define SERIAL_BUFFER_SIZE 512

int uwb_open(void)
{
    int fd = open(UWB_SERIAL_DEVICE, O_RDWR | O_NOCTTY);

    if (fd < 0) {
        perror("Failed to open UWB serial device");
        return -1;
    }

    struct termios tty;

    if (tcgetattr(fd, &tty) != 0) {
        perror("Failed to read serial configuration");
        close(fd);
        return -1;
    }

    cfsetispeed(&tty, UWB_BAUD_RATE);
    cfsetospeed(&tty, UWB_BAUD_RATE);

    tty.c_cflag &= ~PARENB;
    tty.c_cflag &= ~CSTOPB;
    tty.c_cflag &= ~CSIZE;
    tty.c_cflag |= CS8;

    tty.c_cflag &= ~CRTSCTS;
    tty.c_cflag |= CREAD | CLOCAL;

    tty.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);
    tty.c_iflag &= ~(IXON | IXOFF | IXANY);
    tty.c_oflag &= ~OPOST;

    tty.c_cc[VMIN] = 1;
    tty.c_cc[VTIME] = 0;

    if (tcsetattr(fd, TCSANOW, &tty) != 0) {
        perror("Failed to configure UWB serial device");
        close(fd);
        return -1;
    }

    tcflush(fd, TCIFLUSH);

    return fd;
}

static bool parse_measurement(
    const char *line,
    AnchorMeasurement *measurement
)
{
    unsigned int anchor_id;
    int distance_cm;

    const char *mac = strstr(line, "mac_address=0x");
    const char *status = strstr(line, "status=\"SUCCESS\"");
    const char *distance = strstr(line, "distance[cm]=");

    if (mac == NULL || status == NULL || distance == NULL) {
        return false;
    }

    if (sscanf(mac, "mac_address=0x%x", &anchor_id) != 1) {
        return false;
    }

    if (sscanf(distance, "distance[cm]=%d", &distance_cm) != 1) {
        return false;
    }

    if (anchor_id < 1 || anchor_id > UWB_ANCHOR_COUNT) {
        return false;
    }

    if (distance_cm < 0) {
        return false;
    }

    measurement->id = (int)anchor_id;
    measurement->distance = distance_cm / 100.0;

    return true;
}

bool uwb_read_measurements(
    int fd,
    AnchorMeasurement measurements[UWB_ANCHOR_COUNT]
)
{
    char line[SERIAL_BUFFER_SIZE];
    size_t line_length = 0;

    bool received[UWB_ANCHOR_COUNT] = {false};
    int measurement_count = 0;

    while (measurement_count < UWB_ANCHOR_COUNT) {
        char ch;

        ssize_t bytes_read = read(fd, &ch, 1);

        if (bytes_read < 0) {
            perror("Failed to read UWB serial data");
            return false;
        }

        if (ch == '\r') {
            continue;
        }

        if (ch == '\n') {
            line[line_length] = '\0';

            AnchorMeasurement measurement;

            if (parse_measurement(line, &measurement)) {
                int index = measurement.id - 1;

                if (!received[index]) {
                    measurements[index] = measurement;
                    received[index] = true;
                    measurement_count++;
                }
            }

            line_length = 0;
            continue;
        }

        if (line_length < SERIAL_BUFFER_SIZE - 1) {
            line[line_length++] = ch;
        } else {
            line_length = 0;
        }
    }

    return true;
}

void uwb_close(int fd)
{
    if (fd >= 0) {
        close(fd);
    }
}