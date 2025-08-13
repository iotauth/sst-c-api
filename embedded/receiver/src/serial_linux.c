// src/serial_linux.c
#include <fcntl.h>
#include <stdio.h>
#include <termios.h>
#include <unistd.h>

int init_serial(const char* device, int baudrate) {
    int fd = open(device, O_RDWR | O_NOCTTY);
    if (fd == -1) {
        perror("open serial");
        return -1;
    }

    struct termios opt;
    if (tcgetattr(fd, &opt) != 0) {
        perror("tcgetattr");
        close(fd);
        return -1;
    }

    cfmakeraw(&opt);
    cfsetispeed(&opt, baudrate);
    cfsetospeed(&opt, baudrate);
    opt.c_cflag |= (CLOCAL | CREAD);
    opt.c_cflag &= ~(PARENB | CSTOPB | CSIZE);
    opt.c_cflag |= CS8;
    opt.c_cc[VMIN] = 1;
    opt.c_cc[VTIME] = 1;

    if (tcsetattr(fd, TCSANOW, &opt) != 0) {
        perror("tcsetattr");
        close(fd);
        return -1;
    }
    return fd;
}
