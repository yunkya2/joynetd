/*
 * Copyright (c) 2026 Yuichi Nakamura (@yunkya2)
 *
 * The MIT License (MIT)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <sys/socket.h>
#include <sys/endian.h>

#include <x68k/dos.h>
#include <x68k/iocs.h>

#include "winetd.h"
#include "winetdcmd.h"

//****************************************************************************
// Macros and definitions
//****************************************************************************

typedef long (*_ti_func) (long, void *);
extern _ti_func __sock_func;

_ti_func __sock_search_ti_entry (void);

typedef struct _cyw43_ev_scan_result_t {
    uint32_t _0[5];
    uint8_t bssid[6];   ///< access point mac address
    uint16_t _1[2];
    uint8_t ssid_len;   ///< length of wlan access point name
    uint8_t ssid[32];   ///< wlan access point name
    uint32_t _2[5];
    uint16_t channel;   ///< wifi channel
    uint16_t _3;
    uint8_t auth_mode;  ///< wifi auth mode \ref CYW43_AUTH_
    int16_t rssi;       ///< signal strength
} cyw43_ev_scan_result_t;

//****************************************************************************
// Global variables
//****************************************************************************

//****************************************************************************
// Private functions
//****************************************************************************

#include <errno.h>

int wifi_getrssi(void)
{
    if (!__sock_func) {
        errno = ENOSYS;
        return -1;
    }

    return __sock_func(WTI_GETRSSI, NULL);
}

int wifi_scan(int sockfd)
{
    if (!__sock_func) {
        errno = ENOSYS;
        return -1;
    }

    return __sock_func(WTI_SCAN, (long *)sockfd);
}

int wifi_scanresult(int sockfd, void *buf, size_t len)
{
    if (!__sock_func) {
        errno = ENOSYS;
        return -1;
    }

    long arg[3];

    arg[0] = sockfd;
    arg[1] = (long)buf;
    arg[2] = len;

    return __sock_func(WTI_SCANRESULT, arg);
}

//****************************************************************************
// Program entry
//****************************************************************************

int main(int argc, char **argv)
{

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        printf("socket error\n");
        return 1;
    }

    // winetd常駐確認

    printf("RSSI=%ddBm\n", -wifi_getrssi());

    wifi_scan(fd);

    cyw43_ev_scan_result_t result;
    int res;
    while ((res = wifi_scanresult(fd, &result, sizeof(result))) >= 0) {
        if (res > 0) {
            printf("SSID: %s, BSSID: %02x:%02x:%02x:%02x:%02x:%02x, Channel: %d, Auth: %d, RSSI: %ddBm\n",
                   result.ssid,
                   result.bssid[0], result.bssid[1], result.bssid[2],
                   result.bssid[3], result.bssid[4], result.bssid[5],
                   le16toh(result.channel),
                   result.auth_mode, 
                   (int16_t)le16toh(result.rssi));
#if 0
            for (int i = 0; i < sizeof(result); i++) {
                if (i % 16 == 0) {
                    printf("%04x: ", i);
                }
                printf("%02x ", ((uint8_t *)&result)[i]);
                if (i % 16 == 15) {
                    printf("\n");
                }
            }
#endif
        }
        usleep(100 * 1000);
    }

    close(fd);

    return 0;
}
