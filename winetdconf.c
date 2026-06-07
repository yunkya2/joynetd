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
#include "libwifi.h"

//****************************************************************************
// Macros and definitions
//****************************************************************************

//****************************************************************************
// Global variables
//****************************************************************************

//****************************************************************************
// Private functions
//****************************************************************************

char *getpass(const char *prompt)
{
  static char password[32];
  char *p = password;

  printf("%s", prompt);
  fflush(stdout);
  while (1) {
    int ch = _iocs_b_keyinp() & 0xff;
    switch (ch) {
    case '\0':
      continue;
    case '\r':
    case '\n':
      *p = '\0';
      printf("\n");
      return password;
    case '\b':
      if (p > password) {
        p--;
        printf("\b \b");
        fflush(stdout);
      }
      break;
    case '\x03':  // Ctrl-C
    case '\x1b':  // ESC
      printf("\n");
      return NULL;
    case '\x17':  // Ctrl-W
    case '\x15':  // Ctrl-U
      while (p > password && *(p - 1) != ' ') {
        p--;
        printf("\b \b");
        fflush(stdout);
      }
      break;
    default:
      if (p - password < sizeof(password) - 1 &&
          ch >= 32 && ch <= 126) {
        *p++ = (char)ch;
        printf("*");
        fflush(stdout);
      }
      break;
    }
  }
}

//****************************************************************************
// Program entry
//****************************************************************************

int main(int argc, char **argv)
{
    if (wifi_init() < 0) {
        printf("winetdが常駐していません\n");
    }

    char *cmd = "";
    if (argc > 1) {
        cmd = argv[1];
    }

    if (strcmp(cmd, "join") == 0) {
        wifi_join(WIFI_SSID, WIFI_PASSWORD, -1);
        for (int i = 0; i < 300; i++) {
            int stat = wifi_getstat();
            if ((stat & W5500_WSR_JOINED) != 0) {
                printf("WiFi is up\n");
                break;
            }
            if ((stat & W5500_WSR_ERR) != 0) {
                printf("WiFi connection error\n");
                break;
            }
            usleep(100 * 1000);
        }
    } else if (strcmp(cmd, "leave") == 0) {
        wifi_leave();
    } else if (strcmp(cmd, "scan") == 0) {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) {
            printf("socket error\n");
            return 1;
        }

        wifi_scan(fd);

        wifi_scan_result_t result;
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
            }
            usleep(100 * 1000);
        }

        close(fd);
    } else {
        printf("RSSI=%ddBm\n", -wifi_getrssi());
    }

    return 0;
}
