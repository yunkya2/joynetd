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

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <x68k/dos.h>
#include <x68k/iocs.h>

#include "joynetd.h"

//****************************************************************************
// Macros and definitions
//****************************************************************************

union inaddr {
    in_addr_t a;
    uint8_t b[4];
};

//****************************************************************************
// Global variables
//****************************************************************************

union inaddr w5500_gar;
union inaddr w5500_subr;
union inaddr w5500_sipr;
union inaddr w5500_dns;
static uint8_t w5500_mac[6];

//****************************************************************************
// Private functions
//****************************************************************************

void read_config(void)
{
    FILE *fp;
    char cfgname[256];
    struct dos_psp *psp = _dos_getpdb();

    strcpy(cfgname, psp->exe_path);
    strcat(cfgname, "joynetd.cfg");
    if ((fp = fopen(cfgname, "r")) != NULL) {
        char line[256];
        char *p;
        char *q;
        while (fgets(line, sizeof(line), fp) != NULL) {
            if (strncasecmp(line, "mac=", 4) == 0) {
                p = &line[4];
                for (int i = 0; i < 6; i++) {
                    w5500_mac[i] = strtoul(p, &q, 16);
                    p = q + 1;
                }
            } else if (strncasecmp(line, "ip=", 3) == 0) {
                p = &line[3];
                for (int i = 0; i < 4; i++) {
                    w5500_sipr.b[i] = strtoul(p, &q, 0);
                    p = q + 1;
                }
            } else if (strncasecmp(line, "mask=", 5) == 0) {
                p = &line[5];
                for (int i = 0; i < 4; i++) {
                    w5500_subr.b[i] = strtoul(p, &q, 0);
                    p = q + 1;
                }
            } else if (strncasecmp(line, "gw=", 3) == 0) {
                p = &line[3];
                for (int i = 0; i < 4; i++) {
                    w5500_gar.b[i] = strtoul(p, &q, 0);
                    p = q + 1;
                }
            } else if (strncasecmp(line, "dns=", 4) == 0) {
                p = &line[4];
                for (int i = 0; i < 4; i++) {
                    w5500_dns.b[i] = strtoul(p, &q, 0);
                    p = q + 1;
                }
            } else if (strncasecmp(line, "domain=", 7) == 0) {
                do_set_domain_name(&line[7]);
            }
        }
        fclose(fp);
    }

    printf("MAC: ");
    for (int i = 0; i < 6; i++) {
        printf("%02x%s", w5500_mac[i], i < 5 ? ":" : "");
    }
    printf("\nIP: ");
    for (int i = 0; i < 4; i++) {
        printf("%d%s", w5500_sipr.b[i], i < 3 ? "." : "");
    }
    printf("\nnetmask: ");
    for (int i = 0; i < 4; i++) {
        printf("%d%s", w5500_subr.b[i], i < 3 ? "." : "");
    }
    printf("\ngateway: ");
    for (int i = 0; i < 4; i++) {
        printf("%d%s", w5500_gar.b[i], i < 3 ? "." : "");
    }
    printf("\nDNS: ");
    for (int i = 0; i < 4; i++) {
        printf("%d%s", w5500_dns.b[i], i < 3 ? "." : "");
    }
    printf("\n");

#ifdef DEBUG
    for (int i = 0; i < 0x40; i += 0x10) {
        uint8_t data[16];
        w5500_read(i, 0, data, 16);
        for (int j = 0; j < 16; j++) {
            PRINTF(" %02x", data[j]);
        }
        PRINTF("\n");
    }
    PRINTF("\n");
#endif

    // Configure W5500 network settings

    w5500_write(W5500_SHAR, 0, w5500_mac, 6);
    w5500_write_l(W5500_GAR, 0, w5500_gar.a);
    w5500_write_l(W5500_SUBR, 0, w5500_subr.a);
    w5500_write_l(W5500_SIPR, 0, w5500_sipr.a);
}
