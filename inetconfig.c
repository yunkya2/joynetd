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

#define FLAG_MAC        (1 << 0)
#define FLAG_IP         (1 << 1)
#define FLAG_MASK       (1 << 2)
#define FLAG_GW         (1 << 3)
#define FLAG_DNS        (1 << 4)
#define FLAG_DOMAIN     (1 << 5)

union inaddr {
    in_addr_t a;
    uint8_t b[4];
};

//****************************************************************************
// Global variables
//****************************************************************************

static union inaddr w5500_gar;
static union inaddr w5500_subr;
static union inaddr w5500_sipr;
static union inaddr w5500_dns;
static uint8_t w5500_mac[6];

static int config_flags = 0;

extern const char joynetd_cfg_tmpl[];

__asm__ (
    ".section .rodata\n"
    "joynetd_cfg_tmpl:\n"
    ".incbin \"joynetd.cfg.tmpl.txt\"\n"
    ".previous\n"
);

//****************************************************************************
// Private functions
//****************************************************************************

static void generate_random_mac(void)
{
    // Generate random MAC address with locally administered bit set
    // Use X68000 system timer as random seed
    struct iocs_time now = _iocs_ontime();
    unsigned long seed = now.sec + now.day;
    
    // Set first byte: locally administered (bit 1 = 1), unicast (bit 0 = 0)
    w5500_mac[0] = 0x02;
    
    // Generate remaining 5 bytes using simple PRNG
    for (int i = 1; i < 6; i++) {
        seed = seed * 1103515245 + 12345;
        w5500_mac[i] = (seed >> 16) & 0xFF;
    }
}

static char *mactoa(const uint8_t *mac)
{
    static char buf[18];
    sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return buf;
}

static char *get_default_cfgfile(char *buf)
{
    // Use default config file path based on executable path
    struct dos_psp *psp = _dos_getpdb();
    strcpy(buf, psp->exe_path);
    strcat(buf, "joynetd.cfg");
    return buf;
}

//****************************************************************************
// Public functions
//****************************************************************************

int read_config(const char *cfgfile)
{
    char cfgdefault[256];
    FILE *fp;

    if (cfgfile == NULL) {
        cfgfile = get_default_cfgfile(cfgdefault);
    }

    if ((fp = fopen(cfgfile, "r")) == NULL) {
        _dos_print("設定ファイルが見つかりません\r\n"
                   "joynetd -c で設定ファイルを生成してください\r\n");
        return -1;
    }

    // Read config file line by line
    int v;
    char line[256];
    char *p;
    char *q;
    while (fgets(line, sizeof(line), fp) != NULL) {
        if (strncasecmp(line, "port=", 5) == 0) {
            v = atoi(&line[5]);
            if (v <= 2) {
                joy_port = v;
            }
        } else if (strncasecmp(line, "trap=", 5) == 0) {
            v = atoi(&line[5]);
            if (v < 8) {
                trap_number = v;
            }
        } else if (strncasecmp(line, "ifname=", 7) == 0) {
            char *n = &line[7];
            size_t len = strlen(n);
            if (len > 0 && n[len - 1] == '\n') {
                n[len - 1] = '\0';
                ifname = malloc(len + 1);
                if (ifname) {
                    strcpy(ifname, n);
                }
            }
        } else if (strncasecmp(line, "mac=", 4) == 0) {
            p = &line[4];
            for (int i = 0; i < 6; i++) {
                w5500_mac[i] = strtoul(p, &q, 16);
                p = q + 1;
            }
            config_flags |= FLAG_MAC;
        } else if (strncasecmp(line, "ip=", 3) == 0) {
            p = &line[3];
            for (int i = 0; i < 4; i++) {
                w5500_sipr.b[i] = strtoul(p, &q, 0);
                p = q + 1;
            }
            config_flags |= FLAG_IP;
        } else if (strncasecmp(line, "mask=", 5) == 0) {
            p = &line[5];
            for (int i = 0; i < 4; i++) {
                w5500_subr.b[i] = strtoul(p, &q, 0);
                p = q + 1;
            }
            config_flags |= FLAG_MASK;
        } else if (strncasecmp(line, "gw=", 3) == 0) {
            p = &line[3];
            for (int i = 0; i < 4; i++) {
                w5500_gar.b[i] = strtoul(p, &q, 0);
                p = q + 1;
            }
            config_flags |= FLAG_GW;
        } else if (strncasecmp(line, "dns=", 4) == 0) {
            p = &line[4];
            for (int i = 0; i < 4; i++) {
                w5500_dns.b[i] = strtoul(p, &q, 0);
                p = q + 1;
            }
            config_flags |= FLAG_DNS;
        } else if (strncasecmp(line, "domain=", 7) == 0) {
            do_set_domain_name(&line[7]);
            config_flags |= FLAG_DOMAIN;
        }
    }

    fclose(fp);
    return 0;
}

int create_config(const char *cfgfile)
{
    char cfgdefault[256];
    FILE *fp;

    // Generate default random MAC address
    generate_random_mac();

    if (cfgfile == NULL) {
        cfgfile = get_default_cfgfile(cfgdefault);
    }

    if ((fp = fopen(cfgfile, "r")) != NULL) {
        _dos_print("設定ファイルが既に存在します\r\n");
        fclose(fp);
        return -1;
    }

    // Create default config file with random MAC address
    if ((fp = fopen(cfgfile, "w")) == NULL) {
        _dos_print("設定ファイルの生成に失敗しました\r\n");
        return -1;
    } else {
        fprintf(fp, joynetd_cfg_tmpl,
                mactoa(w5500_mac),
                joy_port == NOSPEC_INT ? ";" : "",
                joy_port == NOSPEC_INT ? DEFAULT_PORT : joy_port,
                trap_number == NOSPEC_INT ? ";" : "",
                trap_number == NOSPEC_INT ? DEFAULT_TRAP : trap_number,
                ifname == NOSPEC_STR ? ";" : "",
                ifname == NOSPEC_STR ? DEFAULT_IFNAME : ifname
        );
        fclose(fp);
    }
    _dos_print("設定ファイルを生成しました\r\n");
    return 0;
}

void set_config(void)
{
    if (!(config_flags & FLAG_MAC)) {
        printf("※ joynetd.cfg にMACアドレスの指定がないため、ランダムなアドレスを生成します\n");
        generate_random_mac();
    }
    printf("MAC addr: %s\n", mactoa(w5500_mac));
    if (config_flags & FLAG_IP) {
        printf("IP addr : %s\n", inet_ntoa(*(struct in_addr *)&w5500_sipr.a));
    }
    if (config_flags & FLAG_MASK) {
        printf("Netmask : %s\n", inet_ntoa(*(struct in_addr *)&w5500_subr.a));
    }
    if (config_flags & FLAG_GW) {
        printf("Gateway : %s\n", inet_ntoa(*(struct in_addr *)&w5500_gar.a));
    }
    if (config_flags & FLAG_DNS) {
        printf("DNS     : %s\n", inet_ntoa(*(struct in_addr *)&w5500_dns.a));
    }
    if (config_flags & FLAG_DOMAIN) {
        char *domain = do_get_domain_name();
        printf("Domain  : %s\n", domain[0] ? domain : "(none)");
    }

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
    if (config_flags & FLAG_IP) {
        w5500_write_l(W5500_SIPR, 0, w5500_sipr.a);
    }
    if (config_flags & FLAG_MASK) {
        w5500_write_l(W5500_SUBR, 0, w5500_subr.a);
    }
    if (config_flags & FLAG_GW) {
        do_rt_add (0, 0, w5500_gar.a, NULL, 16, 0, 1);
    }
    if (config_flags & FLAG_DNS) {
        do_dns_add(ntohl(w5500_dns.a));
    }

    ifenable = (config_flags & (FLAG_IP|FLAG_MASK|FLAG_GW|FLAG_DNS)) == (FLAG_IP|FLAG_MASK|FLAG_GW|FLAG_DNS);
}
