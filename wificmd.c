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
#include <errno.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <x68k/dos.h>
#include <x68k/iocs.h>

#include "winetd.h"
#include "wificmd.h"

//****************************************************************************
// Macros and definitions
//****************************************************************************

//****************************************************************************
// Global variables
//****************************************************************************

//****************************************************************************
// Private functions
//****************************************************************************

static void wifi_command(uint8_t cmd)
{
    w5500_write_b(W5500_WCR, 0, cmd);
    // コマンドが完了するまで待つ
    while (w5500_read_b(W5500_WCR, 0) != 0)
        ;
}

//****************************************************************************
// Public functions
//****************************************************************************

int do_wifi_getrssi(void)
{
    wifi_command(W5500_WCR_GETRSSI);
    return (int8_t)w5500_read_b(W5500_WRSSI, 0);
}

int do_wifi_getstat(void)
{
    uint8_t oldstat = w5500_read_b(W5500_WSR, 0);
    wifi_command(W5500_WCR_GETSTAT);
    uint8_t newstat = w5500_read_b(W5500_WSR, 0);
    if (!(oldstat & W5500_WSR_JOINED) && (newstat & W5500_WSR_JOINED)) {
        do_rt_add(0, 0, w5500_read_l(W5500_GAR, 0), NULL, 16, 0, 1);
        do_dns_add(w5500_read_l(W5500_WDNSR, 0));
        ifenable = true;
    }
    return newstat;
}

int do_wifi_scan(int sno)
{
    if ((do_wifi_getstat() & W5500_WSR_SCANNING) != 0) {
        PRINTF("WiFi is already scanning\n");
        return -1;
    }

    int blk_sreg = sno * 4 + 1;
    w5500_write_b(W5500_Sn_CR, blk_sreg, W5500_WCR_SCAN);
    return 0;
}

int do_wifi_scanresult(int sno, void *buf, size_t len)
{
    int blk_sreg = sno * 4 + 1;
    int blk_rxbuf = sno * 4 + 3;

    int bytes = w5500_read_w(W5500_Sn_RX_RSR, blk_sreg);
    if (bytes == 0) {
        if ((do_wifi_getstat() & W5500_WSR_SCANNING) == 0) {
            return -1;
        } else {
            return 0;
        }
    }

    len = (len < bytes) ? len : bytes;
    int ptr = w5500_read_w(W5500_Sn_RX_RD, blk_sreg);
//    printf("len = %d bytes= %d ptr=%d\n", len, bytes, ptr);
    w5500_read(ptr, blk_rxbuf, (uint8_t *)buf, len);

#if 0
    for (int i = 0; i < len; i++) {
        if ((i % 16) == 0) {
            printf("%04x: ", i);
        }
        printf("%02x ", ((uint8_t *)buf)[i]);
        if ((i % 16) == 15) {
            printf("\n");
        }
    }
    printf("\n");
#endif

    ptr += len;
    w5500_write_w(W5500_Sn_RX_RD, blk_sreg, ptr);
    w5500_write_b(W5500_Sn_CR, blk_sreg, W5500_Sn_CR_RECV);
    return len;
}

int do_wifi_join(char *ssid, char *password, long auth)
{
    memcpy(wifi_ssid, ssid, 32);
    wifi_ssid[32] = '\0';
    memcpy(wifi_passwd, password, 64);
    wifi_passwd[64] = '\0';
    winetd_cfg_flags |= WINETD_CFGF_SSID;
    winetd_cfg_flags |= WINETD_CFGF_PASSWD;
    w5500_write(W5500_WSSID, 0, (uint8_t *)ssid, 32);
    w5500_write(W5500_WPASSWORD, 0, (uint8_t *)password, 64);
    if (auth >= 0) {
        w5500_write_l(W5500_WAUTH, 0, auth);
    }

    wifi_command(W5500_WCR_JOIN);
    return 0;
}

int do_wifi_leave(void)
{
    wifi_command(W5500_WCR_LEAVE);
    ifenable = false;
    return 0;
}

int do_wifi_dhcpmode(int enable)
{
    wifi_command(enable ? W5500_WCR_DHCPON : W5500_WCR_DHCPOFF);
    return 0;
}

struct iface *do_wifi_get_iface(struct route **rt, struct dns **dns)
{
    struct iface *iface = do_get_iface_list();

    if (rt) {
        *rt = do_rt_lookup(0);
    }
    if (dns) {
        *dns = do_dns_get();
    }

    return iface;
}

int do_wifi_get_winetd_config(wifi_winetd_config_t *config)
{
    config->trap_number =
        (winetd_cfg_flags & WINETD_CFGF_TRAP) ? trap_config_number : NOSPEC_INT;
    config->ifname =
        (winetd_cfg_flags & WINETD_CFGF_IFNAME) ? ifname : NOSPEC_STR;
    config->ssid =
        (winetd_cfg_flags & WINETD_CFGF_SSID) ? wifi_ssid : NOSPEC_STR;
    config->password =
        (winetd_cfg_flags & WINETD_CFGF_PASSWD) ? wifi_passwd : NOSPEC_STR;
    config->dhcp_mode =
        (winetd_cfg_flags & WINETD_CFGF_DHCP) ? dhcp_mode : NOSPEC_INT;
    config->hostname =
        (winetd_cfg_flags & WINETD_CFGF_HOSTNAME) ? hostname : NOSPEC_STR;

    return 0;
}
