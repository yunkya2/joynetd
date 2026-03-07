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

#include "tcpipdrv.h"
#include "joynetd.h"

//****************************************************************************
// Macros and definitions
//****************************************************************************

static int iface_stop(struct iface *);
static int iface_dummy(struct iface *);

//****************************************************************************
// Global variables
//****************************************************************************

static iface joyif = {
    .next = NULL,

    .config = (void *)iface_dummy,
    .stop = iface_stop,
    .update = (void *)iface_dummy,
    .send = (void *)iface_dummy,
    .output = (void *)iface_dummy,
    .input = (void *)iface_dummy,
    .fprint = (void *)iface_dummy,
    .sprint = (void *)iface_dummy,
    .fscan = NULL,
    .sscan = NULL,

    .mtu = 1500,
    .arp_type = 0x0806,
    .arp_ip_type = 0x0800,
    .arp_hw_type = 1,
    .hw_addr_len = 6,
    .my_hw_broad_addr = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
};

//****************************************************************************
// Private functions
//****************************************************************************

static int iface_stop(struct iface *i)
{
    PRINTF("joynetd: iface_stop()\n");

    joyif.flag &= ~(IFACE_UP | IFACE_RUNNING);
    set_ifenable(0);

    PRINTF("joynetd: iface_stop() end\n");
    return 0;
}

static int iface_dummy(struct iface *i)
{
    PRINTF("joynetd: iface_dummy()\n");
    return 0;
}

//****************************************************************************
// Public functions
//****************************************************************************

struct iface *do_get_iface_list(void)
{
    PRINTF("joynetd: do_get_iface_list()\n");

    w5500_read(W5500_SHAR, 0, (uint8_t *)joyif.my_hw_addr, 6);
    joyif.name = ifname;
    joyif.my_ip_addr = w5500_read_l(W5500_SIPR, 0);
    joyif.net_mask = w5500_read_l(W5500_SUBR, 0);
    joyif.broad_cast = (joyif.my_ip_addr & joyif.net_mask) | (0xffffffff & ~joyif.net_mask);

    if (ifenable) {
        joyif.flag = IFACE_UP | IFACE_RUNNING | IFACE_NOTRAIL | IFACE_BROAD;
    } else {
        joyif.flag = 0;
    }

    return &joyif;
}

struct iface *do_get_new_iface(const char *name)
{
    PRINTF("joynetd: do_get_new_iface(%s)\n", name);

    return strcmp(name, ifname) == 0 ? do_get_iface_list() : NULL;
}

int do_link_new_iface(const struct iface *i)
{
    PRINTF("joynetd: do_link_new_iface(%p)\n", i);

    if (i != &joyif) {
        return -1;
    }

    w5500_write_l(W5500_SIPR, 0, i->my_ip_addr);
    w5500_write_l(W5500_SUBR, 0, i->net_mask);

    set_ifenable(i->flag & IFACE_UP);

    PRINTF("joynetd: linked iface %s\n", i->name);
    return 0;
}
