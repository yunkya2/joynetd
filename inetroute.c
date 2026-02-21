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

#include "joynetd.h"

//****************************************************************************
// Macros and definitions
//****************************************************************************

#define NROUTE 5

typedef struct route
{
  struct route *prev;
  struct route *next;
  long target;
  unsigned int bits;
  long gateway;
  long metric;
  struct iface *iface;
  int flags;
  int ttl;
  int _ttl;
  long uses;
} route;

typedef route *rtable[32][NROUTE];

//****************************************************************************
// Global variables
//****************************************************************************

static rtable joyrtable;
static struct route defroute;
static in_addr_t def_gateway;
static int rip_mode;

//****************************************************************************
// Private functions
//****************************************************************************

//****************************************************************************
// Public functions
//****************************************************************************

struct route **do_rt_top(struct route **def)
{
    PRINTF("joynetd: rt_top(%p)\n", def);

    if (def) {
        if (def_gateway) {
            defroute.gateway = ntohl(def_gateway);
            defroute.iface = do_get_iface_list();
            *def = &defroute;
        } else {
            *def = NULL;
        }
    }

    return (struct route **)&joyrtable;
}

struct route *do_rt_lookup(long ip)
{
    PRINTF("joynetd: rt_top(%08lx)\n", ip);

    return &defroute;
}

struct route *do_rt_lookupb(long ip, unsigned int bits)
{
    PRINTF("joynetd: rt_top(%08lx/%u)\n", ip, bits);

    return &defroute;
}

int do_rt_drop(long target, unsigned int bits)
{
    PRINTF("joynetd: rt_drop(%08lx/%u)\n", target, bits);

    def_gateway = 0;
    return 0;
}

struct route *do_rt_add(long ip, unsigned int bits, long gateway, struct iface *i,
                        long metric, long ttl, char private)
{
    PRINTF("joynetd: rt_add(%08lx/%u, %08lx, %p, %ld, %ld, %d)\n",
           ip, bits, gateway, i, metric, ttl, private);

    def_gateway = htonl(gateway);
    w5500_write_l(W5500_GAR, 0, gateway);
    return NULL;
}

int do_rip(int mode)
{
    PRINTF("joynetd: rip(%d)\n", mode);

    if (mode == 0 || mode == 1) {
        rip_mode = mode;
    }
    return !rip_mode;
}
