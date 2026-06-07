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
#include "winetd.h"
#include "wificmd.h"

//****************************************************************************
// Macros and definitions
//****************************************************************************

// ARP table entry
typedef struct arp_table {
    struct arp_table *prev;
    struct arp_table *next;
    long tmp1;
    long tmp2;
    int state;
    long tmp3;
    long tmp4;
    long ip_addr;
    int hw_addr_len;
    char hw_addr[16];
} arp_table_t;

//****************************************************************************
// Global variables
//****************************************************************************

#define ARPSIZE 17
void *dummy_arp_table[ARPSIZE];

//****************************************************************************
// Private functions
//****************************************************************************

//****************************************************************************
// Public functions
//****************************************************************************

int do_add_arp_table(long ipaddr, char *src)
{
    return 0;
}

int do_del_arp_table(long ipaddr)
{
    return 0;
}

void *do_search_arp_table(long ipaddr)
{
    return 0;
}

void *do_get_arp_table_top(void)
{
    return &dummy_arp_table;
}

int do_arp_request(long target)
{
    return 0;
}
