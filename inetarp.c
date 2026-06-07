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
static arp_table_t *arp_table_ptr[ARPSIZE];
static arp_table_t arp_table[ARPSIZE];

//****************************************************************************
// Private functions
//****************************************************************************

static void send_command(uint8_t cmd)
{
    w5500_write_b(W5500_WCR, 0, cmd);
    // コマンドが完了するまで待つ
    while (w5500_read_b(W5500_WCR, 0) != 0)
        ;
}

//****************************************************************************
// Public functions
//****************************************************************************

int do_add_arp_table(long ipaddr, char *src)
{
    w5500_write_l(W5500_WARPIP, 0, ipaddr);
    w5500_write(W5500_WARPMAC, 0, (uint8_t *)src, 6);
    send_command(W5500_WCR_ADDARP);
    return 0;
}

int do_del_arp_table(long ipaddr)
{
    w5500_write_l(W5500_WARPIP, 0, ipaddr);
    send_command(W5500_WCR_DELARP);
    return 0;
}

void *do_search_arp_table(long ipaddr)
{
    for (int i = 0; i < 16; i++) {
        if (arp_table[i].ip_addr == ipaddr) {
            return &arp_table[i];
        }
    }
    return NULL;
}

void *do_get_arp_table_top(void)
{
    send_command(W5500_WCR_GETARPTABLE);
    for (int i = 0; i < 16; i++) {
        long ip_addr = w5500_read_l(W5500_WARPTBL + i * (4 + 6), 0);
        if (ip_addr) {
            arp_table[i].ip_addr = ip_addr;
            arp_table[i].hw_addr_len = 6;
            w5500_read(W5500_WARPTBL + 4 + i * (4 + 6), 0, (uint8_t *)arp_table[i].hw_addr, 6);
            arp_table[i].state = 1;
            arp_table_ptr[i] = &arp_table[i];
        } else {
            arp_table_ptr[i] = NULL;
        }
    }
    return &arp_table_ptr;
}

int do_arp_request(long target)
{
    w5500_write_l(W5500_WARPIP, 0, target);
    send_command(W5500_WCR_REQARP);
    return 0;
}
