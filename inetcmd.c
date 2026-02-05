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

#include <x68k/dos.h>
#include <x68k/iocs.h>

#include "tcpipdrv.h"
#include "w5500.h"

//****************************************************************************
// Macros and definitions
//****************************************************************************

//#define PRINTF(...)
#define PRINTF(...) printf(__VA_ARGS__)

//----------------------------------------------------------------------------

#define ARPSIZE 17

typedef struct _arp_table
{
  struct _arp_table *prev;
  struct _arp_table *next;

  long tmp1;
  long tmp2;
  int state;
  long tmp3;
  long tmp4;
  long ip_addr;
  int hw_addr_len;
  char hw_addr[16];
} _arp_table;

//----------------------------------------------------------------------------

struct mib_entry
{
    char *name;
    union {
        long integer;
    } value;
};

struct mib_array {
    struct mib_entry* mib;
    int mib_size;
    char *name;
};

//----------------------------------------------------------------------------

#define NOTUSED (0)
#define SOCKBASE 128
#define DEFNSOCK 32
typedef struct usock
{
    int     refcnt;
    char    noblock;
    char    type;
    int     rdysock;
    void    *p;
    char    *name;
    int     namelen;
    char    *peername;
    int     peernamelen;
    char    errcodes[4];    /* Protocol-specific error codes */
    void    *obuf;          /* Output buffer */
    void    *ibuf;          /* Input buffer */
    char    eol[3];         /* Text mode end-of-line sequence, if any */
    int     flag;           /* Mode flags, defined in socket.h */
    int     flush;          /* Character to trigger flush, if any */
    int     event;
} usock;


//****************************************************************************
// Global variables
//****************************************************************************

_arp_table *arp_table[ARPSIZE];

struct mib_array mib_array[4] = {
    { NULL, 0, "IP" },
    { NULL, 0, "ICMP" },
    { NULL, 0, "UDP" },
    { NULL, 0, "TCP" }
};

usock usock_array[DEFNSOCK];

//****************************************************************************
// Private functions
//****************************************************************************

//////////////////////////////////////////////////////////////////////////////

static int first = 1;

static uint8_t w5500_mac[6];
static uint8_t w5500_gw[4];
static uint8_t w5500_sm[4];
static uint8_t w5500_sip[4];

//////////////////////////////////////////////////////////////////////////////

void configure(void)
{
    if (first) {
        first = 0;

        w5500_ini();

        FILE *fp;
        char cfgname[256];
        struct dos_psp *psp = _dos_getpdb ();

        strcpy(cfgname, psp->exe_path);
        strcat(cfgname, "w5500.cfg");
        if ((fp = fopen(cfgname, "r")) != NULL) {
            char line[256];
            char *p;
            char *q;
            while (fgets(line, sizeof(line), fp) != NULL) {
                if (strncmp(line, "mac=", 4) == 0) {
                    p = &line[4];
                    for (int i = 0; i < 6; i++) {
                        w5500_mac[i] = strtoul(p, &q, 16);
                        p = q + 1;
                    }
                } else if (strncmp(line, "ip=", 3) == 0) {
                    p = &line[3];
                    for (int i = 0; i < 4; i++) {
                        w5500_sip[i] = strtoul(p, &q, 0);
                        p = q + 1;
                    }
                } else if (strncmp(line, "mask=", 5) == 0) {
                    p = &line[5];
                    for (int i = 0; i < 4; i++) {
                        w5500_sm[i] = strtoul(p, &q, 0);
                        p = q + 1;
                    }
                } else if (strncmp(line, "gw=", 3) == 0) {
                    p = &line[3];
                    for (int i = 0; i < 4; i++) {
                        w5500_gw[i] = strtoul(p, &q, 0);
                        p = q + 1;
                    }
                }
            }
            fclose(fp);
        }
        printf("MAC: ");
        for (int i = 0; i < 6; i++) {
            printf("%02x:", w5500_mac[i]);
        }
        printf("\n");

        printf("IP: ");
        for (int i = 0; i < 4; i++) {
            printf("%d.", w5500_sip[i]);
        }
        printf("\n");

        printf("netmask: ");
        for (int i = 0; i < 4; i++) {
            printf("%d.", w5500_sm[i]);
        }
        printf("\n");

        printf("gateway: ");
        for (int i = 0; i < 4; i++) {
            printf("%d.", w5500_gw[i]);
        }
        printf("\n");
    }
}

//****************************************************************************




int do_socket(long *arg)
{
    int domain = arg[0];
    int type = arg[1];
    int protocol = arg[2];
    PRINTF("joynetd: socket(%d, %d, %d)\n", domain, type, protocol);

    for (int i = 0; i < 0x40; i += 0x10) {
        uint8_t data[16];
        w5500_read(i, 0, data, 16);
        for (int j = 0; j < 16; j++) {
            PRINTF(" %02x", data[j]);
        }
        PRINTF("\n");
    }
    PRINTF("\n");

    w5500_write(W5500_SHAR, 0, w5500_mac, 6);
    w5500_write(W5500_GAR, 0, w5500_gw, 4);
    w5500_write(W5500_SUBR, 0, w5500_sm, 4);
    w5500_write(W5500_SIPR, 0, w5500_sip, 4);

//    w5500_write_b(W5500_Sn_RXBUF_SIZE, 1, 4); // buffer size
//    w5500_write_b(W5500_Sn_TXBUF_SIZE, 1, 4); // buffer size


    w5500_write_b(W5500_Sn_MR, 1, 0x01); // S0_MR = 0x01 // TCP mode
    w5500_write_w(W5500_Sn_PORT, 1, 5000); // S0_PORT = 5000

    w5500_write_b(W5500_Sn_CR, 1, W5500_Sn_CR_OPEN);
    PRINTF("S0_MR=%02x\n", w5500_read_b(W5500_Sn_MR, 1));
    PRINTF("S0_SR=%02x\n", w5500_read_b(W5500_Sn_SR, 1));

    w5500_write_b(W5500_Sn_IR, 1, 0x1f); // S0_IR clear



    return 128;
}

int do_connect(long *arg)
{
    int sockfd = arg[0];
    const struct sockaddr *addr = (const struct sockaddr *)arg[1];
    socklen_t addrlen = arg[2];

    PRINTF("joynetd: connect(%d, %p, %lu)\n", sockfd, addr, addrlen);

    struct sockaddr_in *sin = (struct sockaddr_in *)addr;

    w5500_write_l(W5500_Sn_DIPR, 1, ntohl(sin->sin_addr.s_addr));
    w5500_write_w(W5500_Sn_DPORT, 1, ntohs(sin->sin_port));

    w5500_write_b(W5500_Sn_CR, 1, W5500_Sn_CR_CONNECT);

    PRINTF("wait for connection...\n");
    for (int i = 0; i < 1000; i++) {
        PRINTF("S0_SR=%02x\r", w5500_read_b(W5500_Sn_SR, 1));
        if (w5500_read_b(W5500_Sn_SR, 1) == 0x17) {
            break;
        }
    }
    if (w5500_read_b(W5500_Sn_SR, 1) != 0x17) {
        PRINTF("connection timeout\n");
        w5500_write_b(W5500_Sn_CR, 1, W5500_Sn_CR_CLOSE);
        return 11;
    }
    PRINTF("S0_IR=%02x\n", w5500_read_b(W5500_Sn_IR, 1));
    return 0;
}

int do_read(long *arg)
{
    int sockfd = arg[0];
    void *buf = (void *)arg[1];
    size_t count = arg[2];

    PRINTF("joynetd: read(%d, %p, %lu)\n", sockfd, buf, count);


    PRINTF("  S0_RX_RSR=");
    int len;
    do {
        len = w5500_read_w(W5500_Sn_RX_RSR, 1);
        PRINTF("%d ", len);fflush(stdout);
    } while (len == 0);
    PRINTF("\n");

    int ptr = w5500_read_w(W5500_Sn_RX_RD, 1);
    PRINTF("  S0_RX_RD=0x%x\n", ptr);
    w5500_read(ptr, 3, (uint8_t *)buf, len);
    ptr += len;
    w5500_write_w(W5500_Sn_RX_RD, 1, ptr);
    PRINTF("  S0_RX_RD=0x%x\n", ptr);
    w5500_write_b(W5500_Sn_CR, 1, W5500_Sn_CR_RECV);
    return len;

}

int do_write(long *arg)
{
    int sockfd = arg[0];
    const uint8_t *buf = (const uint8_t *)arg[1];
    size_t count = arg[2];

    PRINTF("joynetd: write(%d, %p, %lu)\n", sockfd, buf, count);

    while (count > 0) {
        size_t free;
        do {
            free = w5500_read_w(W5500_Sn_TX_FSR, 1);
            PRINTF("  S0_TX_FSR=%lu\n", free);
        } while (free == 0);
        size_t len = (count < free) ? count : free;

        int ptr = w5500_read_w(W5500_Sn_TX_WR, 1);
        PRINTF("  S0_TX_WR=0x%x\n", ptr);
        w5500_write(ptr, 2, (uint8_t *)buf, len);
        ptr += len;
        buf += len;
        count -= len;
        w5500_write_w(W5500_Sn_TX_WR, 1, ptr);
        PRINTF("  S0_TX_WR=0x%x\n", ptr);
        w5500_write_b(W5500_Sn_CR, 1, W5500_Sn_CR_SEND);
    }
    return arg[2];
}


int do_close(long *arg)
{
    int sockfd = (int)arg;
    PRINTF("joynetd: close(%d)\n", sockfd);

    w5500_write_b(W5500_Sn_CR, 1, W5500_Sn_CR_CLOSE);

    return 0;
}


int do_socklen(long *arg)
{
    int sockfd = arg[0];
    int mode = arg[1];
    PRINTF("joynetd: socklen(%d, %d)\n", sockfd, mode);

    switch (mode) {
    case 0:     // get receive data size
//        return -1;
        return w5500_read_w(W5500_Sn_RX_RSR, 1);
    case 1:     // get send data size
//        return 4096 - w5500_read_w(W5500_Sn_TX_FSR, 1);     // TBD
        return 2048 - w5500_read_w(W5500_Sn_TX_FSR, 1);     // TBD
    default:
        return -1;
    }
}


// ---------------------------------------------------------------------------

int do_seteol(long *arg)
{
    int sockfd = arg[0];
    char *seq = (char *)arg[1];
    PRINTF("joynetd: seteol(%d, %02x:%02x)\n", sockfd, seq[0], seq[1]);
    return 0;
}

int do_sockmode(long *arg)
{
    int sockfd = arg[0];
    int mode = arg[1];
    PRINTF("joynetd: sockmode(%d, %d)\n", sockfd, mode);
    return 0;
}

int do_setflush(long *arg)
{
    int sockfd = arg[0];
    int chr = arg[1];
    PRINTF("joynetd: setflush(%d, %d)\n", sockfd, chr);
    return 0;
}

int do_psocket(long *arg)
{
    PRINTF("joynetd: psocket(%p)\n", arg);
    return (int)arg;
}

// ---------------------------------------------------------------------------

int do_gethostbyname(long *arg)
{
    const char *name = (const char *)arg;

    PRINTF("joynetd: gethostbyname(%s)\n", name);
    return 0;
}

// ---------------------------------------------------------------------------

int do_command(int cmd, void *arg)
{
    PRINTF("joynetd: do_command cmd=%d arg=%p\r\n", cmd, arg);

    _dos_super(0);

    switch (cmd) {
    case -1:        // trap番号の取得
        return -1;  // trap未対応

    case _TI_get_version:
        return 0x00010000;  // (TBD) version

    case _TI_add_arp_table:
    case _TI_del_arp_table:
    case _TI_search_arp_table:
        return 0;
    case _TI_get_arp_table_top:
        return (int)&arp_table;
    case _TI_arp_request:
        return 0;

    case _TI_get_iface_list:
    case _TI_get_new_iface:
    case _TI_link_new_iface:
        return 0;

    case _TI_rt_top:
    case _TI_rt_lookup:
    case _TI_rt_lookupb:
    case _TI_rt_drop:
    case _TI_rt_add:
        return -1;

    case _TI_dns_add:
    case _TI_dns_drop:
    case _TI_dns_get:
    case _TI_set_domain_name:
    case _TI_get_domain_name:
    case _TI_res_query:
    case _TI_res_search:
    case _TI_res_mkquery:
    case _TI_res_sendquery:
        return -1;

    case _TI_get_MIB:
        return (int)&mib_array;

    case _TI_socket:
        return do_socket(arg);
    case _TI_bind:
    case _TI_listen:
    case _TI_accept:
        return -1;
    case _TI_connect:
        return do_connect(arg);
    case _TI_read_s:
        return do_read(arg);
    case _TI_write_s:
        return do_write(arg);
    case _TI_recvfrom:
    case _TI_sendto:
        return -1;
    case _TI_close_s:
        return do_close(arg);
    case _TI_socklen:
        return do_socklen(arg);
    case _TI_getsockname:
    case _TI_getpeername:
    case _TI_sockkick:
    case _TI_shutdown:
    case _TI_usesock:
    case _TI_recvline:
    case _TI_sendline:
    case _TI_rrecvchar:
    case _TI_recvchar:
    case _TI_usflush:
        return -1;
    case _TI_seteol:
        return do_seteol(arg);
    case _TI_sockmode:
        return do_sockmode(arg);
    case _TI_setflush:
        return do_setflush(arg);
    case _TI_psocket:
        return do_psocket(arg);
    case _TI_sockerr:
        return -1;
    case _TI_sockstate:
        return -1;

    case _TI_sock_top:
        return (int)&usock_array;
    case _TI_ntoa_sock:
        return -1;

    case _TI_gethostbyname:
        return do_gethostbyname(arg);
    case _TI_gethostbyaddr:
    case _TI_getnetbyname:
    case _TI_getnetbyaddr:
    case _TI_getservbyname:
    case _TI_getservbyport:
    case _TI_getprotobyname:
    case _TI_getprotobynumber:
        return -1;

    case _TI_rip:
        return -1;
    default:
        break;
    }

    return -1;
}
