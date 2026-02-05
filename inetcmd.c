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
    char    type;           // 未使用なら0(NOTUSED)
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

//----------------------------------------------------------------------------

#define EPH_PORT_BEGIN   0xc000
#define EPH_PORT_END     0xd000

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

static int current_eph_port = EPH_PORT_BEGIN;

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
    }
}

//****************************************************************************

static inline unsigned int duration(struct iocs_time *t0)
{
    struct iocs_time now = _iocs_ontime();

    return (now.sec - t0->sec) +
           (now.day - t0->day) * 24 * 60 * 60 * 100;
}

static int wait_status(int blk_sreg, uint8_t status)
{
    struct iocs_time t0 = _iocs_ontime();

    while (duration(&t0) < 100) {       // timeout 1sec
        if (w5500_read_b(W5500_Sn_SR, blk_sreg) == status) {
            return 0;
        }
    }
    return -1;
}

static inline int validate_sockfd(int sockfd)
{
    if (sockfd < SOCKBASE || sockfd >= SOCKBASE + W5500_N_SOCKETS) {
        PRINTF("joynetd: invalid sockfd %d\r\n", sockfd);
        return -1;
    }
    sockfd -= SOCKBASE;
    if (usock_array[sockfd].type == NOTUSED) {
        PRINTF("joynetd: unused sockfd %d\r\n", sockfd + SOCKBASE);
        return -1;
    }
    return sockfd;
}

// ---------------------------------------------------------------------------

int do_socket(int domain, int type, int protocol)
{
    PRINTF("joynetd: socket(%d, %d, %d)\n", domain, type, protocol);

//    w5500_write_b(W5500_Sn_RXBUF_SIZE, 1, 4); // buffer size
//    w5500_write_b(W5500_Sn_TXBUF_SIZE, 1, 4); // buffer size

    for (int i = 0; i < W5500_N_SOCKETS; i++) {
        usock *u = &usock_array[i];
        if (u->type == NOTUSED) {

            // ポート番号を適当に決める
            int port;
            while (1) {
                port = current_eph_port++;
                if (current_eph_port >= EPH_PORT_END) {
                    current_eph_port = EPH_PORT_BEGIN;
                }
                int i;
                for (i = 0; i < W5500_N_SOCKETS; i++) {
                    usock *ua = &usock_array[i];
                    if (ua->type ==type && (int)ua->p == port) {
                        break;
                    }
                }
                if (i == W5500_N_SOCKETS) {
                    break;
                }
            }

            memset(u, 0, sizeof(usock));
            u->type = type + 1;
            u->refcnt = 1;
            u->p = (void *)port;    // TBD

            int blk_sreg = i * 4 + 1;
            switch (type) {
            case SOCK_STREAM:
                w5500_write_b(W5500_Sn_MR, blk_sreg, 0x01);  // TCP mode
                break;
            case SOCK_DGRAM:
                w5500_write_b(W5500_Sn_MR, blk_sreg, 0x02);  // UDP mode
                break;
            case SOCK_RAW:
                w5500_write_b(W5500_Sn_MR, blk_sreg, 0x03);  // MACRAW mode
                break;
            default:
                PRINTF("joynetd: unsupported socket type %d\n", type);
                u->type = NOTUSED;
                return -1;  // EPROTOTYPE
            }
            w5500_write_w(W5500_Sn_PORT, blk_sreg, port);
            w5500_write_b(W5500_Sn_CR, blk_sreg, W5500_Sn_CR_OPEN);
            if (wait_status(blk_sreg, W5500_Sn_SR_INIT) < 0) {
                PRINTF("socket open timeout\n");
                w5500_write_b(W5500_Sn_CR, blk_sreg, W5500_Sn_CR_CLOSE);
                u->type = NOTUSED;
                return -1;  // EIO
            }
            w5500_write_b(W5500_Sn_IR, 1, 0x1f); // S0_IR clear
            return SOCKBASE + i;
        }
    }
    return -1;  // ENOMEM
}

int do_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    PRINTF("joynetd: connect(%d, %p, %lu)\n", sockfd, addr, addrlen);

    int sno = validate_sockfd(sockfd);
    if (sno < 0) {
        return -1;  // EBADF
    }

    int blk_sreg = sno * 4 + 1;

    struct sockaddr_in *sin = (struct sockaddr_in *)addr;
    w5500_write_l(W5500_Sn_DIPR, blk_sreg, ntohl(sin->sin_addr.s_addr));
    w5500_write_w(W5500_Sn_DPORT, blk_sreg, ntohs(sin->sin_port));

    w5500_write_b(W5500_Sn_CR, blk_sreg, W5500_Sn_CR_CONNECT);
    if (wait_status(blk_sreg, W5500_Sn_SR_ESTABLISHED) < 0) {
        PRINTF("connect timeout\n");
        w5500_write_b(W5500_Sn_CR, blk_sreg, W5500_Sn_CR_CLOSE);
        return 11;  // ECONNREFUSED
    }

    PRINTF("S0_IR=%02x\n", w5500_read_b(W5500_Sn_IR, blk_sreg));
    return 0;
}

ssize_t do_read(int sockfd, void *buf, size_t count)
{
    PRINTF("joynetd: read(%d, %p, %lu)\n", sockfd, buf, count);

    int sno = validate_sockfd(sockfd);
    if (sno < 0) {
        return -1;  // EBADF
    }

    int blk_sreg = sno * 4 + 1;
    int blk_rxbuf = sno * 4 + 3;

    PRINTF("  S0_RX_RSR=");
    int len;
    do {
        len = w5500_read_w(W5500_Sn_RX_RSR, blk_sreg);
        PRINTF("%d ", len);fflush(stdout);
    } while (len == 0);
    PRINTF("\n");

    int ptr = w5500_read_w(W5500_Sn_RX_RD, blk_sreg);
    PRINTF("  S0_RX_RD=0x%x\n", ptr);
    w5500_read(ptr, blk_rxbuf, (uint8_t *)buf, len);
    ptr += len;
    w5500_write_w(W5500_Sn_RX_RD, blk_sreg, ptr);
    PRINTF("  S0_RX_RD=0x%x\n", ptr);
    w5500_write_b(W5500_Sn_CR, blk_sreg, W5500_Sn_CR_RECV);
    return len;
}

ssize_t do_write(int sockfd, const void *buf, size_t count)
{
    PRINTF("joynetd: write(%d, %p, %lu)\n", sockfd, buf, count);

    int sno = validate_sockfd(sockfd);
    if (sno < 0) {
        return -1;  // EBADF
    }

    int blk_sreg = sno * 4 + 1;
    int blk_txbuf = sno * 4 + 2;
    ssize_t written = 0;

    while (count > 0) {
        size_t free;
        do {
            free = w5500_read_w(W5500_Sn_TX_FSR, blk_sreg);
            PRINTF("  S0_TX_FSR=%lu\n", free);
        } while (free == 0);
        size_t len = (count < free) ? count : free;

        int ptr = w5500_read_w(W5500_Sn_TX_WR, blk_sreg);
        PRINTF("  S0_TX_WR=0x%x\n", ptr);
        w5500_write(ptr, blk_txbuf, (uint8_t *)buf, len);
        ptr += len;
        buf += len;
        count -= len;
        written += len;
        w5500_write_w(W5500_Sn_TX_WR, blk_sreg, ptr);
        PRINTF("  S0_TX_WR=0x%x\n", ptr);
        w5500_write_b(W5500_Sn_CR, blk_sreg, W5500_Sn_CR_SEND);
    }
    return written;
}

ssize_t do_recvfrom(int sockfd, void *buf, size_t len,
                    int flags, struct sockaddr *src_addr, socklen_t *addrlen)
{
    PRINTF("joynetd: recvfrom(%d, %p, %lu, %d, %p, %p)\n", sockfd, buf, len, flags, src_addr, addrlen);

    int sno = validate_sockfd(sockfd);
    if (sno < 0) {
        return -1;  // EBADF
    }

    int blk_sreg = sno * 4 + 1;
    int blk_rxbuf = sno * 4 + 3;

    PRINTF("  S0_RX_RSR=");
    int bytes;
    do {
        bytes = w5500_read_w(W5500_Sn_RX_RSR, blk_sreg);
        PRINTF("%d ", bytes);fflush(stdout);
    } while (bytes == 0);
    PRINTF("\n");

    int ptr = w5500_read_w(W5500_Sn_RX_RD, blk_sreg);
    PRINTF("  S0_RX_RD=0x%x\n", ptr);

    struct {
        in_addr_t sin_addr;
        in_port_t sin_port;
        uint16_t len;
    } packet_info;

    w5500_read(ptr, blk_rxbuf, (uint8_t *)&packet_info, sizeof(packet_info));
    ptr += sizeof(packet_info);

    w5500_read(ptr, blk_rxbuf, (uint8_t *)buf, packet_info.len);
    ptr += packet_info.len;
    w5500_write_w(W5500_Sn_RX_RD, blk_sreg, ptr);
    PRINTF("  S0_RX_RD=0x%x\n", ptr);
    w5500_write_b(W5500_Sn_CR, blk_sreg, W5500_Sn_CR_RECV);

    if (src_addr != NULL && addrlen != NULL && *addrlen >= sizeof(struct sockaddr_in)) {
        struct sockaddr_in *sin = (struct sockaddr_in *)src_addr;
        sin->sin_family = AF_INET;
        sin->sin_addr.s_addr = htonl(packet_info.sin_addr);
        sin->sin_port = htons(packet_info.sin_port);
        *addrlen = sizeof(struct sockaddr_in);
    }

    return packet_info.len;
}


ssize_t do_sendto(int sockfd, const void *buf, size_t len,
                  int flags, struct sockaddr *dest_addr, socklen_t addrlen)
{
    PRINTF("joynetd: sendto(%d, %p, %lu, %d, %p, %lu)\n", sockfd, buf, len, flags, dest_addr, addrlen);

    int sno = validate_sockfd(sockfd);
    if (sno < 0) {
        return -1;  // EBADF
    }

    int blk_sreg = sno * 4 + 1;
    int blk_txbuf = sno * 4 + 2;

    size_t free;
    do {
        free = w5500_read_w(W5500_Sn_TX_FSR, blk_sreg);
        PRINTF("  S0_TX_FSR=%lu\n", free);
    } while (free < len);

    struct sockaddr_in *sin = (struct sockaddr_in *)dest_addr;
    w5500_write_l(W5500_Sn_DIPR, blk_sreg, ntohl(sin->sin_addr.s_addr));
    w5500_write_w(W5500_Sn_DPORT, blk_sreg, ntohs(sin->sin_port));

    int ptr = w5500_read_w(W5500_Sn_TX_WR, blk_sreg);
    PRINTF("  S0_TX_WR=0x%x\n", ptr);
    w5500_write(ptr, blk_txbuf, (uint8_t *)buf, len);
    ptr += len;
    w5500_write_w(W5500_Sn_TX_WR, blk_sreg, ptr);
    PRINTF("  S0_TX_WR=0x%x\n", ptr);
    w5500_write_b(W5500_Sn_CR, blk_sreg, W5500_Sn_CR_SEND);
    return len;
}


int do_close(int sockfd)
{
    PRINTF("joynetd: close(%d)\n", sockfd);

    int sno = validate_sockfd(sockfd);
    if (sno < 0) {
        return -1;  // EBADF
    }

    int blk_sreg = sno * 4 + 1;
    usock *u = &usock_array[sno];

    w5500_write_b(W5500_Sn_CR, blk_sreg, W5500_Sn_CR_CLOSE);
    u->type = NOTUSED;

    return 0;
}


int do_socklen(int sockfd, int mode)
{
    PRINTF("joynetd: socklen(%d, %d)\n", sockfd, mode);

    int sno = validate_sockfd(sockfd);
    if (sno < 0) {
        return -1;  // EBADF
    }

    int blk_sreg = sno * 4 + 1;

    switch (mode) {
    case 0:     // get receive data size
//        return -1;
        return w5500_read_w(W5500_Sn_RX_RSR, blk_sreg);
    case 1:     // get send data size
        return 2048 - w5500_read_w(W5500_Sn_TX_FSR, blk_sreg);
    default:
        return -1;
    }
}


// ---------------------------------------------------------------------------

int do_seteol(int sockfd, char *seq)
{
    PRINTF("joynetd: seteol(%d, %02x:%02x)\n", sockfd, seq[0], seq[1]);
    return 0;
}

int do_sockmode(int sockfd, int mode)
{
    PRINTF("joynetd: sockmode(%d, %d)\n", sockfd, mode);
    return 0;
}

int do_setflush(int sockfd, int chr)
{
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

int do_command(int cmd, long *arg)
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
        return do_socket(arg[0], arg[1], arg[2]);
    case _TI_bind:
    case _TI_listen:
    case _TI_accept:
        return -1;
    case _TI_connect:
        return do_connect(arg[0], (const struct sockaddr *)arg[1], arg[2]);
    case _TI_read_s:
        return do_read(arg[0], (void *)arg[1], arg[2]);
    case _TI_write_s:
        return do_write(arg[0], (const void *)arg[1], arg[2]);
    case _TI_recvfrom:
        return do_recvfrom(arg[0], (void *)arg[1], arg[2],
                           arg[3], (struct sockaddr *)arg[4], (socklen_t *)arg[5]);
    case _TI_sendto:
        return do_sendto(arg[0], (const void *)arg[1], arg[2],
                         arg[3], (struct sockaddr *)arg[4], arg[5]);
    case _TI_close_s:
        return do_close((int)arg);
    case _TI_socklen:
        return do_socklen(arg[0], arg[1]);
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
        return do_seteol(arg[0], (char *)arg[1]);
    case _TI_sockmode:
        return do_sockmode(arg[0], arg[1]);
    case _TI_setflush:
        return do_setflush(arg[0], arg[1]);
    case _TI_psocket:
        return do_psocket(arg);
    case _TI_sockerr:
        return -1;
    case _TI_sockstate:
        return -1;

    case _TI_sock_top:
        return (int)&usock_array;
    case _TI_ntoa_sock:
        return 0;

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
