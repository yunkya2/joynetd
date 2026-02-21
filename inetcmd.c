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

#define NOTUSED             0
#define TYPE_TCP            1
#define TYPE_UDP            2
#define TYPE_RAW            3
#define TYPE_LOCAL_STREAM   4
#define TYPE_LOCAL_DGRAM    5

#define	SOCK_BINARY	0	/* socket in raw (binary) mode */
#define	SOCK_ASCII	1	/* socket in cooked (newline mapping) mode */
#define	SOCK_QUERY	2	/* Return setting without change */

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

#define SOCKCLNT_BASE   (SOCKBASE + W5500_N_SOCKETS)

#define EPH_PORT_BEGIN   0xc000
#define EPH_PORT_END     0xd000

#define W5500_SOCK_BUF_SIZE   2048

#define SOCKFD_SOCKET       0   // fd for all socket
#define SOCKFD_RDWR         1   // fd for send()/recv()
#define SOCKFD_LISTEN       2   // fd for listen()
#define SOCKFD_ACCEPT       3   // fd for accept()

//****************************************************************************
// Global variables
//****************************************************************************

#define ARPSIZE 17
void *dummy_arp_table[ARPSIZE];

struct {
    void *entry;
    int size;
    const char *name;
} dummy_mib_array[4] = {
    { NULL, 0, "IP" },
    { NULL, 0, "ICMP" },
    { NULL, 0, "UDP" },
    { NULL, 0, "TCP" }
};

usock usock_array[DEFNSOCK];

static in_port_t current_eph_port = EPH_PORT_BEGIN;
static in_port_t usock_port[W5500_N_SOCKETS];
static uint32_t usock_connecting = 0;
static uint32_t usock_listening = 0;
static uint32_t usock_accepted = 0;

//****************************************************************************
// Private functions
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

static int wait_data(int blk_sreg, int reg, int status, int nonblock)
{
    int len;

    do {
        len = w5500_read_w(reg, blk_sreg);
#ifdef DEBUG
        PRINTF("%d ", len); fflush(stdout);
#endif
        if (len > 0) {
            PRINTF("\n");
            return len;
        }
        if (nonblock) {
            if (w5500_read_b(W5500_Sn_SR, blk_sreg) != status) {
                break;
            }
            PRINTF("\n");
            return len;
        }
    } while (w5500_read_b(W5500_Sn_SR, blk_sreg) == status);

    PRINTF("socket closed\n");
    return -1;
}

static int validate_sockfd(int sockfd, int type)
{
    switch (type) {
    case SOCKFD_SOCKET:
        if (sockfd >= SOCKCLNT_BASE && sockfd < SOCKCLNT_BASE + W5500_N_SOCKETS) {
            sockfd -= SOCKCLNT_BASE;
            if (usock_array[sockfd].type == NOTUSED) {
                PRINTF("joynetd: unused sockfd %d\r\n", sockfd + SOCKCLNT_BASE);
                errno = EBADF;
                return -1;
            }
            return sockfd;
        }
        if (sockfd >= SOCKBASE && sockfd < SOCKBASE + W5500_N_SOCKETS) {
            sockfd -= SOCKBASE;
            if (usock_array[sockfd].type == NOTUSED) {
                PRINTF("joynetd: unused sockfd %d\r\n", sockfd + SOCKBASE);
                errno = EBADF;
                return -1;
            }
            return sockfd;
        }
        break;

    case SOCKFD_RDWR:
        if (sockfd >= SOCKCLNT_BASE && sockfd < SOCKCLNT_BASE + W5500_N_SOCKETS) {
            sockfd -= SOCKCLNT_BASE;
            if (usock_array[sockfd].type == NOTUSED) {
                PRINTF("joynetd: unused sockfd %d\r\n", sockfd + SOCKCLNT_BASE);
                errno = EBADF;
                return -1;
            }
            if (!(usock_accepted & (1 << sockfd))) {
                PRINTF("joynetd: socket %d is not ready for recv/send\r\n", sockfd + SOCKCLNT_BASE);
                errno = EADDRINUSE;
                return -1;
            }
            return sockfd;
        }
        /* fall through */

    case SOCKFD_LISTEN:
        if (sockfd >= SOCKBASE && sockfd < SOCKBASE + W5500_N_SOCKETS) {
            sockfd -= SOCKBASE;
            if (usock_array[sockfd].type == NOTUSED) {
                PRINTF("joynetd: unused sockfd %d\r\n", sockfd + SOCKBASE);
                errno = EBADF;
                return -1;
            }
            if (usock_listening & (1 << sockfd)) {
                PRINTF("joynetd: socket %d is already listening\r\n", sockfd + SOCKBASE);
                errno = EADDRINUSE;
                return -1;
            }
            return sockfd;
        }
        break;

    case SOCKFD_ACCEPT:
        if (sockfd >= SOCKBASE && sockfd < SOCKBASE + W5500_N_SOCKETS) {
            sockfd -= SOCKBASE;
            if (usock_array[sockfd].type == NOTUSED) {
                PRINTF("joynetd: unused sockfd %d\r\n", sockfd + SOCKBASE);
                errno = EBADF;
                return -1;
            }
            if (!(usock_listening & (1 << sockfd)) || (usock_accepted & (1 << sockfd))) {
                PRINTF("joynetd: socket %d is not ready for accept\r\n", sockfd + SOCKBASE);
                errno = EADDRINUSE;
                return -1;
            }
            return sockfd;
        }

        break;
    default:
        break;
    }
    PRINTF("joynetd: invalid sockfd %d\r\n", sockfd);
    errno = EBADF;
    return -1;
}

//****************************************************************************
// Public functions
//****************************************************************************

int do_socket(int domain, int type, int protocol)
{
    PRINTF("joynetd: socket(%d, %d, %d)\n", domain, type, protocol);

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
                int j;
                for (j = 0; j < W5500_N_SOCKETS; j++) {
                    usock *ua = &usock_array[j];
                    if (i != j && ua->type != NOTUSED && usock_port[j] == port) {
                        break;
                    }
                }
                if (j == W5500_N_SOCKETS) {
                    break;
                }
            }

            memset(u, 0, sizeof(usock));
            int blk_sreg = i * 4 + 1;
            int socket_type;
            int socket_mode;
            int socket_stat;

            switch (type) {
            case SOCK_STREAM:
                socket_type = TYPE_TCP;
                socket_mode = W5500_Sn_MR_TCP;
                socket_stat = W5500_Sn_SR_INIT;
                break;
            case SOCK_DGRAM:
                socket_type = TYPE_UDP;
                socket_mode = W5500_Sn_MR_UDP;
                socket_stat = W5500_Sn_SR_UDP;
                break;
            case SOCK_RAW:
                socket_type = TYPE_RAW;
                socket_mode = W5500_Sn_MR_IPRAW;
                socket_stat = W5500_Sn_SR_IPRAW;
                w5500_write_b(W5500_Sn_PROTO, blk_sreg, protocol);
                break;
            default:
                PRINTF("joynetd: unsupported socket type %d\n", type);
                errno = EPROTOTYPE;
                return -1;
            }

            w5500_write_b(W5500_Sn_MR, blk_sreg, socket_mode);
            w5500_write_w(W5500_Sn_PORT, blk_sreg, port);
            w5500_write_b(W5500_Sn_CR, blk_sreg, W5500_Sn_CR_OPEN);
            if (wait_status(blk_sreg, socket_stat) < 0) {
                PRINTF("socket open timeout\n");
                w5500_write_b(W5500_Sn_CR, blk_sreg, W5500_Sn_CR_CLOSE);
                u->type = NOTUSED;
                errno = EIO;
                return -1;
            }
            u->type = socket_type;
            u->refcnt = 1;
            u->noblock = 0;
            u->flush = '\n';
            strcpy(u->eol, "\r\n");
            usock_port[i] = port;
            w5500_write_b(W5500_Sn_IR, 1, 0x1f); // S0_IR clear
            return SOCKBASE + i;
        }
    }
    errno = ENOMEM;
    return -1;
}

int do_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    PRINTF("joynetd: bind(%d, %p, %lu)\n", sockfd, addr, addrlen);

    int sno = validate_sockfd(sockfd, SOCKFD_RDWR);
    if (sno < 0) {
        return -1;
    }

    int blk_sreg = sno * 4 + 1;
    usock *u = &usock_array[sockfd - SOCKBASE];

    switch (u->type) {
    case TYPE_TCP:
    case TYPE_UDP:
    case TYPE_RAW:
        break;
    default:
        PRINTF("joynetd: unsupported socket type %d\n", u->type);
        errno = EPROTOTYPE;
        return -1;
    }

    struct sockaddr_in *sin = (struct sockaddr_in *)addr;
    w5500_write_w(W5500_Sn_PORT, blk_sreg, ntohs(sin->sin_port));

    return 0;
}

int do_listen(int sockfd, int backlog)
{
    PRINTF("joynetd: listen(%d, %d)\n", sockfd, backlog);

    int sno = validate_sockfd(sockfd, SOCKFD_LISTEN);
    if (sno < 0) {
        return -1;
    }

    int blk_sreg = sno * 4 + 1;
    usock *u = &usock_array[sockfd - SOCKBASE];

    switch (u->type) {
    case TYPE_TCP:
        break;
    case TYPE_UDP:
    case TYPE_RAW:
    default:
        PRINTF("joynetd: unsupported socket type %d\n", u->type);
        errno = EOPNOTSUPP;
        return -1;
    }

    if (w5500_read_b(W5500_Sn_SR, blk_sreg) != W5500_Sn_SR_INIT) {
        PRINTF("socket not in INIT state\n");
        errno = EINVAL;
        return -1;
    }
    w5500_write_b(W5500_Sn_CR, blk_sreg, W5500_Sn_CR_LISTEN);
    usock_listening |= (1 << sno);

    return 0;
}

int do_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    PRINTF("joynetd: accept(%d, %p, %p)\n", sockfd, addr, addrlen);

    int sno = validate_sockfd(sockfd, SOCKFD_ACCEPT);
    if (sno < 0) {
        return -1;
    }

    int blk_sreg = sno * 4 + 1;
    usock *u = &usock_array[sockfd - SOCKBASE];

    switch (u->type) {
    case TYPE_TCP:
        break;
    case TYPE_UDP:
    case TYPE_RAW:
    default:
        PRINTF("joynetd: unsupported socket type %d\n", u->type);
        errno = EOPNOTSUPP;
        return -1;
    }

    int stat;
    do {
        stat = w5500_read_b(W5500_Sn_SR, blk_sreg);
        if (stat == W5500_Sn_SR_ESTABLISHED) {
            if (addr != NULL && addrlen != NULL && *addrlen >= sizeof(struct sockaddr_in)) {
                struct sockaddr_in *sin = (struct sockaddr_in *)addr;
                sin->sin_family = AF_INET;
                sin->sin_addr.s_addr = htonl(w5500_read_l(W5500_Sn_DIPR, blk_sreg));
                sin->sin_port = htons(w5500_read_w(W5500_Sn_DPORT, blk_sreg));
                *addrlen = sizeof(struct sockaddr_in);

                usock *uc = &usock_array[sno + SOCKCLNT_BASE - SOCKBASE];
                uc->type = u->type;
                uc->refcnt = 1;
                uc->noblock = 0;
                uc->flush = u->flush;
                strcpy(uc->eol, u->eol);
                usock_accepted |= (1 << sno);

                return SOCKCLNT_BASE + sno;
            }
            PRINTF("joynetd: addr or addrlen is NULL or too small\n");
            errno = EINVAL;
            return -1;
        } else if (u->noblock && stat == W5500_Sn_SR_LISTEN) {
            errno = EAGAIN;
            return -1;
        }
    } while (stat == W5500_Sn_SR_LISTEN);
    PRINTF("accept failed, Sn_SR=%02x\n", stat);
    errno = ECONNABORTED;
    return -1;
}

int do_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    PRINTF("joynetd: connect(%d, %p, %lu)\n", sockfd, addr, addrlen);

    int sno = validate_sockfd(sockfd, SOCKFD_RDWR);
    if (sno < 0) {
        return -1;
    }

    int blk_sreg = sno * 4 + 1;
    usock *u = &usock_array[sockfd - SOCKBASE];

    switch (u->type) {
    case TYPE_TCP:
    case TYPE_UDP:
    case TYPE_RAW:
        break;
    default:
        PRINTF("joynetd: unsupported socket type %d\n", u->type);
        errno = EPROTOTYPE;
        return -1;
    }

    struct sockaddr_in *sin = (struct sockaddr_in *)addr;
    w5500_write_l(W5500_Sn_DIPR, blk_sreg, ntohl(sin->sin_addr.s_addr));
    w5500_write_w(W5500_Sn_DPORT, blk_sreg, ntohs(sin->sin_port));

    if (u->type != TYPE_TCP) {
        return 0;
    }

    w5500_write_b(W5500_Sn_CR, blk_sreg, W5500_Sn_CR_CONNECT);
    usock_connecting |= (1 << sno);
    if (u->noblock) {
        errno = EINPROGRESS;
        return -1;
    }

    if (wait_status(blk_sreg, W5500_Sn_SR_ESTABLISHED) < 0) {
        PRINTF("connect timeout\n");
        w5500_write_b(W5500_Sn_CR, blk_sreg, W5500_Sn_CR_CLOSE);
        usock_connecting &= ~(1 << sno);
        errno = ECONNREFUSED;
        return -1;
    }

    usock_connecting &= ~(1 << sno);
    PRINTF("S0_IR=%02x\n", w5500_read_b(W5500_Sn_IR, blk_sreg));
    return 0;
}

ssize_t do_recvfrom(int sockfd, void *buf, size_t len,
                    int flags, struct sockaddr *src_addr, socklen_t *addrlen)
{
    PRINTF("joynetd: recvfrom(%d, %p, %lu, %d, %p, %p)\n", sockfd, buf, len, flags, src_addr, addrlen);

    int sno = validate_sockfd(sockfd, SOCKFD_RDWR);
    if (sno < 0) {
        return -1;
    }

    int blk_sreg = sno * 4 + 1;
    int blk_rxbuf = sno * 4 + 3;
    usock *u = &usock_array[sockfd - SOCKBASE];
    int socket_stat;
    int packet_info_size;
    uint16_t *packet_info_len;

    union {
        struct {
            in_addr_t sin_addr;
            in_port_t sin_port;
            uint16_t len;
        } udp;
        struct {
            in_addr_t sin_addr;
            uint16_t len;
        } ipraw;
    } packet_info;

    switch (u->type) {
    case TYPE_TCP:
        socket_stat = W5500_Sn_SR_ESTABLISHED;
        packet_info_size = 0;
        packet_info_len = NULL;
        src_addr = NULL;    // アドレス指定は無視する
        addrlen = NULL;
        break;
    case TYPE_UDP:
        socket_stat = W5500_Sn_SR_UDP;
        packet_info_size = sizeof(packet_info.udp);
        packet_info_len = &packet_info.udp.len;
        break;
    case TYPE_RAW:
        socket_stat = W5500_Sn_SR_IPRAW;
        packet_info_size = sizeof(packet_info.ipraw);
        packet_info_len = &packet_info.ipraw.len;
        break;
    default:
        PRINTF("joynetd: unsupported socket type %d\n", u->type);
        errno = EPROTOTYPE;
        return -1;
    }

    PRINTF("  Sn_RX_RSR=");
    int bytes = wait_data(blk_sreg, W5500_Sn_RX_RSR, socket_stat, u->noblock);
    if (bytes == 0) {
        errno = EAGAIN;
        return -1;
    } else if (bytes < 0) {
        return 0;
    }

    int ptr = w5500_read_w(W5500_Sn_RX_RD, blk_sreg);
    PRINTF("  Sn_RX_RD=0x%x\n", ptr);

    // UDP/IPRAWの場合は付加情報を先に読む
    if (packet_info_size > 0) {
        w5500_read(ptr, blk_rxbuf, (uint8_t *)&packet_info, packet_info_size);
        ptr += packet_info_size;
        len = (len < *packet_info_len) ? len : *packet_info_len;
    } else {
        len = (len < bytes) ? len : bytes;
    }

    w5500_read(ptr, blk_rxbuf, (uint8_t *)buf, len);
    if (packet_info_size > 0) {
        ptr += *packet_info_len;
    } else {
        ptr += len;
    }
    w5500_write_w(W5500_Sn_RX_RD, blk_sreg, ptr);
    PRINTF("  Sn_RX_RD=0x%x\n", ptr);
    w5500_write_b(W5500_Sn_CR, blk_sreg, W5500_Sn_CR_RECV);

    if (src_addr != NULL && addrlen != NULL && *addrlen >= sizeof(struct sockaddr_in)) {
        struct sockaddr_in *sin = (struct sockaddr_in *)src_addr;
        sin->sin_family = AF_INET;
        sin->sin_addr.s_addr = htonl(packet_info.udp.sin_addr);
        sin->sin_port = (u->type == TYPE_UDP) ? htons(packet_info.udp.sin_port) : 0;
        *addrlen = sizeof(struct sockaddr_in);
    }

    return len;
}

ssize_t do_sendto(int sockfd, const void *buf, size_t len,
                  int flags, struct sockaddr *dest_addr, socklen_t addrlen)
{
    PRINTF("joynetd: sendto(%d, %p, %lu, %d, %p, %lu)\n", sockfd, buf, len, flags, dest_addr, addrlen);

    int sno = validate_sockfd(sockfd, SOCKFD_RDWR);
    if (sno < 0) {
        return -1;
    }

    int blk_sreg = sno * 4 + 1;
    int blk_txbuf = sno * 4 + 2;
    usock *u = &usock_array[sockfd - SOCKBASE];
    int socket_stat;

    switch (u->type) {
    case TYPE_TCP:
        socket_stat = W5500_Sn_SR_ESTABLISHED;
        dest_addr = NULL;   // アドレス指定は無視する
        addrlen = 0;
        break;
    case TYPE_UDP:
        socket_stat = W5500_Sn_SR_UDP;
        break;
    case TYPE_RAW:
        socket_stat = W5500_Sn_SR_IPRAW;
        break;
    default:
        PRINTF("joynetd: unsupported socket type %d\n", u->type);
        errno = EPROTOTYPE;
        return -1;
    }

    if (dest_addr != NULL &&  addrlen >= sizeof(struct sockaddr_in)) {
        struct sockaddr_in *sin = (struct sockaddr_in *)dest_addr;
        w5500_write_l(W5500_Sn_DIPR, blk_sreg, ntohl(sin->sin_addr.s_addr));
        w5500_write_w(W5500_Sn_DPORT, blk_sreg, ntohs(sin->sin_port));
    }

    if (u->type == TYPE_TCP) {
        ssize_t written = 0;
        while (len > 0) {
            PRINTF("  Sn_TX_FSR=");
            int size = wait_data(blk_sreg, W5500_Sn_TX_FSR, socket_stat, u->noblock);
            if (size == 0) {            // ノンブロッキングでこれ以上データが書き込めない場合
                if (written == 0) {     // 1バイトも書いていなければエラー
                    errno = EAGAIN;
                    return -1;
                } else {                // 書き込めた分だけ返す
                    break;
                }
            } else if (size < 0) {
                errno = EPIPE;
                return -1;
            }
            size = (len < size) ? len : size;

            int ptr = w5500_read_w(W5500_Sn_TX_WR, blk_sreg);
            PRINTF("  Sn_TX_WR=0x%x\n", ptr);
            w5500_write(ptr, blk_txbuf, buf, size);
            ptr += size;
            buf += size;
            len -= size;
            written += size;
            w5500_write_w(W5500_Sn_TX_WR, blk_sreg, ptr);
            PRINTF("  Sn_TX_WR=0x%x\n", ptr);
            w5500_write_b(W5500_Sn_CR, blk_sreg, W5500_Sn_CR_SEND);
        }

        return written;
    } else {
        if (len > W5500_SOCK_BUF_SIZE) {
            PRINTF("joynetd: message too long for UDP/IPRAW socket\n");
            errno = EMSGSIZE;
            return -1;
        }

        int free;
        while (1) {
            PRINTF("  Sn_TX_FSR=");
            free = wait_data(blk_sreg, W5500_Sn_TX_FSR, socket_stat, u->noblock);
            if (free < 0) {
                errno = EPIPE;
                return -1;
            } else if (free >= len) {
                break;
            } else if (u->noblock) {    // ノンブロッキングで一度でデータを書き込めない場合はエラー
                errno = EAGAIN;
                return -1;
            }
        }

        int ptr = w5500_read_w(W5500_Sn_TX_WR, blk_sreg);
        PRINTF("  Sn_TX_WR=0x%x\n", ptr);
        w5500_write(ptr, blk_txbuf, buf, len);
        ptr += len;
        w5500_write_w(W5500_Sn_TX_WR, blk_sreg, ptr);
        PRINTF("  Sn_TX_WR=0x%x\n", ptr);
        w5500_write_b(W5500_Sn_CR, blk_sreg, W5500_Sn_CR_SEND);

        return len;
    }
}

int do_close(int sockfd)
{
    PRINTF("joynetd: close(%d)\n", sockfd);

    int sno = validate_sockfd(sockfd, SOCKFD_SOCKET);
    if (sno < 0) {
        return -1;
    }

    int blk_sreg = sno * 4 + 1;
    usock *u = &usock_array[sockfd - SOCKBASE];

    if (--u->refcnt > 0) {
        return 0;
    }

    if (sockfd >= SOCKCLNT_BASE) {
        usock_accepted &= ~(1 << sno);
        w5500_write_b(W5500_Sn_CR, blk_sreg, W5500_Sn_CR_CLOSE);
        w5500_write_b(W5500_Sn_CR, blk_sreg, W5500_Sn_CR_LISTEN);
    } else {
        usock_listening &= ~(1 << sno);
        w5500_write_b(W5500_Sn_CR, blk_sreg, W5500_Sn_CR_CLOSE);
    }
    u->type = NOTUSED;
    return 0;
}

int do_socklen(int sockfd, int mode)
{
    PRINTF("joynetd: socklen(%d, %d)\n", sockfd, mode);

    int sno = validate_sockfd(sockfd, SOCKFD_SOCKET);
    if (sno < 0) {
        return -1;
    }

    int blk_sreg = sno * 4 + 1;
    usock *u = &usock_array[sockfd - SOCKBASE];

    if (u->type == TYPE_TCP) {
        if (w5500_read_b(W5500_Sn_SR, blk_sreg) != W5500_Sn_SR_ESTABLISHED) {
            PRINTF("socket not in ESTABLISHED state\n");
            errno = EINVAL;
            return -1;
        }
    }

    switch (mode) {
    case 0:     // get receive data size
        PRINTF("--> %d\n", w5500_read_w(W5500_Sn_RX_RSR, blk_sreg));
        return w5500_read_w(W5500_Sn_RX_RSR, blk_sreg);
    case 1:     // get send data size
        return W5500_SOCK_BUF_SIZE - w5500_read_w(W5500_Sn_TX_FSR, blk_sreg);
    default:
        errno = EINVAL;
        return -1;
    }
}

int do_getsockname(int sockfd, char *name, int *namelen)
{
    PRINTF("joynetd: getsockname(%d, %p, %p)\n", sockfd, name, namelen);

    int sno = validate_sockfd(sockfd, SOCKFD_SOCKET);
    if (sno < 0) {
        return -1;
    }

    int blk_sreg = sno * 4 + 1;
    if (name != NULL && namelen != NULL && *namelen >= sizeof(struct sockaddr_in)) {
        struct sockaddr_in *sin = (struct sockaddr_in *)name;
        sin->sin_family = AF_INET;
        sin->sin_addr.s_addr = htonl(w5500_read_l(W5500_SIPR, 0));
        sin->sin_port = htons(w5500_read_w(W5500_Sn_PORT, blk_sreg));
        *namelen = sizeof(struct sockaddr_in);
        return 0;
    }
    errno = EINVAL;
    return -1;
}

int do_getpeername(int sockfd, char *peer, int *peerlen)
{
    PRINTF("joynetd: getpeername(%d, %p, %p)\n", sockfd, peer, peerlen);

    int sno = validate_sockfd(sockfd, SOCKFD_SOCKET);
    if (sno < 0) {
        return -1;
    }

    int blk_sreg = sno * 4 + 1;
    if (peer != NULL && peerlen != NULL && *peerlen >= sizeof(struct sockaddr_in)) {
        struct sockaddr_in *sin = (struct sockaddr_in *)peer;
        sin->sin_family = AF_INET;
        sin->sin_addr.s_addr = htonl(w5500_read_l(W5500_Sn_DIPR, blk_sreg));
        sin->sin_port = htons(w5500_read_w(W5500_Sn_DPORT, blk_sreg));
        *peerlen = sizeof(struct sockaddr_in);
        return 0;
    }
    errno = EINVAL;
    return -1;
}

int do_sockkick(int sockfd)
{
    PRINTF("joynetd: sockkick(%d)\n", sockfd);

    int sno = validate_sockfd(sockfd, SOCKFD_SOCKET);
    if (sno < 0) {
        return -1;
    }

    return 0;
}

int do_shutdown(int sockfd, int how)
{
    PRINTF("joynetd: shutdown(%d, %d)\n", sockfd, how);

    int sno = validate_sockfd(sockfd, SOCKFD_SOCKET);
    if (sno < 0) {
        return -1;
    }

    int blk_sreg = sno * 4 + 1;
    usock *u = &usock_array[sockfd - SOCKBASE];

    if (u->type == TYPE_TCP) {
        w5500_write_b(W5500_Sn_CR, blk_sreg, W5500_Sn_CR_DISCON);
    }

    return 0;
}

int do_usesock(int sockfd)
{
    PRINTF("joynetd: usesock(%d)\n", sockfd);

    int sno = validate_sockfd(sockfd, SOCKFD_SOCKET);
    if (sno < 0) {
        return -1;
    }

    usock *u = &usock_array[sockfd - SOCKBASE];
    u->refcnt++;
    return 0;
}

int do_rrecvchar(int sockfd)
{
    PRINTF("joynetd: rrecvchar(%d)\n", sockfd);

    uint8_t c;
    if (do_recvfrom(sockfd, &c, 1, 0, NULL, NULL) != 1) {
        return -1;
    }
    return c;
}

int do_recvchar(int sockfd)
{
    PRINTF("joynetd: recvchar(%d)\n", sockfd);

    int sno = validate_sockfd(sockfd, SOCKFD_RDWR);
    if (sno < 0) {
        return -1;
    }

    usock *u = &usock_array[sockfd - SOCKBASE];
    if (u->flag == SOCK_BINARY) {
        return do_rrecvchar(sockfd);
    } else {
        int c;
        c = do_rrecvchar(sockfd);
        if (c < 0) {
            return -1;
        } else if (c != u->eol[0]) {
            return c;
        } else if (u->eol[1] == '\0') {
            return '\n';
        }

        c = do_rrecvchar(sockfd);
        if (c < 0) {
            return -1;
        } else if (c != u->eol[1]) {
            return c;
        } else {
            return '\n';
        }
    }
}

int do_recvline(int sockfd, char *buf, size_t len)
{
    PRINTF("joynetd: recvline(%d, %p, %lu)\n", sockfd, buf, len);

    char *p = buf;
    while (len > 0) {
        int c = do_recvchar(sockfd);
        if (c < 0) {
            return -1;
        }
        *p++ = c;
        len--;
        if (c == '\n') {
            break;
        }
    }
    return p - buf;
}

int do_sendline(int sockfd, const char *buf, size_t len)
{
    PRINTF("joynetd: sendline(%d, %p, %lu)\n", sockfd, buf, len);
    errno = ENOSYS;
    return -1;
}

int do_usflush(int sockfd)
{
    PRINTF("joynetd: usflush(%d)\n", sockfd);

    int sno = validate_sockfd(sockfd, SOCKFD_SOCKET);
    if (sno < 0) {
        return -1;
    }

    return 0;
}

int do_seteol(int sockfd, char *seq)
{
    PRINTF("joynetd: seteol(%d, %02x:%02x)\n", sockfd, seq[0], seq[1]);

    int sno = validate_sockfd(sockfd, SOCKFD_SOCKET);
    if (sno < 0) {
        return -1;
    }

    usock *u = &usock_array[sockfd - SOCKBASE];
    strncpy(u->eol, seq, 2);
    u->eol[2] = '\0';

    return 0;
}

int do_sockmode(int sockfd, int mode)
{
    PRINTF("joynetd: sockmode(%d, %d)\n", sockfd, mode);

    int sno = validate_sockfd(sockfd, SOCKFD_SOCKET);
    if (sno < 0) {
        return -1;
    }

    usock *u = &usock_array[sockfd - SOCKBASE];
    int oldmode = u->flag;
    if (mode == SOCK_BINARY || mode == SOCK_ASCII) {
        u->flag = mode;
    }
    return oldmode;
}

int do_setflush(int sockfd, int chr)
{
    PRINTF("joynetd: setflush(%d, %d)\n", sockfd, chr);

    int sno = validate_sockfd(sockfd, SOCKFD_SOCKET);
    if (sno < 0) {
        return -1;
    }

    return 0;
}

char *do_psocket(long *arg)
{
    PRINTF("joynetd: psocket(%p)\n", arg);
    return "";
}

char *do_sockerr(int sockfd)
{
    PRINTF("joynetd: sockerr(%d)\n", sockfd);

    int sno = validate_sockfd(sockfd, SOCKFD_SOCKET);
    if (sno < 0) {
        return NULL;
    }

    return "";
}

char *do_sockstate(int sockfd)
{
    PRINTF("joynetd: sockstate(%d)\n", sockfd);

    int sno = validate_sockfd(sockfd, SOCKFD_SOCKET);
    if (sno < 0) {
        return NULL;
    }

    int isconnecting = (sockfd < SOCKCLNT_BASE) && ((usock_connecting & (1 << sno)) != 0);
    int islistening = (sockfd < SOCKCLNT_BASE) && ((usock_listening & (1 << sno)) != 0);

    int blk_sreg = sno * 4 + 1;
    switch (w5500_read_b(W5500_Sn_SR, blk_sreg)) {
    case W5500_Sn_SR_CLOSED:
        return "CLOSED";
    case W5500_Sn_SR_INIT:
        return isconnecting ? "SYN SENT" : "INIT";
    case W5500_Sn_SR_LISTEN:
        return "LISTEN";
    case W5500_Sn_SR_SYNSENT:
        return "SYN SENT";
    case W5500_Sn_SR_SYNRECV:
        return islistening ? "LISTEN" : "SYN RECEIVED";
    case W5500_Sn_SR_ESTABLISHED:
        if (isconnecting) {
            usock_connecting &= ~(1 << sno);
        }
        return islistening ? "LISTEN" : "ESTABLISHED";
    case W5500_Sn_SR_FIN_WAIT:
        return islistening ? "LISTEN" : "FIN_WAIT";
    case W5500_Sn_SR_CLOSING:
        return islistening ? "LISTEN" : "CLOSING";
    case W5500_Sn_SR_TIME_WAIT:
        return islistening ? "LISTEN" : "TIME_WAIT";
    case W5500_Sn_SR_CLOSE_WAIT:
        return islistening ? "LISTEN" : "CLOSE_WAIT";
    case W5500_Sn_SR_LAST_ACK:
        return islistening ? "LISTEN" : "LAST_ACK";
    case W5500_Sn_SR_UDP:
        return "UDP";
    case W5500_Sn_SR_IPRAW:
        return "IPRAW";
    case W5500_Sn_SR_MACRAW:
        return "MACRAW";
    default:
        return "";
    }
}

// ---------------------------------------------------------------------------

int do_command(void)
{
    int cmd;
    long *arg;

    __asm__ volatile (
        "move.l %%d0,%0\n"
        "move.l %%a0,%1\n"
        : "=r" (cmd), "=r" (arg) : : "d0", "a0"
    );

    int res = -1;

    PRINTF("joynetd: do_command cmd=%d arg=%p\r\n", cmd, arg);

    w5500_ini();

    switch (cmd) {
    case -1:        // trap番号の取得
        res = trap_number;
        break;

    case _TI_get_version:
        res = 0x00010000;  // (TBD) version
        break;

    case _TI_add_arp_table:
    case _TI_del_arp_table:
    case _TI_search_arp_table:
        res = 0;
        break;
    case _TI_get_arp_table_top:
        res = (int)&dummy_arp_table;
        break;
    case _TI_arp_request:
        res = 0;
        break;

    case _TI_get_iface_list:
        res = (int)do_get_iface_list();
        break;
    case _TI_get_new_iface:
        res = (int)do_get_new_iface((const char *)arg);
        break;
    case _TI_link_new_iface:
        res = do_link_new_iface((const struct iface *)arg);
        break;

    case _TI_rt_top:
    case _TI_rt_lookup:
    case _TI_rt_lookupb:
    case _TI_rt_drop:
    case _TI_rt_add:
        res = 0;
        break;

    case _TI_dns_add:
    case _TI_dns_drop:
    case _TI_dns_get:
        res = 0;
        break;
    case _TI_set_domain_name:
        res = do_set_domain_name((char *)arg);
        break;
    case _TI_get_domain_name:
        res = (int)do_get_domain_name();
        break;
    case _TI_res_query:
        res = do_res_query((char *)arg[0], arg[1], arg[2], (unsigned char *)arg[3], arg[4]);
        break;
    case _TI_res_search:
        res = do_res_search((char *)arg[0], arg[1], arg[2], (unsigned char *)arg[3], arg[4]);
        break;
    case _TI_res_mkquery:
        res = do_res_mkquery(arg[0], (char *)arg[1], arg[2], arg[3],
                             (char *)arg[4], arg[5],
                             (struct rrec *)arg[6],
                             (char *)arg[7], arg[8]);
        break;
    case _TI_res_sendquery:
        res = do_res_send((char *)arg[0], arg[1], (char *)arg[2], arg[3]);
        break;

    case _TI_get_MIB:
        res = (int)&dummy_mib_array;
        break;

    case _TI_socket:
        res = do_socket(arg[0], arg[1], arg[2]);
        break;
    case _TI_bind:
        res = do_bind(arg[0], (const struct sockaddr *)arg[1], arg[2]);
        break;
    case _TI_listen:
        res = do_listen(arg[0], arg[1]);
        break;
    case _TI_accept:
        res = do_accept(arg[0], (struct sockaddr *)arg[1], (socklen_t *)arg[2]);
        break;
    case _TI_connect:
        res = do_connect(arg[0], (const struct sockaddr *)arg[1], arg[2]);
        break;
    case _TI_read_s:
        res = do_recvfrom(arg[0], (void *)arg[1], arg[2], 0, NULL, NULL);
        break;
    case _TI_write_s:
        res = do_sendto(arg[0], (const void *)arg[1], arg[2], 0, NULL, 0);
        break;
    case _TI_recvfrom:
        res = do_recvfrom(arg[0], (void *)arg[1], arg[2],
                          arg[3], (struct sockaddr *)arg[4], (socklen_t *)arg[5]);
        break;
    case _TI_sendto:
        res = do_sendto(arg[0], (const void *)arg[1], arg[2],
                        arg[3], (struct sockaddr *)arg[4], arg[5]);
        break;
    case _TI_close_s:
        res = do_close((int)arg);
        break;
    case _TI_socklen:
        res = do_socklen(arg[0], arg[1]);
        break;
    case _TI_getsockname:
        res = do_getsockname(arg[0], (char *)arg[1], (int *)arg[2]);
        break;
    case _TI_getpeername:
        res = do_getpeername(arg[0], (char *)arg[1], (int *)arg[2]);
        break;
    case _TI_sockkick:
        res = do_sockkick(arg[0]);
        break;
    case _TI_shutdown:
        res = do_shutdown(arg[0], arg[1]);
        break;
    case _TI_usesock:
        res = do_usesock(arg[0]);
        break;
    case _TI_recvline:
        res = do_recvline(arg[0], (char *)arg[1], arg[2]);
        break;
    case _TI_sendline:
        res = do_sendline(arg[0], (const char *)arg[1], arg[2]);
        break;
    case _TI_rrecvchar:
        res = do_rrecvchar(arg[0]);
        break;
    case _TI_recvchar:
        res = do_recvchar(arg[0]);
        break;
    case _TI_usflush:
        res = do_usflush(arg[0]);
        break;
    case _TI_seteol:
        res = do_seteol(arg[0], (char *)arg[1]);
        break;
    case _TI_sockmode:
        res = do_sockmode(arg[0], arg[1]);
        break;
    case _TI_setflush:
        res = do_setflush(arg[0], arg[1]);
        break;
    case _TI_psocket:
        res = (int)do_psocket(arg);
        break;
    case _TI_sockerr:
        res = (int)do_sockerr((int)arg);
        break;
    case _TI_sockstate:
        res = (int)do_sockstate((int)arg);
        break;

    case _TI_sock_top:
        res = (int)&usock_array;
        break;
    case _TI_ntoa_sock:
        res = 0;
        break;

    case _TI_gethostbyname:
        res = (int)do_gethostbyname((const char *)arg);
        break;
    case _TI_gethostbyaddr:
        res = (int)do_gethostbyaddr((const char *)arg[0], arg[1], arg[2]);
        break;
    case _TI_getnetbyname:
        res = (int)do_getnetbyname((const char *)arg);
        break;
    case _TI_getnetbyaddr:
        res = (int)do_getnetbyaddr(arg[0], arg[1]);
        break;
    case _TI_getservbyname:
        res = (int)do_getservbyname((const char *)arg[0], (const char *)arg[1]);
        break;
    case _TI_getservbyport:
        res = (int)do_getservbyport(arg[0], (const char *)arg[1]);
        break;
    case _TI_getprotobyname:
        res = (int)do_getprotobyname((const char *)arg);
        break;
    case _TI_getprotobynumber:
        res = (int)do_getprotobynumber((int)arg);
        break;

    case _TI_rip:
    default:
        break;
    }

    w5500_fin();

    return res;
}
