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

#include "tcpipdrv.h"
#include "w5500.h"

#include "joynetd.h"

//****************************************************************************
// Macros and definitions
//****************************************************************************

//****************************************************************************
// Global variables
//****************************************************************************

//****************************************************************************
// Private functions
//****************************************************************************

#define DNS_SERVER "8.8.8.8"  // Google DNS
#define DNS_PORT 53
#define MAX_RESPONSE_SIZE 512

// DNS Header
typedef struct {
    unsigned short id;
    unsigned short flags;
    unsigned short qdcount;  // Question count
    unsigned short ancount;  // Answer count
    unsigned short nscount;
    unsigned short arcount;
} DNSHeader;

// DNS Question
typedef struct {
    unsigned short type;
    unsigned short class;
} DNSQuestion;


int do_res_query(char *dname, int class, int type, unsigned char *answer, int anslen)
{
    PRINTF("joynetd: res_query(%s, %d, %d, %p, %d)\n", dname, class, type, answer, anslen);

    uint8_t query[512];
    int qlen = do_res_mkquery(0, dname, class, type, NULL, 0, NULL, (char *)query, sizeof(query));
    if (qlen < 0) {
        PRINTF("mkquery failed\n");
        return 0;
    }
    int rlen = do_res_send((char *)query, qlen, (char *)answer, anslen);
    if (rlen < 0) {
        PRINTF("res_send failed\n");
        return 0;
    }
    return rlen;
}

int do_res_search(char *dname, int class, int type, unsigned char *answer, int anslen)
{
    PRINTF("joynetd: res_search(%s, %d, %d, %p, %d)\n", dname, class, type, answer, anslen);

    uint8_t query[512];
    int qlen = do_res_mkquery(0, dname, class, type, NULL, 0, NULL, (char *)query, sizeof(query));
    if (qlen < 0) {
        PRINTF("mkquery failed\n");
        return 0;
    }
    int rlen = do_res_send((char *)query, qlen, (char *)answer, anslen);
    if (rlen < 0) {
        PRINTF("res_send failed\n");
        return 0;
    }
    return rlen;
}

int do_res_mkquery(int op, char *dname, int class, int type, char *data, int datalen,
                   struct rrec *newrr, char *buf, int buflen)
{
    PRINTF("joynetd: res_mkquery(%d, %s, %d, %d, %p, %d, %p, %p, %d)\n",
           op, dname, class, type, data, datalen, newrr, buf, buflen);

    DNSHeader *header = (DNSHeader *)buf;
    unsigned char *qname = (unsigned char *)buf + sizeof(DNSHeader);
    
    memset(header, 0, sizeof(DNSHeader));
    header->id = htons(1);      // TBD
    header->flags = htons(0x0100);  // Standard query
    header->qdcount = htons(1);

    // Encode hostname (example.com -> 7example3com0)
    const char *p = dname;
    unsigned char *q = qname;
    while (*p) {
        unsigned char *len_ptr = q++;
        int len = 0;
        while (*p && *p != '.') {
            *q++ = *p++;
            len++;
        }
        *len_ptr = len;
        if (*p == '.') p++;
    }
    *q++ = 0;
    
    // Add question
    DNSQuestion *question = (DNSQuestion *)q;
#if 0
    question->type = htons(type);      // A record
    question->class = htons(class);     // IN class
#else
    uint8_t *qt = (uint8_t *)&question->type;
    qt[0] = type >> 8;
    qt[1] = type & 0xff;
    uint8_t *qc = (uint8_t *)&question->class;
    qc[0] = class >> 8;
    qc[1] = class & 0xff;
#endif
    q += sizeof(DNSQuestion);

    // TBD: data, datalen

    return (char *)q - (char *)buf;
}

int do_res_send(char *msg, int msglen, char *answer, int anslen)
{
    PRINTF("joynetd: res_send(%p, %d, %p, %d)\n", msg, msglen, answer, anslen);

    // Create UDP socket
    int sock = do_socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        PRINTF("socket\n");
        return -1;
    }
    
    // Send to DNS server
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(DNS_PORT);
    inet_pton(AF_INET, DNS_SERVER, &server_addr.sin_addr);
    
    ssize_t n = do_sendto(sock, msg, msglen, 0,
                          (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (n < 0) {
        PRINTF("sendto\n");
        do_close(sock);
        return -1;
    }
    
    // Receive response
    n = do_recvfrom(sock, answer, anslen, 0, NULL, NULL);
    if (n < 0) {
        PRINTF("recvfrom\n");
        do_close(sock);
        return -1;
    }

    do_close(sock);
    return n;
}
