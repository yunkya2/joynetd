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

#define DNS_PORT 53
#define MAX_RESPONSE_SIZE 512
#define DNS_CACHE_MAX_ENTRIES 8
#define DNS_CACHE_EXPIRE_TIME (100 * 60 * 5)  // 5 minutes

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

struct dns_cache_entry {
    struct dns_cache_entry *next;
    char *dname;
    int type;
    int class;
    unsigned char *answer;
    int anslen;
    struct iocs_time timestamp;
};

//****************************************************************************
// Global variables
//****************************************************************************

extern uint8_t w5500_dns[4];

char *domainname = NULL;

struct dns_cache_entry *dns_cache = NULL;
static int dns_cache_count = 0;

//****************************************************************************
// Private functions
//****************************************************************************

static inline unsigned int duration(struct iocs_time *t0)
{
    struct iocs_time now = _iocs_ontime();

    return (now.sec - t0->sec) +
           (now.day - t0->day) * 24 * 60 * 60 * 100;
}

static void remove_dns_cache_entry(struct dns_cache_entry *entry, struct dns_cache_entry *prev)
{
    // Remove from list
    if (prev != NULL) {
        prev->next = entry->next;
    } else {
        dns_cache = entry->next;
    }
    // Free memory
    if (entry->dname != NULL) free(entry->dname);
    if (entry->answer != NULL) free(entry->answer);
    free(entry);
    dns_cache_count--;
}

static void add_dns_cache_entry(char *dname, int class, int type, unsigned char *answer, int anslen)
{
    struct dns_cache_entry *new_entry = (struct dns_cache_entry *)malloc(sizeof(struct dns_cache_entry));
    if (new_entry == NULL) {
        return;
    }

    new_entry->dname = (char *)malloc(strlen(dname) + 1);
    new_entry->answer = (unsigned char *)malloc(anslen);
    if (new_entry->dname == NULL || new_entry->answer == NULL) {
        if (new_entry->dname != NULL) free(new_entry->dname);
        if (new_entry->answer != NULL) free(new_entry->answer);
        free(new_entry);
        return;
    }

    strcpy(new_entry->dname, dname);
    memcpy(new_entry->answer, answer, anslen);
    new_entry->type = type;
    new_entry->class = class;
    new_entry->anslen = anslen;
    new_entry->timestamp = _iocs_ontime();
    new_entry->next = dns_cache;
    dns_cache = new_entry;
    dns_cache_count++;
    
    // Remove oldest entry if cache is full
    if (dns_cache_count > DNS_CACHE_MAX_ENTRIES) {
        struct dns_cache_entry *curr = dns_cache;
        struct dns_cache_entry *prev = NULL;
        while (curr->next != NULL) {
            prev = curr;
            curr = curr->next;
        }
        if (prev != NULL) {
            remove_dns_cache_entry(curr, prev);
        }
    }
}

static struct dns_cache_entry *find_dns_cache(char *dname, int class, int type)
{
    struct dns_cache_entry *entry = dns_cache;
    struct dns_cache_entry *prev = NULL;
    
    while (entry != NULL) {
        struct dns_cache_entry *next = entry->next;
        
        // Check if entry has expired
        if (duration(&entry->timestamp) >= DNS_CACHE_EXPIRE_TIME) {
            PRINTF("Cache entry expired: %s\n", entry->dname);
            // Remove expired entry
            remove_dns_cache_entry(entry, prev);
            entry = next;
            continue;
        }
        
        if (strcasecmp(entry->dname, dname) == 0 &&
            entry->class == class &&
            entry->type == type) {
            // Move to the head (without updating timestamp)
            if (prev != NULL) {
                prev->next = entry->next;
                entry->next = dns_cache;
                dns_cache = entry;
            }
            return entry;
        }
        prev = entry;
        entry = next;
    }
    return NULL;
}

//****************************************************************************
// Public functions
//****************************************************************************

int do_res_query(char *dname, int class, int type, unsigned char *answer, int anslen)
{
    PRINTF("joynetd: res_query(%s, %d, %d, %p, %d)\n", dname, class, type, answer, anslen);

    // Check cache first
    struct dns_cache_entry *entry = find_dns_cache(dname, class, type);
    if (entry != NULL) {
        PRINTF("Found in cache\n");
        // Copy cached answer to answer buffer
        if (entry->anslen <= anslen) {
            memcpy(answer, entry->answer, entry->anslen);
            return entry->anslen;
        }
        return 0; // Buffer too small
    }

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

    // Cache the result
    add_dns_cache_entry(dname, class, type, answer, rlen);

    return rlen;
}

int do_res_search(char *dname, int class, int type, unsigned char *answer, int anslen)
{
    PRINTF("joynetd: res_search(%s, %d, %d, %p, %d)\n", dname, class, type, answer, anslen);

    // If dname does not contain '.', append domainname
    if (strchr(dname, '.') == NULL && domainname != NULL && *domainname != '\0') {
        char fullname[256];
        strncpy(fullname, dname, sizeof(fullname) - 1);
        fullname[sizeof(fullname) - 1] = '\0';
        strncat(fullname, ".", sizeof(fullname) - strlen(fullname) - 1);
        strncat(fullname, domainname, sizeof(fullname) - strlen(fullname) - 1);
        return do_res_query(fullname, class, type, answer, anslen);
    }

    return do_res_query(dname, class, type, answer, anslen);
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
    memcpy(&server_addr.sin_addr, w5500_dns, 4);
    
    ssize_t n = do_sendto(sock, msg, msglen, 0,
                          (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (n < 0) {
        PRINTF("sendto\n");
        do_close(sock);
        return -1;
    }
    
    // Receive response

    struct iocs_time t0 = _iocs_ontime();
    int timeout = 100 * 1;
    int counter = 0;

    while (1) {
        if (do_socklen(sock, 0) > 0) {
            break;
        }
        if (duration(&t0) >= timeout) {
            PRINTF("res_send: timeout %d\n", counter);
            if (++counter > 4) {
                PRINTF("DNS timeout\n");
                do_close(sock);
                return -1;
            }
            timeout += 100 * counter;
        }
    }

    n = do_recvfrom(sock, answer, anslen, 0, NULL, NULL);
    if (n < 0) {
        PRINTF("recvfrom\n");
        do_close(sock);
        return -1;
    }

    do_close(sock);
    return n;
}
