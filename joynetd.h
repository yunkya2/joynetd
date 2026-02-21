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

#ifndef _JOYNETD_H_
#define _JOYNETD_H_

//#define DEBUG

#ifdef DEBUG
#define PRINTF(...) printf(__VA_ARGS__)
#else
#define PRINTF(...)
#endif

#include <stdbool.h>
#include <sys/socket.h>
#include <netdb.h>

#include "w5500.h"

#define IFNAME "en0"

// joynetd.c
extern bool ifenable;
extern int trap_number;
int set_ifenable(bool enable);

// inetcmd.c
int do_socket(int domain, int type, int protocol);
int do_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
ssize_t do_read(int sockfd, void *buf, size_t count);
ssize_t do_write(int sockfd, const void *buf, size_t count);
ssize_t do_recvfrom(int sockfd, void *buf, size_t len,
                    int flags, struct sockaddr *src_addr, socklen_t *addrlen);
ssize_t do_sendto(int sockfd, const void *buf, size_t len,
                  int flags, struct sockaddr *dest_addr, socklen_t addrlen);
int do_close(int sockfd);
int do_socklen(int sockfd, int mode);

int do_seteol(int sockfd, char *seq);
int do_sockmode(int sockfd, int mode);
int do_setflush(int sockfd, int chr);

// inetiface.c
struct iface;
struct iface *do_get_iface_list(void);
struct iface *do_get_new_iface(const char *name);
int do_link_new_iface(const struct iface *n_i);

// inetdns.c
struct dns;
int do_dns_add(long ipaddr);
int do_dns_drop(long ipaddr);
struct dns *do_dns_get(void);
struct rrec;
int do_set_domain_name(char *name);
char *do_get_domain_name(void);
int do_res_query(char *dname, int class, int type, unsigned char *answer, int anslen);
int do_res_search(char *dname, int class, int type, unsigned char *answer, int anslen);
int do_res_mkquery(int op, char *dname, int class, int type, char *data, int datalen,
                   struct rrec *newrr, char *buf, int buflen);
int do_res_send(char *msg, int msglen, char *answer, int anslen);

// inetetc.c
struct hostent *do_gethostbyname(const char *name);
struct hostent *do_gethostbyaddr(const void *addr, socklen_t len, int type);
struct netent *do_getnetbyname(const char *name);
struct netent *do_getnetbyaddr(uint32_t net, int type);
struct servent *do_getservbyname(const char *name, const char *proto);
struct servent *do_getservbyport(int port, const char *proto);
struct protoent *do_getprotobynumber(int proto);
struct protoent *do_getprotobyname(const char *name);

int init_etc_files(void);
void fini_etc_files(void);

// inetconfig.c
void read_config(void);

#endif /* _JOYNETD_H_ */
