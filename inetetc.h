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

#ifndef _INETETC_H_
#define _INETETC_H_

#include <sys/socket.h>

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

#endif /* _INETETC_H_ */
