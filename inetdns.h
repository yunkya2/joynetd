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

#ifndef _INETDNS_H_
#define _INETDNS_H_

#include <sys/socket.h>
#include <netdb.h>

struct rrec {
  short r_zone;			/* zone number */
  short r_class;		/* class number */
  short r_type;			/* type number */
  unsigned long r_ttl;		/* time to live */
  int r_size;			/* size of data area */
  char *r_data;			/* pointer to data */
};

int do_res_query(char *dname, int class, int type, unsigned char *answer, int anslen);
int do_res_search(char *dname, int class, int type, unsigned char *answer, int anslen);
int do_res_mkquery(int op, char *dname, int class, int type, char *data, int datalen,
                   struct rrec *newrr, char *buf, int buflen);
int do_res_send(char *msg, int msglen, char *answer, int anslen);

#endif /* _INETDNS_H_ */
