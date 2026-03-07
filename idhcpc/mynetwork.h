/* SPDX-License-Identifier: 0BSD */

#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define n2a_ipaddr(addr, dst) inet_ntoa((struct in_addr){htonl(addr)})
