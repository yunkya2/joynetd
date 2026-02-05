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

#include <x68k/dos.h>
#include <x68k/iocs.h>

#include "tcpipdrv.h"
#include "w5500.h"

//****************************************************************************
// Macros and definitions
//****************************************************************************

struct dos_devheader {
    struct dos_devheader *next;
    uint16_t    attr;
    void        *strategy;
    void        *interrupt;
    char        name[8];
    struct joynetd_data *data;
};

struct joynetd_data {
    void *memblock;
};

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

extern struct dos_devheader devheader;  // Human68kのデバイスヘッダ

struct joynetd_data joynetd_data;

_arp_table *arp_table[ARPSIZE];

struct mib_array mib_array[4] = {
    { NULL, 0, "IP" },
    { NULL, 0, "ICMP" },
    { NULL, 0, "UDP" },
    { NULL, 0, "TCP" }
};

usock usock_array[DEFNSOCK];


bool opt_r = false;  // -r option

//****************************************************************************
// Private functions
//****************************************************************************

// 次のデバイスが name であるデバイスヘッダを探す
static struct dos_devheader *find_devheader(char *name)
{
    // Human68kからNULデバイスドライバを探す
    char *p = *(char **)0x001c20;   // 先頭のメモリブロック
    while (memcmp(p, "NUL     ", 8) != 0) {
        p += 2;
    }

    // デバイスドライバのリンクをたどって name の前のデバイスヘッダを探す
    // (name == NULLなら最後のデバイスヘッダを返す)
    struct dos_devheader *devh = (struct dos_devheader *)(p - 14);
    while (devh->next != (struct dos_devheader *)-1) {
        if (name && memcmp(devh->next->name, name, 8) == 0) {
            return devh;
        }
        devh = devh->next;
    }
    return name ? NULL : devh;
}

// TCP/IPスタックが存在するか確認する
static void *find_tcpip(void)
{
    struct dos_psp *psp;
    struct dos_mep *mep;

    psp = _dos_getpdb();
    mep = &((struct dos_mep *)psp)[-1];

    while ((mep = mep->prev_mp)) {
        if (((int)mep->parent_mp & 0xff000000) == 0xff000000) {
            if (memcmp((uint8_t *)((int)mep + 0x100), "TCP/IP", 6) == 0) {
                return mep;  // TCP/IPスタックが存在する
            }
        }
    }
    return NULL;
}

//----------------------------------------------------------------------------

int do_command(int cmd, void *arg)
{
    printf("joynetd: do_command cmd=%d arg=%p\r\n", cmd, arg);

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
    case _TI_bind:
    case _TI_listen:
    case _TI_accept:
    case _TI_connect:
    case _TI_read_s:
    case _TI_write_s:
    case _TI_recvfrom:
    case _TI_sendto:
    case _TI_close_s:
    case _TI_socklen:
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
    case _TI_seteol:
    case _TI_sockmode:
    case _TI_setflush:
    case _TI_psocket:
    case _TI_sockerr:
    case _TI_sockstate:
        return -1;

    case _TI_sock_top:
        return (int)&usock_array;
    case _TI_ntoa_sock:
        return -1;

    case _TI_gethostbyname:
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

//****************************************************************************
// Program entry
//****************************************************************************

void help(void)
{
    printf("Usage: joynetd [-r]\n");
    printf("  -r    Remove resident joynetd from memory\n");
    exit(1);
}

int main(int argc, char **argv)
{
    _dos_print("X680x0 Ethernet Joy-kun Network driver (version " GIT_REPO_VERSION ")\r\n");

    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-' || argv[i][0] == '/') {
            switch (argv[i][1]) {
            case 'r':
                opt_r = true;
                break;
            default:
                help();
                return 1;
            }
        }
    }

    _dos_super(0);

    if (opt_r) {
        struct dos_devheader *prev = find_devheader("/joynet/");
        if (prev != NULL) {
            struct joynetd_data *data = prev->next->data;
            prev->next = prev->next->next;
            _dos_print("joynetd を常駐解除しました\r\n");
            _dos_mfree(data->memblock);
        } else {
            _dos_print("joynetd は常駐していません\r\n");
        }
        return 0;
    }

    //////////////////////////////////////////////////////////////////////////

    struct dos_devheader *prev = find_devheader("/joynet/");
    if (prev != NULL) {
        _dos_print("既に joynetd が常駐しています\r\n");
        return 0;
    }
    if (find_tcpip() != NULL) {
        _dos_print("既に他のTCP/IPドライバが常駐しています\r\n");
        return 1;
    }

    w5500_ini();

    w5500_write_b(W5500_MR, 0, 0x80);   // ソフトウェアリセット

    if (w5500_read_b(W5500_VERSIONR, 0) != 0x04) {
        _dos_print("イーサネットじょい君が接続されていません\r\n");
        w5500_fin();
        return 1;
    }

    for (int i = 0; i < 0x40; i++) {
        if (i % 16 == 0) {
            printf("\n%02x:", i);
        }
        printf(" %02x", w5500_read_b(i, 0));
    }
    printf("\n");

    w5500_fin();

    joynetd_data.memblock = _dos_getpdb();

    prev = find_devheader(NULL);
    prev->next = &devheader;

    _dos_print("joynetd を常駐しました\r\n");

    _dos_keeppr(0xffffff, 0);  // ヒープ領域の末尾までを常駐
}
