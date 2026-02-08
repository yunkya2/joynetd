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

#include "joynetd.h"

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
    int magic;
    void *memblock;
    int vectno;
    void *oldvect;
    void *oldvect_joy;
};

#define JOYNET_MAGIC    0x4a4f5901  // "JOY\1"

//****************************************************************************
// Global variables
//****************************************************************************

extern struct dos_devheader devheader;  // Human68kのデバイスヘッダ

extern int joyget();
extern uint16_t joyget_stat;
extern uint16_t joyget_port;
extern void *joyget_org;

struct joynetd_data joynetd_data = {
    .magic = JOYNET_MAGIC,
    .vectno = 0,
};

int trap_number = -1;

static bool opt_r = false;  // -r option

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

//****************************************************************************
// Program entry
//****************************************************************************

void help(void)
{
    printf("使用法: joynetd [-r] [-p|-j<port number>] [-t<trap number>]\n");
    printf("  -r       常駐解除\n");
    printf("  -p|-j    使用するジョイスティックポート番号 (1 or 2) (default: 1)\n");
    printf("  -t       APIのtrap番号 (0～7)\n");
    exit(1);
}

int main(int argc, char **argv)
{
    _dos_print("X680x0 Ethernet Joy-kun Network driver (version " GIT_REPO_VERSION ")\r\n");

    int port = 1;
    int trap = -2;

    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-' || argv[i][0] == '/') {
            switch (argv[i][1]) {
            case 'r':
                opt_r = true;
                break;
            case 'p':
            case 'j':
                port = atoi(&argv[i][2]);
                if (port < 1 || port > 2) {
                    help();
                }
                break;
            case 't':
                trap = atoi(&argv[i][2]);
                if (trap > 7) {
                    help();
                }
                break;
            default:
                help();
                return 1;
            }
        }
    }

    w5500_select(port);
    joyget_stat = 0x4b00 + port;
    joyget_port = port - 1;

    _dos_super(0);

    if (opt_r) {
        struct dos_devheader *prev = find_devheader("/joynet/");
        if (prev == NULL) {
            _dos_print("joynetd は常駐していません\r\n");
            return 0;
        }

        struct joynetd_data *data = prev->next->data;
        if (data->magic != JOYNET_MAGIC) {
            _dos_print("常駐している joynetd のバージョンが異なります\r\n");
            return 1;
        }
        if (data->vectno != 0) {
            _dos_intvcs(data->vectno, data->oldvect);
        }
        _dos_intvcs(0x013b, data->oldvect_joy);
        prev->next = prev->next->next;
        _dos_print("joynetd を常駐解除しました\r\n");
        _dos_mfree(data->memblock);
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

    init_etc_files();
    read_config();

    w5500_fin();

    if (trap < -1) {    // 未使用のtrap番号を探す
        for (trap = 0; trap < 8; trap++) {
            if ((int)_dos_intvcg(trap + 0x20) >= 0x01000000) {
                break;
            }
        }
        if (trap >= 8) {
            trap = -1;  // trapが空いていないので使用しない
        }
    }
    if (trap >= 0) {
        if ((int)_dos_intvcg(trap + 0x20) < 0x01000000) {
            _dos_print("指定されたtrap番号は既に使用されています\r\n");
            return 1;
        }
        extern int trap_entry(void);
        joynetd_data.vectno = trap + 0x20;
        joynetd_data.oldvect = _dos_intvcs(joynetd_data.vectno, trap_entry);
        trap_number = trap;
    }
    PRINTF("joynetd: using trap number %d\n", trap_number);

    joynetd_data.memblock = _dos_getpdb();
    joynetd_data.oldvect_joy = _dos_intvcs(0x013b, joyget);
    joyget_org = joynetd_data.oldvect_joy;

    prev = find_devheader(NULL);
    prev->next = &devheader;

    _dos_print("joynetd が常駐しました\r\n");

    // ヒープ領域の末尾までを常駐して終了する
    // (ヒープの後ろにあるスタック領域は常駐しない)
    extern char *tcpip_magic;
    extern char *_HEND;
    _dos_keeppr((int)_HEND - (int)&tcpip_magic, 0);
}
