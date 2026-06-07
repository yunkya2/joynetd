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
#include <unistd.h>

#include <x68k/dos.h>
#include <x68k/iocs.h>

#include "winetd.h"
#include "wificmd.h"

//****************************************************************************
// Macros and definitions
//****************************************************************************

struct dos_devheader {
    struct dos_devheader *next;
    uint16_t    attr;
    void        *strategy;
    void        *interrupt;
    char        name[8];
    struct winetd_data *data;
};

struct winetd_data {
    int magic;
    void *memblock;
    int vectno;
    void *oldvect;
};

#define WINET_MAGIC     0x57694e01  // "WiN\1"

#define WIFI_JOIN_TIMEOUT   30000   // WiFi接続のタイムアウト時間（ms）

//****************************************************************************
// Global variables
//****************************************************************************

extern struct dos_devheader devheader;  // Human68kのデバイスヘッダ

struct winetd_data winetd_data = {
    .magic = WINET_MAGIC,
    .vectno = 0,
};

char *cfgfile = NULL;
int trap_number = NOSPEC_INT;
int trap_config_number = NOSPEC_INT;
char *ifname = NOSPEC_STR;
char wifi_ssid[32 + 1];
char wifi_passwd[64 + 1];
int dhcp_mode = NOSPEC_INT;
char *hostname = NOSPEC_STR;
uint32_t winetd_cfg_flags = 0;
bool ifenable = false;

static bool opt_r = false;  // -r option
static bool opt_v = false;  // -v option

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

int set_ifenable(bool enable)
{
    if (ifenable == enable) {
        return 0;
    }

    if (enable) {
        if (wifi_ssid[0] == '\0') {
            return -1;
        }

        do_wifi_join(wifi_ssid, wifi_passwd, -1);   // TBD

        int t = 0;
        while (t < WIFI_JOIN_TIMEOUT) {
            int stat = do_wifi_getstat();
            if (stat & W5500_WSR_JOINED) {
                break;
            } else if (stat & W5500_WSR_ERR) {
                if (stat & W5500_WSR_NONET) {
                    return -2;
                } else if (stat & W5500_WSR_BADAUTH) {
                    return -3;
                } else {
                    return -4;
                }
            }
            usleep(500 * 1000);
            t += 500;
        }
        if (t >= WIFI_JOIN_TIMEOUT) {
            return -5;
        }
    } else {
        do_wifi_leave();
    }

    ifenable = enable;
    return 0;
}

static int get_arg_opt(char **opt, int index, int argc, char **argv)
{
    if (argv[index][2] != '\0') {
        *opt = &argv[index][2];
        return index;
    } else if (index + 1 < argc) {
        *opt = argv[index + 1];
        return index + 1;
    } else {
        return -1;
    }
}

static int parse_cmdline(int argc, char **argv)
{
    int v;
    char *p;
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-' || argv[i][0] == '/') {
            switch (argv[i][1]) {
            case 'f':
                if ((i = get_arg_opt(&p, i, argc, argv)) < 0) {
                    return -1;
                }
                cfgfile = p;
                break;
            case 'r':
                opt_r = true;
                break;
            case 'v':
                opt_v = true;
                break;
            case 't':
                if ((i = get_arg_opt(&p, i, argc, argv)) < 0) {
                    return -1;
                }
                v = atoi(p);
                if (v > 7) {
                    return -1;
                }
                trap_number = v;
                trap_config_number = v;
                winetd_cfg_flags |= WINETD_CFGF_TRAP;
                break;
            case 'i':
                if ((i = get_arg_opt(&p, i, argc, argv)) < 0) {
                    return -1;
                }
                ifname = p;
                winetd_cfg_flags |= WINETD_CFGF_IFNAME;
                break;
            case 's':
                if ((i = get_arg_opt(&p, i, argc, argv)) < 0) {
                    return -1;
                }
                {
                    strncpy(wifi_ssid, p, 32);
                    wifi_ssid[32] = '\0';

                    if (i + 1 >= argc) {
                        return -1;
                    }

                    char *passwd = argv[i + 1];
                    strncpy(wifi_passwd, passwd, 64);
                    wifi_passwd[64] = '\0';

                    winetd_cfg_flags |= WINETD_CFGF_SSID;
                    winetd_cfg_flags |= WINETD_CFGF_PASSWD;

                    i++;    // パスワード引数を消費
                }
                break;
             case 'd':
                 if ((i = get_arg_opt(&p, i, argc, argv)) < 0) {
                    return -1;
                }
                v = atoi(p);
                if (v < 0 || v > 1) {
                    return -1;
                }
                dhcp_mode = v;
                winetd_cfg_flags |= WINETD_CFGF_DHCP;
                break;
            case 'h':
                if ((i = get_arg_opt(&p, i, argc, argv)) < 0) {
                    return -1;
                }
                hostname = p;
                winetd_cfg_flags |= WINETD_CFGF_HOSTNAME;
                break;
            default:
                return -1;
            }
        }
    }
    return 0;
}

static void help(void)
{
    printf(
        "使用法: winetd [オプション]\n"
        "オプション:\n"
        "  -r                 常駐解除\n"
        "  -f<config file>    設定ファイルのパスを指定する\n"
        "  -t<trap number>    APIのtrap番号 (0～7/-1(none)/-2(auto)) (default: -2)\n"
        "  -i<interface name> 使用するネットワークインターフェース名 (default: en0)\n"
        "  -s <ssid> <pass>   接続するWiFiのSSIDとパスワード (default: 接続しない)\n"
        "  -d<dhcp mode>      DHCP使用モード (0:使用しない / 1:使用する) (default: 1)\n"
        "  -h<host name>      DHCP使用時のホスト名 (default: なし)\n"
    );
    exit(1);
}

//****************************************************************************
// Program entry
//****************************************************************************

int main(int argc, char **argv)
{
    _dos_print("X680x0 WiFi+PCM Pileder Network driver for PilederX (version " GIT_REPO_VERSION ")\r\n");

    if (parse_cmdline(argc, argv) < 0) {
        help();
    }

    // 常駐解除処理

    if (opt_r) {
        _dos_super(0);

        struct dos_devheader *prev = find_devheader("/winet//");
        if (prev == NULL) {
            _dos_print("winetd は常駐していません\r\n");
            return 0;
        }

        struct winetd_data *data = prev->next->data;
        if (data->magic != WINET_MAGIC) {
            _dos_print("常駐している winetd のバージョンが異なります\r\n");
            return 1;
        }

        do_wifi_leave();

#if 0
        w5500_ini();
        w5500_write_b(W5500_MR, 0, 0x80);   // ソフトウェアリセット
#endif

        if (data->vectno != 0) {
            _dos_intvcs(data->vectno, data->oldvect);
        }
        prev->next = prev->next->next;
        _dos_print("winetd を常駐解除しました\r\n");
        _dos_mfree(data->memblock);
        return 0;
    }

    // 常駐処理

    // コマンドラインで指定されなかった設定のデフォルト値を設定する
    if (trap_number == NOSPEC_INT) {
        trap_number = DEFAULT_TRAP;
    }
    if (ifname == NOSPEC_STR) {
        ifname = DEFAULT_IFNAME;
    }
    if (dhcp_mode == NOSPEC_INT) {
        dhcp_mode = DEFAULT_DHCP;
    }
    if (hostname == NOSPEC_STR) {
        hostname = DEFAULT_HOSTNAME;
    }

    if (read_config(cfgfile) < 0) {
        return 1;
    }

    parse_cmdline(argc, argv);  // 設定をコマンドライン引数で上書き

    _dos_super(0);

    struct dos_devheader *prev = find_devheader("/winet//");
    if (prev != NULL) {
        _dos_print("既に winetd が常駐しています\r\n");
        return 0;
    }
    if (find_tcpip() != NULL) {
        _dos_print("既に他のTCP/IPドライバが常駐しています\r\n");
        return 1;
    }

    const char *w5500_version = w5500_ini();

    if (w5500_version == NULL) {
        _dos_print("WiFi+PCM Pilederが接続されていません\r\n");
        return 1;
    } else {
        _dos_print("WiFi+PCM Pileder version: ");
        _dos_print(w5500_version);
        _dos_print("\r\n");
    }

    do_wifi_leave();

    init_etc_files();
    set_config();

    do_wifi_dhcpmode(dhcp_mode);

#if 0
    if (dhcp_mode) {
        _dos_print("ネットワーク設定をDHCPで取得しています...\r\n");
        dhcp_result = idhcp_request(opt_v, ifname);
        if (dhcp_result != NOERROR) {
            _dos_print("DHCPリースの取得に失敗しました\r\n");
        } else {
            _dos_print("DHCPリースの取得に成功しました\r\n");
        }
    }
#endif

    if (wifi_ssid[0] != '\0') {
        _dos_print("WiFiに接続しています...");

        if (set_ifenable(true) < 0) {
            _dos_print("接続に失敗しました\r\n");
        } else {
            _dos_print("接続しました\r\n");
            do_dns_add(ntohl(w5500_read_l(W5500_WDNSR, 0)));
            show_config(-1);
        }
    } else {
        _dos_print("SSIDが設定されていません\r\n");
    }

    if (trap_number < -1) {    // 未使用のtrap番号を探す
        for (trap_number = 0; trap_number < 8; trap_number++) {
            if ((int)_dos_intvcg(trap_number + 0x20) >= 0x01000000) {
                break;
            }
        }
        if (trap_number >= 8) {
            trap_number = -1;  // trapが空いていないので使用しない
        }
    }
    if (trap_number >= 0) {
        if ((int)_dos_intvcg(trap_number + 0x20) < 0x01000000) {
            _dos_print("指定されたtrap番号は既に使用されています\r\n");
            return 1;
        }
        extern int trap_entry(void);
        winetd_data.vectno = trap_number + 0x20;
        winetd_data.oldvect = _dos_intvcs(winetd_data.vectno, trap_entry);
    }
    PRINTF("winetd: using trap number %d\n", trap_number);

    winetd_data.memblock = _dos_getpdb();

    prev = find_devheader(NULL);
    prev->next = &devheader;

    _dos_print("winetd が常駐しました\r\n");

    // ヒープ領域の末尾までを常駐して終了する
    // (ヒープの後ろにあるスタック領域は常駐しない)
    extern char *tcpip_magic;
    extern char *_HEND;
    _dos_keeppr((int)_HEND - (int)&tcpip_magic, 0);
}
