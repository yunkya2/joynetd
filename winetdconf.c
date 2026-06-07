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
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/endian.h>

#include <x68k/dos.h>
#include <x68k/iocs.h>

#include "network.h"

#include "wificmd.h"
#include "libwifi.h"

//****************************************************************************
// Macros and definitions
//****************************************************************************

#define WIFI_JOIN_TIMEOUT   30000   // WiFi接続のタイムアウト時間（ms）

// TBD
#define NOSPEC_INT      -99999
#define NOSPEC_STR      NULL

#define DEFAULT_TRAP        -2
#define DEFAULT_IFNAME      "en0"
#define DEFAULT_SSIDPASS    NULL
#define DEFAULT_DHCP        1
#define DEFAULT_HOSTNAME    NULL

//****************************************************************************
// Global variables
//****************************************************************************

extern const char winetd_cfg_tmpl[];

__asm__ (
    ".section .rodata\n"
    "winetd_cfg_tmpl:\n"
    ".incbin \"winetd.cfg.tmpl.txt\"\n"
    ".byte 0\n"
    ".previous\n"
);

//****************************************************************************
// Private functions
//****************************************************************************

static char *readpass(const char *prompt)
{
    static char password[64 + 1];
    char *p = password;
    bool echo = false;

    printf("%s", prompt);
    fflush(stdout);
    while (1) {
        int ch = _iocs_b_keyinp() & 0xff;
        switch (ch) {
        case '\0':
            continue;
        case '\r':
        case '\n':
            *p = '\0';
            printf("\n");
            return password;
        case '\b':
            if (p > password) {
                p--;
                printf("\b \b");
                fflush(stdout);
            }
            break;
        case '\x03':  // Ctrl-C
        case '\x1b':  // ESC
            printf("\n");
            return NULL;
        case '\x17':  // Ctrl-W
        case '\x15':  // Ctrl-U
            for (int i = 0; i < p - password; i++) {
                printf("\b \b");
            }
            fflush(stdout);
            p = password;
            break;
        case '\x14':  // Ctrl-T
            echo = !echo;
            for (int i = 0; i < p - password; i++) {
                printf("\b \b");
            }
            for (char *q = password; q < p; q++) {
                putchar(echo ? *q : '*');
            }
            fflush(stdout);
            break;
        default:
            if (p - password < sizeof(password) - 1 &&
                ch >= 32 && ch <= 126) {
                *p++ = (char)ch;
                putchar(echo ? ch : '*');
                fflush(stdout);
            }
            break;
        }
    }
}

static char *mactoa(const uint8_t *mac)
{
    static char buf[18];
    sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return buf;
}

static char *get_default_cfgfile(char *buf)
{
    // Use default config file path based on executable path
    struct dos_psp *psp = _dos_getpdb();
    strcpy(buf, psp->exe_path);
    strcat(buf, "winetd.cfg");
    return buf;
}

static int create_config(const char *cfgfile)
{
    char cfgdefault[256];
    FILE *fp;
    wifi_winetd_config_t config;

    if (cfgfile == NULL || *cfgfile == '\0') {
        cfgfile = get_default_cfgfile(cfgdefault);
    }

    if ((fp = fopen(cfgfile, "r")) != NULL) {
        printf("設定ファイル %s は既に存在します\n", cfgfile);
        fclose(fp);
        return -1;
    }

    wifi_get_winetd_config(&config);

    if ((fp = fopen(cfgfile, "w")) == NULL) {
        printf("設定ファイル %s の生成に失敗しました\n", cfgfile);
        return -1;
        } else {
        fprintf(fp, winetd_cfg_tmpl,
            config.trap_number == NOSPEC_INT ? ";" : "",
            config.trap_number == NOSPEC_INT ? DEFAULT_TRAP : config.trap_number,
            config.ifname == NOSPEC_STR ? ";" : "",
            config.ifname == NOSPEC_STR ? DEFAULT_IFNAME : config.ifname,
            config.ssid == NOSPEC_STR ? ";" : "",
            config.ssid == NOSPEC_STR ? "" : config.ssid,
            config.password == NOSPEC_STR ? ";" : "",
            config.password == NOSPEC_STR ? "" : config.password,
            config.dhcp_mode == NOSPEC_INT ? ";" : "",
            config.dhcp_mode == NOSPEC_INT ? 1 : config.dhcp_mode,
            config.hostname == NOSPEC_STR ? ";" : "",
            config.hostname == NOSPEC_STR ? "" : config.hostname
        );
        fclose(fp);
    }
    printf("設定ファイル %s を生成しました\n", cfgfile);
    return 0;
}

//****************************************************************************
// Command functions
//****************************************************************************

static int do_show_stat(void)
{
    char buf[80];
    struct route *rt;
    struct dns *dns;

    iface *wif = wifi_get_iface(&rt, &dns);

    printf("Interface : %s\t\t\tMAC addr: %s\n", wif->name, mactoa((uint8_t *)wif->my_hw_addr));
    printf("Status  : %s\n", wif->flag & IFACE_UP ? "UP" : "DOWN");

    if (wif->flag & IFACE_UP) {
        printf("RSSI    : %ddBm\n", -wifi_getrssi());

        sprintf(buf, "IP addr : %s", inet_ntoa(*(struct in_addr *)&wif->my_ip_addr));
        printf("%-32s", buf);
        sprintf(buf, "Netmask : %s", inet_ntoa(*(struct in_addr *)&wif->net_mask));
        printf("%-32s", buf);
        printf("\n");

        sprintf(buf, "Gateway : %s", inet_ntoa(*(struct in_addr *)&rt->gateway));
        printf("%-32s", buf);
        sprintf(buf, "DNS     : %s", inet_ntoa(*(struct in_addr *)&dns->address));
        printf("%-32s", buf);
        printf("\n");
    }

    return 0;
}

static int do_wifi_scan(int argc, char **argv, char ***out_ssid_list, int *num_ssid, int *top_ssid)
{
    if (top_ssid != NULL) {
        *top_ssid = 0;
    }
    if (num_ssid != NULL) {
        *num_ssid = 0;
    }
    int max_rssi = -128;

    bool verbose = false;
    if (argc > 0 && strcmp(argv[0], "-v") == 0) {
        verbose = true;
    }

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        printf("socket error\n");
        return -1;
    }

    wifi_scan(fd);

    wifi_scan_result_t result;
    int res;
    int count = 0;
    while ((res = wifi_scanresult(fd, &result, sizeof(result))) >= 0) {
        if (res > 0) {
            count++;
            int rssi = (int16_t)le16toh(result.rssi);

            if (max_rssi < rssi) {
                max_rssi = rssi;
                if (top_ssid != NULL) {
                    *top_ssid = count;
                }
            }

            if (verbose) {
                printf("(%d) SSID:%s BSSID:%02x:%02x:%02x:%02x:%02x:%02x Channel:%d Auth:%d RSSI:%ddBm\n",
                       count,
                       result.ssid,
                       result.bssid[0], result.bssid[1], result.bssid[2],
                       result.bssid[3], result.bssid[4], result.bssid[5],
                       le16toh(result.channel),
                       result.auth_mode, 
                       (int16_t)le16toh(result.rssi));
            } else {
                printf("(%d) SSID:%s RSSI:%ddBm\n",
                       count,
                       result.ssid,
                       (int16_t)le16toh(result.rssi));
            }
            if (out_ssid_list != NULL) {
                *out_ssid_list = realloc(*out_ssid_list, sizeof(char *) * (count + 1));
                (*out_ssid_list)[count - 1] = strdup((char *)result.ssid);
                (*out_ssid_list)[count] = NULL;
            }
        }
        usleep(100 * 1000);
    }

    if (num_ssid != NULL) {
        *num_ssid = count;
    }

    close(fd);
    return 0;
}

static int do_wifi_join(int argc, char **argv)
{
    bool nopasswd = false;
    bool createconfig = false;
    char *ssid = NULL;
    char *passwd = NULL;
    char *confpath = NULL;
    char **ssid_list = NULL;
    char **verbose_opt = NULL;
    int res;

    for (int i = 0; i < argc; i++) {
        if (argv[i][0] == '-') {
            switch (argv[i][1]) {
            case 'N':
                nopasswd = true;
                break;
            case 'c':
                createconfig = true;
                break;
            case 'v':
                verbose_opt = &argv[i];
                break;
            case 'f':
                confpath = &argv[i][2];
                break;
            default:
                printf("Unknown option: %s\n", argv[i]);
                return -1;
            }
        } else if (ssid == NULL) {
            ssid = argv[i];
        } else if (passwd == NULL) {
            passwd = argv[i];
        }
    }

    if (ssid == NULL) {
        int top_ssid = 0;
        int num_ssid = 0;

        printf("アクセスポイントをスキャンします...\n");
        res = do_wifi_scan(verbose_opt ? 1 : 0, verbose_opt, &ssid_list,
                           &num_ssid, &top_ssid);
        if (res < 0) {
            return -1;
        }
        if (num_ssid == 0) {
            printf("アクセスポイントが見つかりません\n");
            return -1;
        } else if (num_ssid == 1) {
            ssid = ssid_list[0];
        } else {
            printf("SSIDを 1-%d の値で選択してください (default:%d): ", num_ssid, top_ssid);
            char input[16];
            fgets(input, sizeof(input), stdin);
            int choice = atoi(input);
            if (choice == 0) {
                choice = top_ssid;
            } else if (choice < 1 || choice > num_ssid) {
                printf("SSIDの指定が無効です\n");
                return -1;
            }
            ssid = ssid_list[choice - 1];
        }

        if (!nopasswd) {
            printf("%s のパスワードを入力: ", ssid);
            passwd = readpass("");
            if (passwd == NULL) {
                return -1;
            }
        } else {
            passwd = "";
        }

#if 0
            for (ssidp = ssid_list; *ssidp != NULL; ssidp++) {
                free((void *)*ssidp);
            }
            free(ssid_list);
#endif
    }

    printf("アクセスポイント %s に接続します...\n", ssid);

//    printf("SSID: %s password: %s\n", ssid, passwd);

//    wifi_join(WIFI_SSID, WIFI_PASSWORD, -1);
    wifi_join(ssid, passwd, -1);
    int t = 0;
    int stat = 0;
    while (t < WIFI_JOIN_TIMEOUT) {
        stat = wifi_getstat();
        if ((stat & W5500_WSR_JOINED) != 0) {
            break;
        }
        if ((stat & W5500_WSR_ERR) != 0) {
            break;
        }
        usleep(500 * 1000);
        t += 500;
    }
    if (stat & W5500_WSR_JOINED) {
        printf("WiFiに接続しました\n");
        do_show_stat();
        if (createconfig) {
            if (create_config(confpath) < 0) {
                return -1;
            }
        }
    } else if (stat & W5500_WSR_ERR) {
        if (stat & W5500_WSR_NONET) {
            printf("アクセスポイントが見つかりません\n");
        } else if (stat & W5500_WSR_BADAUTH) {
            printf("パスワードが間違っています\n");
        } else {
            printf("WiFiへの接続に失敗しました\n");
        }
    } else if (t >= WIFI_JOIN_TIMEOUT) {
        printf("WiFiへの接続にタイムアウトしました\n");
    }
    return 0;
}

static int do_wifi_leave(void)
{
    wifi_leave();
    return 0;
}

static void help(void)
{
    printf(
        "winetdconf version " GIT_REPO_VERSION "\n\n"
        "使用法: winetdconf                                      - 現在の接続状態の表示\n"
        "        winetdconf scan                                 - アクセスポイントのスキャン\n"
        "        winetdconf connect [オプション] [SSID] [passwd] - アクセスポイントへ接続\n"
        "        winetdconf disconnect                           - アクセスポインタから接続断\n"
        "オプション:\n"
        "    -c               - 設定ファイルを生成する\n"
        "    -f<config file>  - 設定ファイルのパスを指定する\n"
        "    -N               - パスワードをユーザに問い合わせない\n"
    );
    exit(1);
}

//****************************************************************************
// Program entry
//****************************************************************************

int main(int argc, char **argv)
{
    int res = 0;

    if (wifi_init() < 0) {
        printf("winetdが常駐していません\n");
        return 1;
    }

    if (argc <= 1 || strcmp(argv[1], "stat") == 0) {
        res = do_show_stat();
    } else if (strcmp(argv[1], "scan") == 0) {
        res = do_wifi_scan(argc - 2, &argv[2], NULL, NULL, NULL);
    } else if (strcmp(argv[1], "connect") == 0 || strcmp(argv[1], "join") == 0) {
        res = do_wifi_join(argc - 2, &argv[2]);
    } else if (strcmp(argv[1], "disconnect") == 0 || strcmp(argv[1], "leave") == 0) {
        res = do_wifi_leave();
    } else {
        help();
    }

    return res;
}
