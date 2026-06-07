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
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>

#include "network.h"
#include "tcpipdrv.h"

#include "libwifi.h"
#include "winetdcmd.h"

//****************************************************************************
// Macros and definitions
//****************************************************************************

typedef long (*_ti_func) (long, void *);
extern _ti_func __sock_func;

_ti_func __sock_search_ti_entry (void);

#define check_sock_func() do { \
    if (!__sock_func) { \
        errno = ENOSYS; \
        return -1; \
    } \
} while (0)

//****************************************************************************
// Public functions
//****************************************************************************

// wifi_init() - winetd.xが常駐していることを確認する
// in:  なし
// out: 0:成功 -1:失敗

int wifi_init(void)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -1;
    }
    close(fd);

    // TBD wifiサービス利用可否確認

    return 0;
}

// wifi_getrssi() - 現在のWiFi接続のRSSIをdBm単位で返す。接続されていない場合は-1を返す。
// in:  なし
// out: RSSI値 (dBm単位で正負が逆) 接続されていない場合は-1

int wifi_getrssi(void)
{
    check_sock_func();
    return __sock_func(WTI_GETRSSI, NULL);
}

// wifi_getstat() - WiFiの接続状態を返す
// in:  なし
// out: 接続状態 (bit0:接続済み bit5:DHCPを使用しない bit6:APスキャン中 bit7:エラー発生)

int wifi_getstat(void)
{
    check_sock_func();
    return __sock_func(WTI_GETSTAT, NULL);
}

// wifi_scan() - WiFiのアクセスポイントのスキャンを開始する
// in:  sockfd - ソケットファイルディスクリプタ
//               (スキャン結果はこのソケットの受信バッファに格納される)
// out: 0:成功 -1:失敗

int wifi_scan(int sockfd)
{
    check_sock_func();
    return __sock_func(WTI_SCAN, (long *)sockfd);
}

// wifi_scanresult() - wifi_scan()で開始したスキャンの結果を受け取る
// in:  sockfd - ソケットファイルディスクリプタ
//      buf    - 結果を格納するバッファ
//      len    - バッファのサイズ
// out: 0:スキャン結果なし >0:スキャン結果のサイズ -1:エラーまたはスキャン終了

int wifi_scanresult(int sockfd, void *buf, size_t len)
{
    check_sock_func();

    long arg[3];
    arg[0] = sockfd;
    arg[1] = (long)buf;
    arg[2] = len;

    return __sock_func(WTI_SCANRESULT, arg);
}

// wifi_join() - 指定したSSIDのWiFiに接続する
// in:  ssid     - 接続するWiFiのSSID
//      password - 接続するWiFiのパスワード
//      auth     - 接続するWiFiの認証方式 (-1: デフォルト)
// out: 0:成功

int wifi_join(char *ssid, char *password, uint32_t auth)
{
    check_sock_func();

    long arg[3];
    arg[0] = (long)ssid;
    arg[1] = (long)password;
    arg[2] = auth;

    return __sock_func(WTI_JOIN, arg);
}

// wifi_leave() - WiFiから切断する
// in:  なし
// out: 0:成功

int wifi_leave(void)
{
    check_sock_func();
    return __sock_func(WTI_LEAVE, 0);
}

// wifi_get_iface() - WiFi interfaceの情報を取得する
// in:  なし
// out: iface *

iface *wifi_get_iface(void)
{
    return (iface *)__sock_func(_TI_get_iface_list, NULL);
}
