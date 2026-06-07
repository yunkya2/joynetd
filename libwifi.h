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

#ifndef _LIBWIFI_H_
#define _LIBWIFI_H_

#include <stdint.h>
#include "w5500wifi.h"

//****************************************************************************
// Macros and definitions
//****************************************************************************

typedef struct wifi_scan_result {
    uint32_t _0[5];
    uint8_t bssid[6];   ///< access point mac address
    uint16_t _1[2];
    uint8_t ssid_len;   ///< length of wlan access point name
    uint8_t ssid[32];   ///< wlan access point name
    uint32_t _2[5];
    uint16_t channel;   ///< wifi channel
    uint16_t _3;
    uint8_t auth_mode;  ///< wifi auth mode \ref CYW43_AUTH_
    int16_t rssi;       ///< signal strength
} wifi_scan_result_t;

typedef struct wifi_winetd_config {
    int trap_number;
    char *ifname;
    char *ssid;
    char *password;
    int dhcp_mode;
    char *hostname;
} wifi_winetd_config_t;

struct route;
struct dns;

//****************************************************************************
// Public functions
//****************************************************************************

// wifi_init() - winetd.xが常駐していることを確認する
// in:  なし
// out: 0:成功 -1:失敗

int wifi_init(void);

// wifi_getrssi() - 現在のWiFi接続のRSSIをdBm単位で返す。接続されていない場合は-1を返す。
// in:  なし
// out: RSSI値 (dBm単位で正負が逆) 接続されていない場合は-1

int wifi_getrssi(void);

// wifi_getstat() - WiFiの接続状態を返す
// in:  なし
// out: 接続状態 (bit0:接続済み bit5:DHCPを使用しない bit6:APスキャン中 bit7:エラー発生)

int wifi_getstat(void);

// wifi_scan() - WiFiのアクセスポイントのスキャンを開始する
// in:  sockfd - ソケットファイルディスクリプタ
//               (スキャン結果はこのソケットの受信バッファに格納される)
// out: 0:成功 -1:失敗

int wifi_scan(int sockfd);

// wifi_scanresult() - wifi_scan()で開始したスキャンの結果を受け取る
// in:  sockfd - ソケットファイルディスクリプタ
//      buf    - 結果を格納するバッファ
//      len    - バッファのサイズ
// out: 0:スキャン結果なし >0:スキャン結果のサイズ -1:エラーまたはスキャン終了

int wifi_scanresult(int sockfd, void *buf, size_t len);

// wifi_join() - 指定したSSIDのWiFiに接続する
// in:  ssid     - 接続するWiFiのSSID
//      password - 接続するWiFiのパスワード
//      auth     - 接続するWiFiの認証方式 (-1: デフォルト)
// out: 0:成功

int wifi_join(char *ssid, char *password, uint32_t auth);

// wifi_leave() - WiFiから切断する
// in:  なし
// out: 0:成功

int wifi_leave(void);

// wifi_get_iface() - WiFi interfaceの情報を取得する
// in:  rt       - ルーティング情報を返すroute構造体へのポインタ
//      dns      - DNS情報を返すdns構造体へのポインタ
// out: iface *

iface *wifi_get_iface(struct route **rt, struct dns **dns);

// wifi_get_winetd_config() - winetd.xの設定を取得する
// in:  wifi_winetd_config_t *
// out: 0:成功

int wifi_get_winetd_config(wifi_winetd_config_t *config);

#endif /* _LIBWIFI_H_ */
