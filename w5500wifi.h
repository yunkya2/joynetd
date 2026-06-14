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

#ifndef _W5500WIFI_H_
#define _W5500WIFI_H_

//****************************************************************************
// Additional WiFi Register Definitions
//****************************************************************************

// Socket n Mode bits (W5500_Sn_MR)
#define W5500_Sn_MR_TCPTLS      0x09

#define W5500_WIDENT        0x0040  // WiFi System Identifier
#define W5500_WVERSION      0x0048  // WiFi System Version
#define W5500_WCR           0x0050  // WiFi Control
#define W5500_WSR           0x0051  // WiFi Status
#define W5500_WRSSI         0x0052  // WiFi RSSI
#define W5500_WAUTH         0x0054  // WiFi Authentication Type
#define W5500_WDNSR         0x0058  // WiFi DNS Address

#define W5500_WHOSTNAME     0x0060  // WiFi DHCP Hostname
#define W5500_WSSID         0x0080  // WiFi SSID
#define W5500_WPASSWORD     0x00a0  // WiFi Password

#define W5500_WSTATSND      0x0060  // Status sndcnt
#define W5500_WSTATRCV      0x0064  // Status rcvcnt
#define W5500_WSTATERR      0x0068  // Status errcnt
#define W5500_WSTATDRP      0x006c  // Status drpcnt

#define W5500_WARPTBL       0x0060  // ARP Table (4+6 bytes x 16 entries)

#define W5500_WARPIP        0x0060  // ARP IP Address
#define W5500_WARPMAC       0x0064  // ARP MAC Address

// WiFi Control Register Command code (W5500_WCR)
#define W5500_WCR_GETSTAT       0x80    // WiFiの状態を取得する
#define W5500_WCR_GETRSSI       0x81    // WiFiのRSSIを取得する
#define W5500_WCR_SCAN          0x82    // WiFiのAPのscanを開始する
#define W5500_WCR_JOIN          0x83    // WiFiネットワークに参加する
#define W5500_WCR_LEAVE         0x84    // WiFiネットワークから離脱する
#define W5500_WCR_DHCPON        0x85    // WiFi接続時のDHCPクライアント機能を有効にする
#define W5500_WCR_DHCPOFF       0x86    // WiFi接続時のDHCPクライアント機能を無効にする
#define W5500_WCR_GETNETSTAT    0x87    // ネットワーク統計情報を取得する
#define W5500_WCR_GETARPTABLE   0x88    // ARPテーブルの内容を取得する
#define W5500_WCR_REQARP        0x89    // ARP要求を送信する
#define W5500_WCR_ADDARP        0x8a    // ARPテーブルにエントリを追加する
#define W5500_WCR_DELARP        0x8b    // ARPテーブルからエントリを削除する

// WiFi Status Register bit definitions (W5500_WSR)
#define W5500_WSR_JOINED        0x01    // WiFiネットワークに参加中
#define W5500_WSR_SCANNING      0x02    // WiFiのscan処理中
#define W5500_WSR_NODHCP        0x04    // WiFi接続時のDCPクライアント機能を使用しない
#define W5500_WSR_NONET         0x20    // 指定したSSIDのアクセスポイントが見つからない
#define W5500_WSR_BADAUTH       0x40    // アクセスポイントの認証エラー
#define W5500_WSR_ERR           0x80    // コマンド処理中にエラーが発生した

#endif /* _W5500WIFI_H_ */
