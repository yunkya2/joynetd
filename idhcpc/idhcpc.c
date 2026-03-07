/* SPDX-License-Identifier: 0BSD */

#include "idhcpc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "dhcp.h"
#include "mynetwork.h"
#include "nwsub.h"

typedef struct {
  int s; /* 送信用 UDP ソケット識別子 */
  int r; /* 受信用 UDP ソケット識別子 */
} udpsockets;

static int initialize(const char *);
static udpsockets create_sockets(void);
static dherrno prepare_iface(const char *, iface **, dhcp_hw_addr *);
static dherrno prepare_discover(iface *, udpsockets *, struct sockaddr_in *);
static dherrno discover_dhcp_server(const int, const dhcp_hw_addr *,
                                  const udpsockets *, unsigned long *,
                                  unsigned long *, struct sockaddr_in *);
static dherrno request_to_dhcp_server(const int, const dhcp_hw_addr *,
                                    const udpsockets *, const unsigned long,
                                    const unsigned long, struct sockaddr_in *,
                                    iface *);
static dherrno send_and_receive(const int, const dhcp_hw_addr *,
                              const udpsockets *, const unsigned long,
                              const unsigned long, const int, dhcp_msg *,
                              struct sockaddr_in *);
static dherrno fill_idhcpcinfo(unsigned long *, char *, dhcp_msg *);
static dherrno release_config(const int, iface *, dhcp_hw_addr *, udpsockets *);
static void close_sockets(udpsockets *);
static void iface_when_discover(iface *);
static void iface_when_request(const unsigned long, const char *, iface *);
static void iface_when_release(iface *);
static void fill_dhcp_hw_addr(const iface *, dhcp_hw_addr *);
static void msleep(const int);

idhcpcinfo *g_pidhcpcinfo; /* initialize() で初期化される */
idhcpcinfo g_idhcpcinfo = {0};

/**
 * @brief 常駐処理
 * @param verbose 非 0 でバーボーズモード
 * @param ifname インタフェース名
 * @return エラーコード
 */
dherrno idhcp_request(const int verbose, const char *ifname) {
  dherrno err;

  if (initialize(ifname)) {
    err = ERR_ALREADYKEPT;
  } else {
    iface *piface;
    dhcp_hw_addr hwaddr;

    if ((err = prepare_iface(g_pidhcpcinfo->ifname, &piface, &hwaddr)) ==
        NOERROR) {
      udpsockets sockets = create_sockets();
      struct sockaddr_in inaddr_s;
      unsigned long me;
      unsigned long server;

      g_pidhcpcinfo->startat = time(NULL); /* 起動日時 */

      (void)(
      (!0) &&
          ((err = prepare_discover(piface, &sockets, &inaddr_s)) == NOERROR) &&
          ((err = discover_dhcp_server(verbose, &hwaddr, &sockets, &me, &server,
                                       &inaddr_s)) == NOERROR) &&
          ((err = request_to_dhcp_server(verbose, &hwaddr, &sockets, me, server,
                                         &inaddr_s, piface)) == NOERROR));
      close_sockets(&sockets);
    }
  }
  return err;
}

/**
 * @brief 常駐解除処理
 * @param verbose 非 0 でバーボーズモード
 * @param ifname インタフェース名
 * @return エラーコード
 */
dherrno idhcp_release(const int verbose, const char *ifname) {
  dherrno err;

  if (!initialize(ifname)) {
    err = ERR_NOTKEPT;
  } else {
    iface *piface;
    dhcp_hw_addr hwaddr;

    if (prepare_iface(g_pidhcpcinfo->ifname, &piface, &hwaddr) != NOERROR) {
      err = NOERROR; /* DHCPRELEASE の発行は行わず、常駐解除のみ */
    } else {
      udpsockets sockets = create_sockets();

      if ((err = release_config(verbose, piface, &hwaddr, &sockets)) !=
          NOERROR) {
        return err;
      }
      close_sockets(&sockets);
    }
  }
  return err;
}

/**
 * @brief 残りリース期間を返す
 * @param ifname インタフェース名
 * @param force 非 0 で強制的にリース期間を取得する (常駐時専用)
 * @param[out] pleasetime 残りリース期間格納域. 無期限の場合は -1 が格納される
 * @return エラーコード
 */
dherrno idhcp_get_remaining(const char *ifname, const int force, int *pleasetime) {
  dherrno err;

  if (!initialize(ifname) && !force) {
    err = ERR_NOTKEPT;
  } else {
    unsigned long leasetime = g_pidhcpcinfo->leasetime;
    *pleasetime = leasetime == 0xffffffff
                      ? -1
                      : (int)leasetime -
                            (int)difftime(time(NULL), g_pidhcpcinfo->dhcpackat);
    err = NOERROR;
  }
  return err;
}

/**
 * @brief 初期化処理
 *   * 常駐判定
 *   * g_pidhcpcinfo の初期化
 * @param ifname インタフェース名
 * @return 0: 常駐していない
 */
static int initialize(const char *ifname) {
  static int initialized = 0;
  static int kept = 0;

  if (!initialized) {
    extern idhcpcinfo g_idhcpcinfo; /* idhcpc ワーク */

    /* インタフェース名を現プロセスのワークへコピーしておく */
    strncpy(g_idhcpcinfo.ifname, ifname, sizeof(g_idhcpcinfo.ifname));
    g_pidhcpcinfo = &g_idhcpcinfo;
    initialized = 1;
  }
  return kept;
}

/**
 * @brief udpsockets 構造体の初期値を返す
 * @return
 */
static udpsockets create_sockets(void) {
  udpsockets ret;
  ret.s = -1;
  ret.r = -1;
  return ret;
}

/**
 * @brief インタフェースとハードウェアアドレス情報を取得する
 * @param ifname インタフェース名
 * @param ppiface iface ポインタ格納域
 * @param phwaddr ハードウェアアドレス情報格納域
 * @return エラーコード
 */
static dherrno prepare_iface(const char *ifname, iface **ppiface,
                           dhcp_hw_addr *phwaddr) {
  {
    iface *p;

    if ((p = do_get_new_iface((char *)ifname)) == NULL) {
      return ERR_NOIFACE;
    }
    *ppiface = p;
  }
  fill_dhcp_hw_addr(*ppiface, phwaddr);
  return NOERROR;
}

/**
 * @brief DHCPDISCOVER 発行前の前処理
 * @param piface インタフェース
 * @param[out] psockets UDP ソケット格納域
 * @param[out] pinaddr_s 送信用ソケット情報格納域
 * @return エラーコード
 */
static dherrno prepare_discover(iface *piface, udpsockets *psockets,
                              struct sockaddr_in *pinaddr_s) {
  /* INIT 時のネットワークインタフェース設定 */
  iface_when_discover(piface);

  /* 送信用 UDP ソケット作成 */
  if ((psockets->s = create_udp_socket()) < 0) {
    return ERR_SOCKET;
  }
  /* 受信用 UDP ソケット作成 */
  if ((psockets->r = create_udp_socket()) < 0) {
    return ERR_SOCKET;
  }
  /* DHCP サーバポート (67) に接続 */
  if (connect2(psockets->s, DHCP_SERVER_PORT, DHCP_LIMITEDBCAST, pinaddr_s) <
      0) {
    return ERR_CONNECT;
  }
  /* DHCPクライアントポート (68) に接続 */
  if (bind2(psockets->r, DHCP_CLIENT_PORT, 0) < 0) {
    return ERR_BIND;
  }

  return NOERROR;
}

/**
 * @brief DHCPDISCOVER を発行して DHCPOFFER を受信する
 * @param verbose 非 0 でバーボーズモード
 * @param phwaddr ハードウェアアドレス情報
 * @param psockets UDP ソケット
 * @param[out] pme 要求 IP アドレス格納域
 * @param[out] pserver DHCP サーバ IP アドレス格納域
 * @param[out] pinaddr_s 送信用ソケット情報格納域
 * @return エラーコード
 */
static dherrno discover_dhcp_server(const int verbose,
                                  const dhcp_hw_addr *phwaddr,
                                  const udpsockets *psockets,
                                  unsigned long *pme, unsigned long *pserver,
                                  struct sockaddr_in *pinaddr_s) {
  dherrno err;
  dhcp_msg msg;

  if ((err = send_and_receive(verbose, phwaddr, psockets, 0, 0, DHCPDISCOVER,
                              &msg, pinaddr_s)) != NOERROR) {
    return err;
  }

  if ((*pme = dhcp_get_yiaddr(&msg)) == 0) { /* 要求 IP アドレス */
    return ERR_NOYIADDR;
  }
  if (dhcp_get_serverid(&msg, pserver) == NULL) { /* サーバ ID */
    return ERR_NOSID;
  }

  return NOERROR;
}

/**
 * @brief DHCPREQUEST を発行して DHCPACK を受信する
 * @param verbose 非 0 でバーボーズモード
 * @param phwaddr ハードウェアアドレス情報
 * @param psockets UDP ソケット
 * @param me 要求 IP アドレス
 * @param server DHCP サーバ IP アドレス
 * @param[out] pdomain ドメイン名格納域
 * @param[out] pinaddr_s 送信用ソケット情報格納域
 * @param[out] piface インタフェース
 * @return エラーコード
 */
static dherrno request_to_dhcp_server(
    const int verbose, const dhcp_hw_addr *phwaddr, const udpsockets *psockets,
    const unsigned long me, const unsigned long server,
    struct sockaddr_in *pinaddr_s, iface *piface) {
  dherrno err;
  dhcp_msg msg;
  unsigned long subnetmask;
  char domainname[256];

  if ((err = send_and_receive(verbose, phwaddr, psockets, me, server,
                              DHCPREQUEST, &msg, pinaddr_s)) != NOERROR) {
    return err;
  }

  g_pidhcpcinfo->dhcpackat = time(NULL); /* DHCPACK 受信日時 */

  /* 受信結果から要求 IP アドレス / サーバIDその他を抜き出す */
  if ((err = fill_idhcpcinfo(&subnetmask, domainname, &msg)) != NOERROR) {
    return err;
  }

  /* REQUEST 時のネットワークインタフェース設定 */
  iface_when_request(subnetmask, domainname, piface);

  return NOERROR;
}

/**
 * @brief DHCP メッセージ送信 / 受信処理
 * @param verbose 非 0 でバーボーズモード
 * @param phwaddr ハードウェアアドレス情報
 * @param psockets UDP ソケット
 * @param me 要求 IP アドレス
 * @param server DHCP サーバ IP アドレス
 * @param msgtype_s DHCP メッセージタイプ (DHCPDISCOVER or DHCPREQUEST)
 * @param[out] prmsg DHCP メッセージバッファ格納域
 * @param[out] pinaddr_s 送信用ソケット情報格納域
 * @return エラーコード
 */
static dherrno send_and_receive(const int verbose, const dhcp_hw_addr *phwaddr,
                              const udpsockets *psockets,
                              const unsigned long me,
                              const unsigned long server, const int msgtype_s,
                              dhcp_msg *prmsg, struct sockaddr_in *pinaddr_s) {
  dhcp_msg smsg; /* DHCP メッセージバッファ (送信用) */
  struct sockaddr_in inaddr_r;
  unsigned char msgtype_r; /* 受信データのメッセージタイプ */
  unsigned long xid;       /* トランザクション ID */
  int wait = 4;            /* タイムアウト秒数 */
  int timeout = 1;         /* タイムアウトフラグ */
  int i;                   /* ループカウンタ */

  /* 最大4回再送 (計5回送信) */
  for (i = 0; i < 5; i++) {
    if (verbose) {
      if (i > 0) printf("リトライします (%d 回目) ...\n", i);
      fflush(stdout);
    }
    {                       /* メッセージ送信処理 */
      unsigned short secs = /* 起動からの経過時間 (秒) */
          (unsigned short)difftime(time(NULL), g_pidhcpcinfo->startat);

      xid = random(); /* トランザクション ID 設定 */
      switch (msgtype_s) {
        case DHCPDISCOVER:
          dhcp_make_dhcpdiscover(phwaddr, xid, secs, &smsg);
          break;
        case DHCPREQUEST:
          dhcp_make_dhcprequest(phwaddr, me, server, xid, secs, &smsg);
          break;
        default:
          break;
      }
    }
    if (verbose) {
      dhcp_print(&smsg);
      printf("DHCP サーバポート (67) へ送信中 ...\n");
      fflush(stdout);
    }
    do_sendto(psockets->s, (char *)&smsg, sizeof(smsg), 0, (struct sockaddr *)pinaddr_s,
           sizeof(*pinaddr_s));
    /* while (socklen(g_sock_s, 1)) ;*/ /* 送信完了待ち */

    /* メッセージ受信処理 */
    if (verbose) {
      printf(
          "DHCP クライアントポート (68) から受信中. "
          "約 %d 秒後にタイムアウトします ...",
          wait);
      fflush(stdout);
    }
    {
      /* 4, 8, 16, 32, 64 ± 1 秒くらい */
      int rest = (wait * 100 + rand() % 199 - 99) * 10;
      int interval = 500;

      do {
        if (do_socklen(psockets->r, 0) == 0) {
          if (verbose) { /* インチキプログレス表示 */
            printf(".");
            fflush(stdout);
          }
          if (rest < interval) {
            interval = rest;
          }
          msleep(interval); /* 少し待つ */
          continue;
        }
        {
          socklen_t len = sizeof(inaddr_r);
          do_recvfrom(psockets->r, (char *)prmsg, sizeof(*prmsg), 0,
                   (struct sockaddr *)&inaddr_r, &len);
        }
        if (!dhcp_isreply(prmsg, xid, &msgtype_r)) continue;
        if (msgtype_s == DHCPDISCOVER) {
          if (msgtype_r == DHCPOFFER) {
            timeout = 0;
            break; /* 受信完了 */
          }
        } else if (msgtype_s == DHCPREQUEST) {
          if ((msgtype_r == DHCPACK) || (msgtype_r == DHCPNAK)) {
            timeout = 0;
            break; /* 受信完了 */
          }
        }
      } while ((rest -= interval) > 0);
      if (!timeout) {
        if (verbose) {
          printf(" done.\n");
          dhcp_print(prmsg);
        }
        break; /* 受信完了でループ脱出 */
      }
      if (verbose) printf(" タイムアウトです.\n");
      wait <<= 1;
    }
  }

  if (timeout) return ERR_TIMEOUT; /* タイムアウト */

  if (msgtype_s == DHCPREQUEST) {
    if (msgtype_r == DHCPNAK) return ERR_NAK;
  }

  return NOERROR;
}

/**
 * @brief コンフィギュレーション情報をセーブする
 * @param[out] pmask サブネットマスク格納域
 * @param[out] pdomain ドメイン名格納域
 * @param[out] pmsg DHCPOFFER または DHCPACK で受信した DHCP メッセージ
 * @return エラーコード
 */
static dherrno fill_idhcpcinfo(unsigned long *pmask, char *pdomain,
                             dhcp_msg *pmsg) {
  if ((g_pidhcpcinfo->me = dhcp_get_yiaddr(pmsg)) == 0) { /* 要求 IP アドレス */
    return ERR_NOYIADDR;
  }
  if (dhcp_get_serverid(pmsg, &g_pidhcpcinfo->server) == NULL) { /* サーバ ID */
    return ERR_NOSID;
  }
  g_pidhcpcinfo->gateway = 0; /* デフォルトゲートウェイ */
  dhcp_get_defroute(pmsg, &g_pidhcpcinfo->gateway);
  dhcp_get_dns(pmsg, g_pidhcpcinfo->dns); /* ドメインサーバ (配列) */
  if (dhcp_get_leasetime(pmsg, &g_pidhcpcinfo->leasetime) ==
      NULL) { /* リース期間 */
    /* リース期間が渡されなかった！？ */
    return ERR_NOLEASETIME;
  }
  g_pidhcpcinfo->renewtime = 0; /* 更新時間 */
  dhcp_get_renewtime(pmsg, &g_pidhcpcinfo->renewtime);
  if (g_pidhcpcinfo->renewtime == 0) {
    g_pidhcpcinfo->renewtime = g_pidhcpcinfo->leasetime / 2;
  }
  g_pidhcpcinfo->rebindtime = 0; /* 再結合時間 */
  dhcp_get_rebindtime(pmsg, &g_pidhcpcinfo->rebindtime);
  if (g_pidhcpcinfo->rebindtime == 0) {
    g_pidhcpcinfo->rebindtime = g_pidhcpcinfo->leasetime * 857 / 1000;
  }
  *pmask = 0; /* サブネットマスク */
  dhcp_get_subnetmask(pmsg, pmask);
  dhcp_get_domainname(pmsg, pdomain); /* ドメイン名 */

  return NOERROR;
}

/**
 * @brief DHCPRELEASE を発行してネットワークインタフェースを初期化する
 * @param verbose 非 0 でバーボーズモード
 * @param piface インタフェース
 * @param phwaddr ハードウェアアドレス情報
 * @param[out] psockets UDP ソケット
 * @return エラーコード
 */
static dherrno release_config(const int verbose, iface *piface,
                            dhcp_hw_addr *phwaddr, udpsockets *psockets) {
  dhcp_msg msg; /* DHCP メッセージバッファ */
  struct sockaddr_in inaddr_s;

  /* 送信用 UDP ソケット作成 */
  if ((psockets->s = create_udp_socket()) < 0) {
    return ERR_SOCKET;
  }
  /* DHCP サーバポート (67) に接続 */
  if (connect2(psockets->s, DHCP_SERVER_PORT, g_pidhcpcinfo->server,
               &inaddr_s) < 0) {
    return ERR_CONNECT;
  }

  /* DHCPRELEASE メッセージ送信処理 */
  dhcp_make_dhcprelease(phwaddr, g_pidhcpcinfo->me, g_pidhcpcinfo->server,
                        random(), &msg);
  if (verbose) {
    dhcp_print(&msg);
    printf("DHCP サーバポート (67) へ送信中 ...\n");
    fflush(stdout);
  }
  do_sendto(psockets->s, (char *)&msg, sizeof(msg), 0, (struct sockaddr *)&inaddr_s,
         sizeof(inaddr_s));
  msleep(500); /* 少し待つ */
  iface_when_release(piface);

  return NOERROR;
}

/**
 * @brief オープン済みのソケットをすべてクローズする
 * @param[out] psockets UDP ソケット
 */
static void close_sockets(udpsockets *psockets) {
  if (psockets->s != -1) {
    do_close(psockets->s);
    psockets->s = -1;
  }
  if (psockets->r != -1) {
    do_close(psockets->r);
    psockets->r = -1;
  }
}

/**
 * @brief DHCPDISCOVER 時のネットワークインタフェース設定
 * @param piface インタフェース
 */
static void iface_when_discover(iface *piface) {
  piface->my_ip_addr = 0;
  piface->broad_cast = DHCP_LIMITEDBCAST;
  piface->flag |= IFACE_UP | IFACE_BROAD;
  do_link_new_iface(piface);
}

/**
 * @brief DHCPREQUEST 時のネットワークインタフェース設定
 * @param subnetmask サブネットマスク
 * @param domainname ドメイン名
 * @param[out] piface インタフェース
 */
static void iface_when_request(const unsigned long subnetmask,
                               const char *domainname, iface *piface) {
  piface->my_ip_addr = g_pidhcpcinfo->me;
  piface->net_mask = subnetmask;
  piface->broad_cast = (piface->my_ip_addr & subnetmask) | ~subnetmask;
  piface->flag |= IFACE_UP;
  do_link_new_iface(piface);
  {
    unsigned long *p = g_pidhcpcinfo->dns, addr;

    while ((addr = *p++)) {
      do_dns_add((long)addr);
    }
  }
  if (strcmp(domainname, "")) {
    do_set_domain_name((char *)domainname);
  }
  if (g_pidhcpcinfo->gateway) {
    route *def;
    do_rt_top(&def);
    def->gateway = (long)g_pidhcpcinfo->gateway;
  }
  /* msleep(1500);*/
}

/**
 * @brief DHCPRELEASE 発行後のネットワークインタフェースの辻褄合わせ
 * @param ifname インタフェース名
 */
static void iface_when_release(iface *piface) {
  {
    unsigned long *p = g_pidhcpcinfo->dns, addr;

    while ((addr = *p++)) {
      do_dns_drop((long)addr);
    }
  }
  do_set_domain_name("");
  if (g_pidhcpcinfo->gateway) {
    route *def;
    do_rt_top(&def);
    def->gateway = 0;
  }
  {
    if (piface->flag & IFACE_UP) {
      piface->stop(piface);
    }
    piface->my_ip_addr = 0;
    piface->net_mask = 0;
    piface->broad_cast = 0;
    piface->flag &= ~(IFACE_UP | IFACE_BROAD);
    do_link_new_iface(piface);
  }
}

/**
 * @brief インタフェースからハードウェアアドレス情報を取得する
 * @param piface インタフェース
 * @param[out] phwaddr ハードウェアアドレス情報格納域
 */
static void fill_dhcp_hw_addr(const iface *piface, dhcp_hw_addr *phwaddr) {
  phwaddr->arp_hw_type = piface->arp_hw_type;
  phwaddr->hw_addr_len = piface->hw_addr_len;
  memcpy(&phwaddr->hw_addr, &piface->my_hw_addr, piface->hw_addr_len);
}

/**
 * @brief ミリ秒単位でウェイトをかます
 * @param tm ウェイトカウント ()
 */
static void msleep(const int tm) { usleep(tm * 1000); }
