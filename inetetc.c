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
#include <ctype.h>
#include <sys/stat.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <x68k/dos.h>
#include <x68k/iocs.h>

#include "joynetd.h"

//****************************************************************************
// Macros and definitions
//****************************************************************************

//****************************************************************************
// Global variables
//****************************************************************************

//****************************************************************************
// Private variables
//****************************************************************************

#define MAX_ALIASES 16
#define INITIAL_CAPACITY 32

static struct hostent **hosts = NULL;
static int hosts_count = 0;
static int hosts_capacity = 0;

static struct netent **networks = NULL;
static int networks_count = 0;
static int networks_capacity = 0;

static struct servent **services = NULL;
static int services_count = 0;
static int services_capacity = 0;

static struct protoent **protocols = NULL;
static int protocols_count = 0;
static int protocols_capacity = 0;

//****************************************************************************
// Private functions
//****************************************************************************

static int read_etc_hosts(const char *line)
{
    // フォーマット: IP-address hostname [aliases...]
    // 例: 127.0.0.1 localhost lo
    
    // 必要に応じて配列を拡張
    if (hosts_count >= hosts_capacity) {
        int new_capacity = (hosts_capacity == 0) ? INITIAL_CAPACITY : hosts_capacity * 2;
        struct hostent **new_hosts = (struct hostent **)realloc(hosts, sizeof(struct hostent *) * new_capacity);
        if (!new_hosts) {
            return -1;
        }
        hosts = new_hosts;
        hosts_capacity = new_capacity;
    }
    
    char buf[256];
    strncpy(buf, line, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    
    // 末尾の改行を削除
    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n') {
        buf[len - 1] = '\0';
    }
    
    // IP アドレスを取得
    char *saveptr;
    char *ip_str = strtok_r(buf, " \t", &saveptr);
    if (!ip_str) {
        return -1;
    }
    
    struct in_addr addr;
    if (inet_aton(ip_str, &addr) == 0) {
        return -1;
    }
    
    // hostname を取得
    char *hostname = strtok_r(NULL, " \t", &saveptr);
    if (!hostname) {
        return -1;
    }
    
    // aliases を取得（複数可）
    char **aliases = (char **)malloc(sizeof(char *) * (MAX_ALIASES + 1));
    if (!aliases) {
        return -1;
    }
    
    int alias_count = 0;
    char *alias;
    while ((alias = strtok_r(NULL, " \t", &saveptr)) != NULL && alias_count < MAX_ALIASES) {
        aliases[alias_count] = (char *)malloc(strlen(alias) + 1);
        if (!aliases[alias_count]) {
            for (int i = 0; i < alias_count; i++) {
                free(aliases[i]);
            }
            free(aliases);
            return -1;
        }
        strcpy(aliases[alias_count], alias);
        alias_count++;
    }
    aliases[alias_count] = NULL;
    
    // IP アドレス配列を作成
    struct in_addr **addr_list = (struct in_addr **)malloc(sizeof(struct in_addr *) * 2);
    if (!addr_list) {
        for (int i = 0; i < alias_count; i++) {
            free(aliases[i]);
        }
        free(aliases);
        return -1;
    }
    
    struct in_addr *addr_entry = (struct in_addr *)malloc(sizeof(struct in_addr));
    if (!addr_entry) {
        free(addr_list);
        for (int i = 0; i < alias_count; i++) {
            free(aliases[i]);
        }
        free(aliases);
        return -1;
    }
    
    *addr_entry = addr;
    addr_list[0] = addr_entry;
    addr_list[1] = NULL;
    
    // struct hostent を作成
    struct hostent *he = (struct hostent *)malloc(sizeof(struct hostent));
    if (!he) {
        free(addr_entry);
        free(addr_list);
        for (int i = 0; i < alias_count; i++) {
            free(aliases[i]);
        }
        free(aliases);
        return -1;
    }
    
    he->h_name = (char *)malloc(strlen(hostname) + 1);
    if (!he->h_name) {
        free(he);
        free(addr_entry);
        free(addr_list);
        for (int i = 0; i < alias_count; i++) {
            free(aliases[i]);
        }
        free(aliases);
        return -1;
    }
    strcpy(he->h_name, hostname);
    
    he->h_aliases = aliases;
    he->h_addrtype = AF_INET;
    he->h_length = sizeof(struct in_addr);
    he->h_addr_list = (char **)addr_list;
    
    hosts[hosts_count] = he;
    hosts_count++;
    
    return 0;
}

static int read_etc_networks(const char *line)
{
    // フォーマット: network-name network-number [aliases...]
    // 例: loopback 127
    
    // 必要に応じて配列を拡張
    if (networks_count >= networks_capacity) {
        int new_capacity = (networks_capacity == 0) ? INITIAL_CAPACITY : networks_capacity * 2;
        struct netent **new_networks = (struct netent **)realloc(networks, sizeof(struct netent *) * new_capacity);
        if (!new_networks) {
            return -1;
        }
        networks = new_networks;
        networks_capacity = new_capacity;
    }
    
    char buf[256];
    strncpy(buf, line, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    
    // 末尾の改行を削除
    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n') {
        buf[len - 1] = '\0';
    }
    
    // network名を取得
    char *saveptr;
    char *net_name = strtok_r(buf, " \t", &saveptr);
    if (!net_name) {
        return -1;
    }
    
    // network番号を取得
    char *net_addr_str = strtok_r(NULL, " \t", &saveptr);
    if (!net_addr_str) {
        return -1;
    }
    
    struct in_addr net_addr_in;
    if (inet_aton(net_addr_str, &net_addr_in) == 0) {
        return -1;
    }
    uint32_t net_addr = net_addr_in.s_addr;
    
    // aliases を取得（複数可）
    char **aliases = (char **)malloc(sizeof(char *) * (MAX_ALIASES + 1));
    if (!aliases) {
        return -1;
    }
    
    int alias_count = 0;
    char *alias;
    while ((alias = strtok_r(NULL, " \t", &saveptr)) != NULL && alias_count < MAX_ALIASES) {
        aliases[alias_count] = (char *)malloc(strlen(alias) + 1);
        if (!aliases[alias_count]) {
            for (int i = 0; i < alias_count; i++) {
                free(aliases[i]);
            }
            free(aliases);
            return -1;
        }
        strcpy(aliases[alias_count], alias);
        alias_count++;
    }
    aliases[alias_count] = NULL;
    
    // struct netent を作成
    struct netent *ne = (struct netent *)malloc(sizeof(struct netent));
    if (!ne) {
        for (int i = 0; i < alias_count; i++) {
            free(aliases[i]);
        }
        free(aliases);
        return -1;
    }
    
    ne->n_name = (char *)malloc(strlen(net_name) + 1);
    if (!ne->n_name) {
        free(ne);
        for (int i = 0; i < alias_count; i++) {
            free(aliases[i]);
        }
        free(aliases);
        return -1;
    }
    strcpy(ne->n_name, net_name);
    
    ne->n_aliases = aliases;
    ne->n_addrtype = AF_INET;
    ne->n_net = net_addr;
    
    networks[networks_count] = ne;
    networks_count++;
    
    return 0;
}

static int read_etc_services(const char *line)
{
    // フォーマット: service-name port/protocol [aliases...]
    // 例: telnet 23/tcp, http 80/tcp www
    
    // 必要に応じて配列を拡張
    if (services_count >= services_capacity) {
        int new_capacity = (services_capacity == 0) ? INITIAL_CAPACITY : services_capacity * 2;
        struct servent **new_services = (struct servent **)realloc(services, sizeof(struct servent *) * new_capacity);
        if (!new_services) {
            return -1;
        }
        services = new_services;
        services_capacity = new_capacity;
    }
    
    char buf[256];
    strncpy(buf, line, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    
    // 末尾の改行を削除
    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n') {
        buf[len - 1] = '\0';
    }
    
    // service名を取得
    char *saveptr;
    char *service_name = strtok_r(buf, " \t", &saveptr);
    if (!service_name) {
        return -1;
    }
    
    // port/protocolを取得
    char *port_proto = strtok_r(NULL, " \t", &saveptr);
    if (!port_proto) {
        return -1;
    }
    
    // port と protocol を分割
    char port_proto_buf[64];
    strncpy(port_proto_buf, port_proto, sizeof(port_proto_buf) - 1);
    port_proto_buf[sizeof(port_proto_buf) - 1] = '\0';
    
    char *proto = strchr(port_proto_buf, '/');
    if (!proto) {
        return -1;
    }
    *proto++ = '\0';
    
    int port = atoi(port_proto_buf);
    
    // aliases を取得（複数可）
    char **aliases = (char **)malloc(sizeof(char *) * (MAX_ALIASES + 1));
    if (!aliases) {
        return -1;
    }
    
    int alias_count = 0;
    char *alias;
    while ((alias = strtok_r(NULL, " \t", &saveptr)) != NULL && alias_count < MAX_ALIASES) {
        aliases[alias_count] = (char *)malloc(strlen(alias) + 1);
        if (!aliases[alias_count]) {
            // エラー処理: 既に割り当てたメモリを解放
            for (int i = 0; i < alias_count; i++) {
                free(aliases[i]);
            }
            free(aliases);
            return -1;
        }
        strcpy(aliases[alias_count], alias);
        alias_count++;
    }
    aliases[alias_count] = NULL;
    
    // struct servent を作成
    struct servent *se = (struct servent *)malloc(sizeof(struct servent));
    if (!se) {
        for (int i = 0; i < alias_count; i++) {
            free(aliases[i]);
        }
        free(aliases);
        return -1;
    }
    
    se->s_name = (char *)malloc(strlen(service_name) + 1);
    if (!se->s_name) {
        free(se);
        for (int i = 0; i < alias_count; i++) {
            free(aliases[i]);
        }
        free(aliases);
        return -1;
    }
    strcpy(se->s_name, service_name);
    
    se->s_aliases = aliases;
    se->s_port = htons(port);
    
    se->s_proto = (char *)malloc(strlen(proto) + 1);
    if (!se->s_proto) {
        free(se->s_name);
        free(se);
        for (int i = 0; i < alias_count; i++) {
            free(aliases[i]);
        }
        free(aliases);
        return -1;
    }
    strcpy(se->s_proto, proto);
    
    services[services_count] = se;
    services_count++;
    
    return 0;
}

static int read_etc_protocols(const char *line)
{
    // フォーマット: protocol-name protocol-number [aliases...]
    // 例: ip 0 IP
    
    // 必要に応じて配列を拡張
    if (protocols_count >= protocols_capacity) {
        int new_capacity = (protocols_capacity == 0) ? INITIAL_CAPACITY : protocols_capacity * 2;
        struct protoent **new_protocols = (struct protoent **)realloc(protocols, sizeof(struct protoent *) * new_capacity);
        if (!new_protocols) {
            return -1;
        }
        protocols = new_protocols;
        protocols_capacity = new_capacity;
    }
    
    char buf[256];
    strncpy(buf, line, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    
    // 末尾の改行を削除
    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n') {
        buf[len - 1] = '\0';
    }
    
    // protocol名を取得
    char *saveptr;
    char *proto_name = strtok_r(buf, " \t", &saveptr);
    if (!proto_name) {
        return -1;
    }
    
    // protocol番号を取得
    char *proto_num_str = strtok_r(NULL, " \t", &saveptr);
    if (!proto_num_str) {
        return -1;
    }
    
    int proto_num = atoi(proto_num_str);
    
    // aliases を取得（複数可）
    char **aliases = (char **)malloc(sizeof(char *) * (MAX_ALIASES + 1));
    if (!aliases) {
        return -1;
    }
    
    int alias_count = 0;
    char *alias;
    while ((alias = strtok_r(NULL, " \t", &saveptr)) != NULL && alias_count < MAX_ALIASES) {
        aliases[alias_count] = (char *)malloc(strlen(alias) + 1);
        if (!aliases[alias_count]) {
            for (int i = 0; i < alias_count; i++) {
                free(aliases[i]);
            }
            free(aliases);
            return -1;
        }
        strcpy(aliases[alias_count], alias);
        alias_count++;
    }
    aliases[alias_count] = NULL;
    
    // struct protoent を作成
    struct protoent *pe = (struct protoent *)malloc(sizeof(struct protoent));
    if (!pe) {
        for (int i = 0; i < alias_count; i++) {
            free(aliases[i]);
        }
        free(aliases);
        return -1;
    }
    
    pe->p_name = (char *)malloc(strlen(proto_name) + 1);
    if (!pe->p_name) {
        free(pe);
        for (int i = 0; i < alias_count; i++) {
            free(aliases[i]);
        }
        free(aliases);
        return -1;
    }
    strcpy(pe->p_name, proto_name);
    
    pe->p_aliases = aliases;
    pe->p_proto = proto_num;
    
    protocols[protocols_count] = pe;
    protocols_count++;
    
    return 0;
}

// ---------------------------------------------------------------------------

static int *read_one_etc_file(const char *sysroot, const char *file,
                              int (*parser)(const char *line))
{
    char filepath[256];
    memset(filepath, 0, sizeof(filepath));
    strncpy(filepath, sysroot, sizeof(filepath) - 1);
    strncat(filepath, "/", sizeof(filepath) - strlen(filepath) - 1);
    strncat(filepath, file, sizeof(filepath) - strlen(filepath) - 1);

    FILE *fp = fopen(filepath, "r");
    if (fp == NULL) {
        return 0;
    }

    char line[256];
    while (fgets(line, sizeof(line), fp) != NULL) {
        char *p = line;
        while (isspace((unsigned char)*p)) {
            p++;
        }
        if (*p == '#' || *p == '\0') {
            continue;   // コメント行または空行
        }
        if (parser) {
            parser(p);
        }
    }

    fclose(fp);
    return 0;
}

static int read_etc_files(const char *sysroot)
{
    read_one_etc_file(sysroot, "hosts", read_etc_hosts);
    read_one_etc_file(sysroot, "networks", read_etc_networks);
    read_one_etc_file(sysroot, "services", read_etc_services);
    read_one_etc_file(sysroot, "protocols", read_etc_protocols);
    return 0;
}

//****************************************************************************
// Public functions
//****************************************************************************

struct hostent *do_gethostbyname(const char *name)
{
    PRINTF("joynetd: gethostbyname(%s)\n", name);

    if (!name) {
        return NULL;
    }
    
    for (int i = 0; i < hosts_count; i++) {
        if (hosts[i] && hosts[i]->h_name) {
            if (strcmp(hosts[i]->h_name, name) == 0) {
                return hosts[i];
            }
            // aliases も検索
            if (hosts[i]->h_aliases) {
                for (int j = 0; hosts[i]->h_aliases[j] != NULL; j++) {
                    if (strcmp(hosts[i]->h_aliases[j], name) == 0) {
                        return hosts[i];
                    }
                }
            }
        }
    }
    
    return NULL;
}

struct hostent *do_gethostbyaddr(const void *addr, socklen_t len, int type)
{
    PRINTF("joynetd: gethostbyaddr(%p, %u, %d)\n", addr, (unsigned int)len, type);

    if (!addr || len != sizeof(struct in_addr) || type != AF_INET) {
        return NULL;
    }
    
    const struct in_addr *in_addr_ptr = (const struct in_addr *)addr;
    
    for (int i = 0; i < hosts_count; i++) {
        if (hosts[i] && hosts[i]->h_addr_list) {
            for (int j = 0; hosts[i]->h_addr_list[j] != NULL; j++) {
                struct in_addr *host_addr = (struct in_addr *)hosts[i]->h_addr_list[j];
                if (host_addr->s_addr == in_addr_ptr->s_addr) {
                    return hosts[i];
                }
            }
        }
    }
    
    return NULL;
}

struct netent *do_getnetbyname(const char *name)
{
    PRINTF("joynetd: getnetbyname(%s)\n", name);

    if (!name) {
        return NULL;
    }
    
    for (int i = 0; i < networks_count; i++) {
        if (networks[i] && networks[i]->n_name) {
            if (strcmp(networks[i]->n_name, name) == 0) {
                return networks[i];
            }
            // aliases も検索
            if (networks[i]->n_aliases) {
                for (int j = 0; networks[i]->n_aliases[j] != NULL; j++) {
                    if (strcmp(networks[i]->n_aliases[j], name) == 0) {
                        return networks[i];
                    }
                }
            }
        }
    }
    
    return NULL;
}

struct netent *do_getnetbyaddr(uint32_t net, int type)
{
    PRINTF("joynetd: getnetbyaddr(%lu, %d)\n", net, type);

    if (type != AF_INET) {
        return NULL;
    }

    for (int i = 0; i < networks_count; i++) {
        if (networks[i] && networks[i]->n_net == net) {
            return networks[i];
        }
    }
    
    return NULL;
}

struct servent *do_getservbyname(const char *name, const char *proto)
{
    PRINTF("joynetd: getservbyname(%s, %s)\n", name, proto);

    if (!name) {
        return NULL;
    }
    
    for (int i = 0; i < services_count; i++) {
        if (services[i] && services[i]->s_name) {
            if (strcmp(services[i]->s_name, name) == 0) {
                // proto が指定されている場合はチェック
                if (proto == NULL || strcmp(services[i]->s_proto, proto) == 0) {
                    return services[i];
                }
            }
            // aliases も検索
            if (services[i]->s_aliases) {
                for (int j = 0; services[i]->s_aliases[j] != NULL; j++) {
                    if (strcmp(services[i]->s_aliases[j], name) == 0) {
                        if (proto == NULL || strcmp(services[i]->s_proto, proto) == 0) {
                            return services[i];
                        }
                    }
                }
            }
        }
    }
    
    return NULL;
}

struct servent *do_getservbyport(int port, const char *proto)
{
    PRINTF("joynetd: getservbyport(%d, %s)\n", port, proto);

    uint16_t net_port = htons(port);

    for (int i = 0; i < services_count; i++) {
        if (services[i] && services[i]->s_port == net_port) {
            // proto が指定されている場合はチェック
            if (proto == NULL || strcmp(services[i]->s_proto, proto) == 0) {
                return services[i];
            }
        }
    }
    
    return NULL;
}

struct protoent *do_getprotobyname(const char *name)
{
    PRINTF("joynetd: getprotobyname(%s)\n", name);

    if (!name) {
        return NULL;
    }
    
    for (int i = 0; i < protocols_count; i++) {
        if (protocols[i] && protocols[i]->p_name) {
            if (strcmp(protocols[i]->p_name, name) == 0) {
                return protocols[i];
            }
            // aliases も検索
            if (protocols[i]->p_aliases) {
                for (int j = 0; protocols[i]->p_aliases[j] != NULL; j++) {
                    if (strcmp(protocols[i]->p_aliases[j], name) == 0) {
                        return protocols[i];
                    }
                }
            }
        }
    }
    
    return NULL;
}

struct protoent *do_getprotobynumber(int proto)
{
    PRINTF("joynetd: getprotobynumber(%d)\n", proto);

    for (int i = 0; i < protocols_count; i++) {
        if (protocols[i] && protocols[i]->p_proto == proto) {
            return protocols[i];
        }
    }
    
    return NULL;
}

// ---------------------------------------------------------------------------

int init_etc_files(void)
{
    char *sysroot = getenv("SYSROOT");
    if (sysroot != NULL) {
        char filepath[256];
        memset(filepath, 0, sizeof(filepath));
        strncpy(filepath, sysroot, sizeof(filepath) - 1);
        strncat(filepath, "/etc", sizeof(filepath) - strlen(filepath) - 1);

        struct stat st;
        if (stat(filepath, &st) == 0 && S_ISDIR(st.st_mode)) {
            // /etc ディレクトリが存在する場合
            return read_etc_files(filepath);
        }
    }

    struct dos_psp *psp = _dos_getpdb();
    return read_etc_files(psp->exe_path);
}

void fini_etc_files(void)
{
    // hosts を解放
    if (hosts) {
        for (int i = 0; i < hosts_count; i++) {
            if (hosts[i]) {
                if (hosts[i]->h_name) {
                    free(hosts[i]->h_name);
                }
                if (hosts[i]->h_aliases) {
                    for (int j = 0; hosts[i]->h_aliases[j] != NULL; j++) {
                        free(hosts[i]->h_aliases[j]);
                    }
                    free(hosts[i]->h_aliases);
                }
                if (hosts[i]->h_addr_list) {
                    for (int j = 0; hosts[i]->h_addr_list[j] != NULL; j++) {
                        free(hosts[i]->h_addr_list[j]);
                    }
                    free(hosts[i]->h_addr_list);
                }
                free(hosts[i]);
            }
        }
        free(hosts);
        hosts = NULL;
        hosts_count = 0;
        hosts_capacity = 0;
    }

    // networks を解放
    if (networks) {
        for (int i = 0; i < networks_count; i++) {
            if (networks[i]) {
                if (networks[i]->n_name) {
                    free(networks[i]->n_name);
                }
                if (networks[i]->n_aliases) {
                    for (int j = 0; networks[i]->n_aliases[j] != NULL; j++) {
                        free(networks[i]->n_aliases[j]);
                    }
                    free(networks[i]->n_aliases);
                }
                free(networks[i]);
            }
        }
        free(networks);
        networks = NULL;
        networks_count = 0;
        networks_capacity = 0;
    }
    
    // services を解放
    if (services) {
        for (int i = 0; i < services_count; i++) {
            if (services[i]) {
                if (services[i]->s_name) {
                    free(services[i]->s_name);
                }
                if (services[i]->s_proto) {
                    free(services[i]->s_proto);
                }
                if (services[i]->s_aliases) {
                    for (int j = 0; services[i]->s_aliases[j] != NULL; j++) {
                        free(services[i]->s_aliases[j]);
                    }
                    free(services[i]->s_aliases);
                }
                free(services[i]);
            }
        }
        free(services);
        services = NULL;
        services_count = 0;
        services_capacity = 0;
    }
    
    // protocols を解放
    if (protocols) {
        for (int i = 0; i < protocols_count; i++) {
            if (protocols[i]) {
                if (protocols[i]->p_name) {
                    free(protocols[i]->p_name);
                }
                if (protocols[i]->p_aliases) {
                    for (int j = 0; protocols[i]->p_aliases[j] != NULL; j++) {
                        free(protocols[i]->p_aliases[j]);
                    }
                    free(protocols[i]->p_aliases);
                }
                free(protocols[i]);
            }
        }
        free(protocols);
        protocols = NULL;
        protocols_count = 0;
        protocols_capacity = 0;
    }
}
