/* ----------------------------------------------------------------------------
 * Zero Dep Tunnel: VPN library without dependencies
 * ----------------------------------------------------------------------------
 *
 * Copyright (C) 2021 - Emanuele Faranda
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 *
 */

/*
 * This program routes all the local/internet traffic via zdtun.
 * In order to do so, a TUN device is created and the default gateway
 * of the system is altered to pass traffic to this device.
 * Sockets created by zdtun are marked so that their traffic is routed
 * via the original internet gateway.
 */

#include <netinet/ip.h>
#include <arpa/inet.h>

#include <sys/select.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <signal.h>
#include <linux/if.h>

#include <netinet/udp.h>
#include <netinet/tcp.h>

#include "zdtun.h"
#include "utils.h"

#define TUN_DEV "zdtun0"

#define PACKET_BUFSIZE 65535
#define MAX_PURGE_SECS 3

// The TUN interface network details
#define TUN_IP            "10.66.12.1"
#define TUN_GATEWAY_IP    "10.66.12.2"
#define TUN_NETMASK       "255.255.255.0"
#define TUN_IP6           "fd12:3456:789a:1::1/64"
#define TUN_GATEWAY_IP6   "fd12:3456:789a:1::2"

// TUN routing details
#define RT_ORIG_GW_RULE   "16000"
#define RT_TUN_GW_RULE    "16001"
#define RT_ORIG_GW_TABLE  "160"
#define RT_TUN_GW_TABLE   "161"
#define FWMARK_ORIG_GW    0x16

/* ******************************************************* */

static int tun_fd;
static uint8_t running;
static uint8_t proxy_ipver = 0;

/* ******************************************************* */

static int data_in(zdtun_t *tun, zdtun_pkt_t *pkt, const zdtun_conn_t *conn_info) {
  int rv = write(tun_fd, pkt->buf, pkt->len);

  if(rv < 0) {
    error("write(tun) failed[%d]: %s", errno, strerror(errno));
    return(rv);
  } else if(rv != pkt->len) {
    error("write(tun): unexpected rv (expected %d, got %d)", pkt->len, rv);
    return(rv);
  }

  // success
  return(0);
}

/* ******************************************************* */

static zdtun_conn_t* data_out(zdtun_t *tun, const char *pkt_buf, int pkt_len) {
  zdtun_pkt_t pkt;

  if(zdtun_parse_pkt(tun, pkt_buf, pkt_len, &pkt) != 0) {
    debug("zdtun_parse_pkt failed");
    return NULL;
  }

  if(pkt.flags & ZDTUN_PKT_IS_FRAGMENT) {
    debug("discarding IP fragment");
    return NULL;
  }

  uint8_t is_tcp_established = ((pkt.tuple.ipproto == IPPROTO_TCP) &&
    (!(pkt.tcp->th_flags & TH_SYN) || (pkt.tcp->th_flags & TH_ACK)));

  zdtun_conn_t *conn = zdtun_lookup(tun, &pkt.tuple, !is_tcp_established);

  if(!conn) {
    if(is_tcp_established) {
      debug("TCP: ignoring non SYN connection");
    } else {
      error("zdtun_lookup failed");
    }

    return NULL;
  }

  if((proxy_ipver != 0) && (pkt.tuple.ipproto == IPPROTO_TCP))
    zdtun_conn_proxy(conn);

  if(zdtun_forward(tun, &pkt, conn) != 0) {
    error("zdtun_forward failed");

    /* Close the connection as soon an any error occurs */
    zdtun_conn_close(tun, conn, CONN_STATUS_ERROR);
    return NULL;
  }

  return conn;
}

/* ******************************************************* */

static int handle_new_connection(zdtun_t *tun, zdtun_conn_t *conn_info) {
  char buf[256];

  zdtun_5tuple2str(zdtun_conn_get_5tuple(conn_info), buf, sizeof(buf));

  printf("[+] %s\n", buf);

  /* accept connection */
  return(0);
}

/* ******************************************************* */

static int print_conn_iterator(zdtun_t *tun, const zdtun_conn_t *conn_info, void *userdata) {
  char buf[256];

  zdtun_5tuple2str(zdtun_conn_get_5tuple(conn_info), buf, sizeof(buf));

  printf("%s [%s] - %lu sec ago\n", buf,
    zdtun_conn_status2str(zdtun_conn_get_status(conn_info)),
    time(NULL) - zdtun_conn_get_last_seen(conn_info));

  // continue
  return 0;
}

/* ******************************************************* */

static void protect_socket(zdtun_t *tun, socket_t sock) {
  uint mark = FWMARK_ORIG_GW;

  if(setsockopt(sock, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) < 0)
    fatal("setsockopt SO_MARK failed[%d] %s", errno, strerror(errno));
}

/* ******************************************************* */

static void term_handler(int signo) {
  if(running) {
    printf("Shutting down...\n");
    running = 0;
  } else {
    printf("Leaving now\n");
    exit(0);
  }
}

/* ******************************************************* */

static int has_ipv6 = 0;

static void setup_zdtun_routing() {
  u_int32_t gw = get_default_gw();

  if(gw == 0)
    fatal("could not get default gateway");

  struct in_addr addr = {.s_addr = gw};
  char *default_gw = inet_ntoa(addr);

  // Setup the original gateway table
  cmd("ip route add default via %s table " RT_ORIG_GW_TABLE, default_gw);
  cmd("ip rule add fwmark 0x%x/0xff pref " RT_ORIG_GW_RULE " table " RT_ORIG_GW_TABLE, FWMARK_ORIG_GW);

  // Setup the new gateway table. It will also match local networks.
  cmd("ip route add default via " TUN_GATEWAY_IP " table " RT_TUN_GW_TABLE);
  cmd("ip rule add pref " RT_TUN_GW_RULE " table " RT_TUN_GW_TABLE);

  // IPv6
  struct in6_addr gw6_addr;
  char iface6[IFNAMSIZ + 1];

  if(get_default_gw6_and_iface(&gw6_addr, iface6) == 0) {
    char gw6[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &gw6_addr, gw6, sizeof(gw6));

    cmd("ip -6 addr add %s dev %s", TUN_IP6, TUN_DEV);

    cmd("ip -6 route add default via %s dev %s table " RT_ORIG_GW_TABLE, gw6, iface6);
    cmd("ip -6 rule add fwmark 0x%x/0xff pref " RT_ORIG_GW_RULE " table " RT_ORIG_GW_TABLE, FWMARK_ORIG_GW);
    cmd("ip -6 route add default via " TUN_GATEWAY_IP6 " table " RT_TUN_GW_TABLE);
    cmd("ip -6 rule add pref " RT_TUN_GW_RULE " table " RT_TUN_GW_TABLE);
    has_ipv6 = 1;
  }
}

/* ******************************************************* */

static void cleanup_zdtun_routing() {
  const char *ipver[] = {"", " -6"};

  for(int i=0; i<(has_ipv6 ? 2 : 1); i++) {
    const char* ipv = ipver[i];

    cmd("ip%s rule del pref " RT_ORIG_GW_RULE, ipv);
    cmd("ip%s route flush table " RT_ORIG_GW_TABLE, ipv);

    cmd("ip%s rule del pref " RT_TUN_GW_RULE, ipv);
    cmd("ip%s route flush table " RT_TUN_GW_TABLE, ipv);
  }
}

/* ******************************************************* */

static void usage(char **argv) {
  fprintf(stderr, "Usage: %s [proxy_ip proxy_port]\n"
    "\n"
    "Routes all the local/internet traffic via zdtun.\n"
    "An optional SOCKS5 proxy can be used for TCP connections.\n"
    "", argv[0]);

  exit(0);
}

/* ******************************************************* */

int main(int argc, char **argv) {
  char *pkt_buf;
  zdtun_t *tun;
  time_t last_purge;
  zdtun_ip_t proxy_ip = {0};
  int proxy_port = 0;

  zdtun_callbacks_t callbacks = {
    .send_client = data_in,
    .on_connection_open = handle_new_connection,
    .on_socket_open = protect_socket,
  };

  if((argc != 1) && (argc != 3))
    usage(argv);

  if(argc == 3) {
    int af = (strchr(argv[1], ':') == NULL) ? AF_INET : AF_INET6;

    if(inet_pton(af, argv[1], ((af == AF_INET) ? (void*)&proxy_ip.ip4 : (void*)&proxy_ip.ip6)) != 1)
      usage(argv);

    proxy_port = htons(atoi(argv[2]));

    if((proxy_port <= 0) || (proxy_port > 65535))
      usage(argv);

    proxy_ipver = (af == AF_INET) ? 4 : 6;
  }

  if(!(pkt_buf = (char*) malloc(PACKET_BUFSIZE)))
    fatal("Cannot allocate packet buffer");

  tun_fd = open_tun(TUN_DEV, TUN_IP, TUN_NETMASK);
  tun = zdtun_init(&callbacks, NULL);

  if(!tun)
    fatal("zdtun_init failed");

  if(proxy_ipver != 0)
    zdtun_set_socks5_proxy(tun, &proxy_ip, proxy_port, proxy_ipver);

  setup_zdtun_routing();
  signal(SIGPIPE, SIG_IGN);
  signal(SIGINT, term_handler);

  last_purge = time(NULL);
  running = 1;
  printf("zdtun running\n");

  while(running) {
    fd_set fdset;
    fd_set wrfds;
    int max_fd = 0;

    zdtun_fds(tun, &max_fd, &fdset, &wrfds);

    FD_SET(tun_fd, &fdset);
    max_fd = max(max_fd, tun_fd);

    struct timeval tv = {0};
    tv.tv_sec = 1;

    int ret = select(max_fd + 1, &fdset, &wrfds, NULL, &tv);

    if(!running)
      break;
    else if(ret < 0) {
      fatal("Select error[%d]: %s\n", ret, strerror(errno));
    } else if (ret > 0) {
      if(FD_ISSET(tun_fd, &fdset)) {
        int pkt_size = read(tun_fd, pkt_buf, PACKET_BUFSIZE);

        if(pkt_size < 0) {
          fatal("Error reading packet[%d]: %s", (int)pkt_size, strerror(errno));
        } else if(pkt_size < sizeof(struct iphdr)) {
          error("Packet too small: %lu < %d", sizeof(struct iphdr), pkt_size);
        } else
          data_out(tun, pkt_buf, pkt_size);
      } else
        zdtun_handle_fd(tun, &fdset, &wrfds);
    }

    if((time(NULL) - last_purge) >= MAX_PURGE_SECS) {
      zdtun_purge_expired(tun);
      last_purge = time(NULL);
    }
  }

  // print still active connections
  printf("\nActive connections:\n");
  zdtun_iter_connections(tun, print_conn_iterator, NULL);

  // cleanup
  cleanup_zdtun_routing();
  zdtun_finalize(tun);
  free(pkt_buf);

  return(0);
}
