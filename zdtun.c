/* ----------------------------------------------------------------------------
 * Zero Dep Tunnel: VPN library without dependencies
 * ----------------------------------------------------------------------------
 *
 * Copyright (C) 2018 - Emanuele Faranda
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 * 
 */

#include "zdtun.h"
#include "utils.h"
#include "third_party/uthash.h"
#include "third_party/net_headers.h"

#define REPLY_BUF_SIZE 65535
#define TCP_WINDOW_SIZE 64240
#define MIN_TCP_HEADER_LEN 20
#define IPV4_HEADER_LEN 20
#define IPV6_HEADER_LEN 40
#define UDP_HEADER_LEN 8

#define ICMP_TIMEOUT_SEC 5
#define UDP_TIMEOUT_SEC 15
#define TCP_TIMEOUT_SEC 30

#ifdef WIN32
  // 64 is the per-thread limit on Winsocks
  // use a lower value to leave room for user defined connections
  #define MAX_NUM_SOCKETS 55
  #define NUM_SOCKETS_AFTER_PURGE 40
#else
  // on linux, the maximum open files limit is 1024
  #define MAX_NUM_SOCKETS 128
  #define NUM_SOCKETS_AFTER_PURGE 96
#endif

/* ******************************************************* */

static void close_conn(zdtun_t *tun, zdtun_conn_t *conn, zdtun_conn_status_t status);

/* ******************************************************* */

struct tcp_pending_data {
  char *data;
  int size;
  int sofar;
};

typedef struct zdtun_dnat {
  zdtun_ip_t ip;
  u_int16_t port;
} zdtun_dnat_t;

typedef struct zdtun_conn {
  zdtun_5tuple_t tuple;
  time_t tstamp;
  socket_t sock;
  zdtun_conn_status_t status;
  zdtun_dnat_t *dnat;

  struct {
    u_int32_t client_seq;    // next client sequence number
    u_int32_t zdtun_seq;     // next proxy sequence number
    u_int16_t window_size;   // client window size
    bool fin_ack_sent;
    bool client_closed;
    struct tcp_pending_data *pending;
  } tcp;

  struct {
    u_int8_t pending_queries;
  } dns;

  void *user_data;
  UT_hash_handle hh;  // tuple -> conn
} zdtun_conn_t;

/* ******************************************************* */

typedef struct zdtun_t {
  struct zdtun_callbacks callbacks;
  void *user_data;
  fd_set all_fds;
  fd_set tcp_connecting;
  int max_window_size;
  zdtun_statistics_t stats;
  char reply_buf[REPLY_BUF_SIZE];

  zdtun_conn_t *sock_2_conn;
  zdtun_conn_t *conn_table;
} zdtun_t;

/* ******************************************************* */

struct dns_packet {
  uint16_t transaction_id;
  uint16_t flags;
  uint16_t questions;
  uint16_t answ_rrs;
  uint16_t auth_rrs;
  uint16_t additional_rrs;
  uint8_t initial_dot; // just skip
  uint8_t queries[];
} __attribute__((packed));

#define DNS_FLAGS_MASK 0x8000
#define DNS_TYPE_REQUEST 0x0000
#define DNS_TYPE_RESPONSE 0x8000

/* ******************************************************* */

struct ippseudo {
  uint32_t ippseudo_src;    /* source internet address */
  uint32_t ippseudo_dst;    /* destination internet address */
  u_int8_t ippseudo_pad;    /* pad, must be zero */
  u_int8_t ippseudo_p;      /* protocol */
  u_int16_t ippseudo_len;	  /* protocol length */
};

struct ip6_hdr_pseudo {
  struct in6_addr ip6ph_src;
  struct in6_addr ip6ph_dst;
  u_int32_t ip6ph_len;
  u_int8_t ip6ph_zero[3];
  u_int8_t ip6ph_nxt;
} __attribute__((packed));

/* ******************************************************* */

void zdtun_fds(zdtun_t *tun, int *max_fd, fd_set *rdfd, fd_set *wrfd) {
  *max_fd = tun->stats.all_max_fd;
  *rdfd = tun->all_fds;
  *wrfd = tun->tcp_connecting;
}

/* ******************************************************* */

static socket_t open_socket(zdtun_t *tun, int domain, int type, int protocol) {
  if(tun->stats.num_open_sockets >= MAX_NUM_SOCKETS)
    return(INVALID_SOCKET);

  socket_t sock = socket(domain, type, protocol);

  if(sock == INVALID_SOCKET)
    return(INVALID_SOCKET);

#ifndef WIN32
  if(sock < 0)
    return(INVALID_SOCKET);

  /* FD_SETSIZE should never be execeeded, otherwise FD_SET will crash */
  if(sock >= FD_SETSIZE) {
    error("socket exceeds FD_SETSIZE");
    closesocket(sock);

    return(INVALID_SOCKET);
  }
#endif

  if(tun->callbacks.on_socket_open)
    tun->callbacks.on_socket_open(tun, sock);

  FD_SET(sock, &tun->all_fds);
  tun->stats.num_open_sockets++;

#ifndef WIN32
  tun->stats.all_max_fd = max(tun->stats.all_max_fd, sock);
#endif

  switch(protocol) {
    case IPPROTO_UDP:
      tun->stats.num_udp_opened++;
      break;
    case IPPROTO_TCP:
      tun->stats.num_tcp_opened++;
      break;
    case IPPROTO_ICMP:
      tun->stats.num_icmp_opened++;
      break;
  }

  return(sock);
}

/* ******************************************************* */

static void close_socket(zdtun_t *tun, socket_t sock) {
  if(sock == INVALID_SOCKET)
    return;

  int rv = closesocket(sock);

  if(rv == SOCKET_ERROR) {
    error("closesocket failed[%d]", socket_errno);
  } else if(tun->callbacks.on_socket_close)
    tun->callbacks.on_socket_close(tun, sock);

  FD_CLR(sock, &tun->all_fds);
  FD_CLR(sock, &tun->tcp_connecting);

  tun->stats.num_open_sockets = max(tun->stats.num_open_sockets-1, 0);
}

/* ******************************************************* */

// Returns != 0 if the error is related to a client side problem
static int close_with_socket_error(zdtun_t *tun, zdtun_conn_t *conn, const char *ctx) {
  int rv = 0;
  zdtun_conn_status_t status;
  char buf[256];

  switch(socket_errno) {
    case socket_con_reset:
      status = CONN_STATUS_RESET;
      break;
    case socket_broken_pipe:
      status = CONN_STATUS_SOCKET_ERROR;
      break;
    case socket_con_refused:
      status = CONN_STATUS_SOCKET_ERROR;
      break;
    case socket_con_aborted:
      status = CONN_STATUS_SOCKET_ERROR;
      break;
    case socket_net_unreachable:
    case socket_host_unreachable:
      status = CONN_STATUS_UNREACHABLE;
      rv = -1;
      break;
    default:
      status = CONN_STATUS_SOCKET_ERROR;
      rv = -1;
      break;
  }

  zdtun_5tuple2str(&conn->tuple, buf, sizeof(buf));

  if(rv == 0) {
    log("%s error[%d]: %s - %s", ctx, socket_errno, strerror(socket_errno), buf);
  } else {
    error("%s error[%d]: %s - %s", ctx, socket_errno, strerror(socket_errno), buf);
  }

  close_conn(tun, conn, status);
  return(rv);
}

/* ******************************************************* */

void* zdtun_userdata(zdtun_t *tun) {
  return(tun->user_data);
}

/* ******************************************************* */

/* Connection methods */
void* zdtun_conn_get_userdata(const zdtun_conn_t *conn) {
  return conn->user_data;
}

void zdtun_conn_set_userdata(zdtun_conn_t *conn, void *userdata) {
  conn->user_data = userdata;
}

// TODO allow DNAT to different IP version
int zdtun_conn_dnat(zdtun_conn_t *conn, const zdtun_ip_t *dest_ip, uint16_t dest_port) {
  zdtun_dnat_t *dnat = (zdtun_dnat_t*) malloc(sizeof(zdtun_dnat_t));

  if(dnat == NULL) {
    error("malloc(zdtun_dnat_t) failed");
    return -1;
  }

  dnat->ip = *dest_ip;
  dnat->port = dest_port;

  if(conn->dnat)
    free(conn->dnat);

  conn->dnat = dnat;

  return 0;
}

const zdtun_5tuple_t* zdtun_conn_get_5tuple(const zdtun_conn_t *conn) {
  return &conn->tuple;
}

time_t zdtun_conn_get_last_seen(const zdtun_conn_t *conn) {
    return conn->tstamp;
}

zdtun_conn_status_t zdtun_conn_get_status(const zdtun_conn_t *conn) {
  return conn->status;
}

/* ******************************************************* */

zdtun_t* zdtun_init(struct zdtun_callbacks *callbacks, void *udata) {
  zdtun_t *tun;
  safe_alloc(tun, zdtun_t);

  if(!tun) {
    error("zdtun_t calloc error");
    return NULL;
  }

  /* Verify mandatory callbacks */
  if(!callbacks) {
    error("callbacks parameter is NULL");
    return NULL;
  }
  if(!callbacks->send_client) {
    error("missing mandatory send_client callback");
    return NULL;
  }

  tun->user_data = udata;
  tun->max_window_size = TCP_WINDOW_SIZE;
  memcpy(&tun->callbacks, callbacks, sizeof(tun->callbacks));

  FD_ZERO(&tun->all_fds);
  FD_ZERO(&tun->tcp_connecting);

  return tun;
}

/* ******************************************************* */

void ztdun_finalize(zdtun_t *tun) {
  zdtun_conn_t *conn, *tmp;

  HASH_ITER(hh, tun->conn_table, conn, tmp) {
    zdtun_destroy_conn(tun, conn);
  }

  free(tun);
}

/* ******************************************************* */

static int send_to_client(zdtun_t *tun, zdtun_conn_t *conn, int l3_len) {
  int size = l3_len + ((conn->tuple.ipver == 4) ? IPV4_HEADER_LEN : IPV6_HEADER_LEN);
  int rv = tun->callbacks.send_client(tun, tun->reply_buf, size, conn);

  if(rv == 0) {
    if(tun->callbacks.account_packet)
      tun->callbacks.account_packet(tun, tun->reply_buf, size, 0 /* from zdtun */, conn);
  } else {
    error("send_client failed [%d]", rv);

    // important: set this to prevent close_conn to call send_to_client again in a loop
    conn->tcp.fin_ack_sent = true;

    close_conn(tun, conn, CONN_STATUS_CLIENT_ERROR);
  }

  return(rv);
}

/* ******************************************************* */

static void build_reply_ip(zdtun_conn_t *conn, char *pkt_buf, u_int16_t l3_len) {
  if(conn->tuple.ipver == 4) {
    struct iphdr *ip = (struct iphdr*)pkt_buf;
    uint16_t tot_len = l3_len + IPV4_HEADER_LEN;

    memset(ip, 0, IPV4_HEADER_LEN);
    ip->ihl = 5; // 5 * 4 = 20 = IPV4_HEADER_LEN
    ip->version = 4;
    ip->frag_off = htons(0x4000); // don't fragment
    ip->tot_len = htons(tot_len);
    ip->ttl = 64; // hops
    ip->protocol = conn->tuple.ipproto;
    ip->saddr = conn->tuple.dst_ip.ip4;
    ip->daddr = conn->tuple.src_ip.ip4;

    ip->check = ~calc_checksum(0, (u_int8_t*)ip, IPV4_HEADER_LEN);
  } else {
    struct ipv6_hdr *ip = (struct ipv6_hdr*)pkt_buf;

    memset(ip, 0, IPV6_HEADER_LEN);
    ip->version = 6;
    ip->payload_len = htons(l3_len);
    ip->nexthdr = (conn->tuple.ipproto != IPPROTO_ICMP) ? conn->tuple.ipproto : IPPROTO_ICMPV6;
    ip->hop_limit = 64;
    ip->saddr = conn->tuple.dst_ip.ip6;
    ip->daddr = conn->tuple.src_ip.ip6;
  }
}

/* ******************************************************* */

static void build_reply_tcpip(zdtun_t *tun, zdtun_conn_t *conn, u_int8_t flags, u_int16_t l4_len) {
  int iphdr_len = (conn->tuple.ipver == 4) ? IPV4_HEADER_LEN : IPV6_HEADER_LEN;
  const u_int16_t l3_len = l4_len + MIN_TCP_HEADER_LEN;
  struct tcphdr *tcp = (struct tcphdr *)&tun->reply_buf[iphdr_len];

  memset(tcp, 0, MIN_TCP_HEADER_LEN);
  tcp->th_sport = conn->tuple.dst_port;
  tcp->th_dport = conn->tuple.src_port;
  tcp->th_seq = htonl(conn->tcp.zdtun_seq);
  tcp->th_ack = (flags & TH_ACK) ? htonl(conn->tcp.client_seq) : 0;
  tcp->th_off = 5;
  tcp->th_flags = flags;
  tcp->th_win = htons(tun->max_window_size);

  build_reply_ip(conn, tun->reply_buf, l3_len);
  tcp->th_sum = calc_checksum(0, (uint8_t*)tcp, l3_len);

  if(conn->tuple.ipver == 4) {
    struct iphdr *ip_header = (struct iphdr*)tun->reply_buf;
    struct ippseudo pseudo = {0};

    pseudo.ippseudo_src = ip_header->saddr;
    pseudo.ippseudo_dst = ip_header->daddr;
    pseudo.ippseudo_p = IPPROTO_TCP;
    pseudo.ippseudo_len = htons(l3_len);

    tcp->th_sum = calc_checksum(tcp->th_sum, (uint8_t*)&pseudo, sizeof(pseudo));
  } else {
    struct ipv6_hdr *ip_header = (struct ipv6_hdr*)tun->reply_buf;
    struct ip6_hdr_pseudo pseudo = {0};

    pseudo.ip6ph_src = ip_header->saddr;
    pseudo.ip6ph_dst = ip_header->daddr;
    pseudo.ip6ph_len = ip_header->payload_len;
    pseudo.ip6ph_nxt = IPPROTO_TCP;

    tcp->th_sum = calc_checksum(tcp->th_sum, (uint8_t*)&pseudo, sizeof(pseudo));
  }

  tcp->th_sum = ~tcp->th_sum;
}

/* ******************************************************* */

// It is used to defer the zdtun_destroy_conn function to let the user
// consume the connection without accessing invalid memory. The connections
// will be (later) destroyed by zdtun_purge_expired.
// May be called multiple times.
static void close_conn(zdtun_t *tun, zdtun_conn_t *conn, zdtun_conn_status_t status) {
  if(conn->status >= CONN_STATUS_CLOSED)
    return;

  close_socket(tun, conn->sock);
  conn->sock = INVALID_SOCKET;

  if(conn->tcp.pending) {
    free(conn->tcp.pending->data);
    free(conn->tcp.pending);
    conn->tcp.pending = NULL;
  }

  if((conn->tuple.ipproto == IPPROTO_TCP)
      && !conn->tcp.fin_ack_sent) {
    // Send TCP RST
    build_reply_tcpip(tun, conn, TH_RST | TH_ACK, 0);
    send_to_client(tun, conn, MIN_TCP_HEADER_LEN);
  }

  conn->status = (status >= CONN_STATUS_CLOSED) ? status : CONN_STATUS_CLOSED;

  if(tun->callbacks.on_connection_close)
    tun->callbacks.on_connection_close(tun, conn);
}

/* ******************************************************* */

// Avoid calling zdtun_destroy_conn inside zdtun_forward_full as it may
// generate dangling pointers. Use close_conn instead.
void zdtun_destroy_conn(zdtun_t *tun, zdtun_conn_t *conn) {
  debug("PURGE SOCKET (type=%d)", conn->tuple.ipproto);

  close_conn(tun, conn, CONN_STATUS_CLOSED);

  switch(conn->tuple.ipproto) {
    case IPPROTO_TCP:
      tun->stats.num_tcp_conn--;
      break;
    case IPPROTO_UDP:
      tun->stats.num_udp_conn--;
      break;
    case IPPROTO_ICMP:
      tun->stats.num_icmp_conn--;
      break;
  }

  if(conn->dnat)
    free(conn->dnat);

  HASH_DELETE(hh, tun->conn_table, conn);
  free(conn);
}

/* ******************************************************* */

static int tcp_socket_syn(zdtun_t *tun, zdtun_conn_t *conn) {
  int rv = 0;

  // disable non-blocking mode from now on

#ifdef WIN32
  unsigned nonblocking = 0;
  ioctlsocket(conn->sock, FIONBIO, &nonblocking);
#else
  int flags = fcntl(conn->sock, F_GETFL);

  if(fcntl(conn->sock, F_SETFL, flags &(~O_NONBLOCK)) == -1)
    error("Cannot disable non-blocking: %d", errno);
#endif

  FD_CLR(conn->sock, &tun->tcp_connecting);
  conn->status = CONN_STATUS_CONNECTED;

  // send the SYN+ACK
  build_reply_tcpip(tun, conn, TH_SYN | TH_ACK, 0);

  if((rv = send_to_client(tun, conn, MIN_TCP_HEADER_LEN)) == 0)
    conn->tcp.zdtun_seq += 1;

  return rv;
}

/* ******************************************************* */

static void tcp_socket_fin_ack(zdtun_t *tun, zdtun_conn_t *conn) {
  build_reply_tcpip(tun, conn, TH_FIN | TH_ACK, 0);

  if(send_to_client(tun, conn, MIN_TCP_HEADER_LEN) == 0)
    conn->tcp.zdtun_seq += 1;
}

/* ******************************************************* */

zdtun_conn_t* zdtun_lookup(zdtun_t *tun, const zdtun_5tuple_t *tuple, uint8_t create) {
  zdtun_conn_t *conn = NULL;

  HASH_FIND(hh, tun->conn_table, tuple, sizeof(*tuple), conn);

  if(!conn && create) {
    if(tun->stats.num_open_sockets >= MAX_NUM_SOCKETS) {
      debug("Force purge!");
      zdtun_purge_expired(tun, time(NULL));
    }

    /* Add a new connection */
    safe_alloc(conn, zdtun_conn_t);
    conn->sock = INVALID_SOCKET;
    conn->tuple = *tuple;
    conn->tstamp = time(NULL);

    if(tun->callbacks.on_connection_open) {
      if(tun->callbacks.on_connection_open(tun, conn) != 0) {
        debug("Dropping connection");
        free(conn);
        return NULL;
      }
    }

    HASH_ADD(hh, tun->conn_table, tuple, sizeof(*tuple), conn);

    switch(conn->tuple.ipproto) {
      case IPPROTO_TCP:
        tun->stats.num_tcp_conn++;
        break;
      case IPPROTO_UDP:
        tun->stats.num_udp_conn++;
        break;
      case IPPROTO_ICMP:
        tun->stats.num_icmp_conn++;
        break;
    }
  }

  return conn;
}

/* ******************************************************* */

static int process_pending_tcp_packets(zdtun_t *tun, zdtun_conn_t *conn) {
  struct tcp_pending_data *pending = conn->tcp.pending;
  int iphdr_len = (conn->tuple.ipver == 4) ? IPV4_HEADER_LEN : IPV6_HEADER_LEN;

  if(!conn->tcp.window_size || !pending || (conn->sock == INVALID_SOCKET))
    return 0;

  int remaining = pending->size - pending->sofar;
  int to_send = min(conn->tcp.window_size, remaining);

  log_tcp_window("[%d][Window size: %d] Sending %d/%d bytes pending data", conn->tuple.src_port, conn->tcp.window_size, to_send, remaining);
  memcpy(tun->reply_buf + MIN_TCP_HEADER_LEN + iphdr_len, &pending->data[pending->sofar], to_send);

  // proxy back the TCP port and reconstruct the TCP header
  build_reply_tcpip(tun, conn, TH_PUSH | TH_ACK, to_send);

  if(send_to_client(tun, conn, to_send + MIN_TCP_HEADER_LEN) != 0) {
    log_tcp_window("[%d][Window size: %d] failed", conn->tuple.src_port, conn->tcp.window_size);
    return -1;
  }

  conn->tcp.zdtun_seq += to_send;
  conn->tcp.window_size -= to_send;

  log_tcp_window("[%d][Window size: %d] Remaining to send: %d", conn->tuple.src_port, conn->tcp.window_size, remaining - to_send);

  if(remaining == to_send) {
    free(pending->data);
    free(pending);
    conn->tcp.pending = NULL;

    // make the socket selectable again
    FD_SET(conn->sock, &tun->all_fds);
  } else
    pending->sofar += to_send;

  return 0;
}

/* ******************************************************* */

static void check_dns_request(zdtun_conn_t *conn, char *l4_payload, uint16_t l4_len) {
  struct dns_packet *dns;

  if((l4_len < sizeof(struct dns_packet)) || (conn->tuple.dst_port != ntohs(53)))
    return;

  dns = (struct dns_packet*)l4_payload;

  if((dns->flags & DNS_FLAGS_MASK) == DNS_TYPE_REQUEST)
    conn->dns.pending_queries++;
}

/* ******************************************************* */

static int check_dns_purge(zdtun_t *tun, zdtun_conn_t *conn,
        char *l4_payload, uint16_t l4_len) {
    struct dns_packet *dns;

    if((l4_len < sizeof(struct dns_packet)) || (conn->tuple.dst_port != ntohs(53)))
      return(1);

    dns = (struct dns_packet*)l4_payload;

    if(((dns->flags & DNS_FLAGS_MASK) == DNS_TYPE_RESPONSE)
        && (conn->dns.pending_queries > 0)) {
      conn->dns.pending_queries--;

      if(conn->dns.pending_queries == 0) {
        char buf[256];

        /* DNS responses received, can now purge the conn */
        debug("DNS purge: %s", zdtun_5tuple2str(&conn->tuple, buf, sizeof(buf)));
        close_conn(tun, conn, CONN_STATUS_CLOSED);

        /* purged */
        return(0);
      }
    }

    return(1);
}

/* ******************************************************* */

static int is_upper_layer(int proto) {
  return (proto == IPPROTO_TCP ||
          proto == IPPROTO_UDP ||
          proto == IPPROTO_ICMP ||
          proto == IPPROTO_ICMPV6);
}

/* ******************************************************* */

int zdtun_parse_pkt(const char *_pkt_buf, uint16_t pkt_len, zdtun_pkt_t *pkt) {
  if(pkt_len < 20) {
    debug("Ignoring non IP packet (len: %d)", pkt_len);
    return -1;
  }

  memset(pkt, 0, sizeof(zdtun_pkt_t));

  char *pkt_buf = (char *)_pkt_buf; /* needed to set the zdtun_pkt_t pointers */
  uint8_t ipver = (*pkt_buf) >> 4;
  uint8_t ipproto;
  int iphdr_len;

  if((ipver != 4) && (ipver != 6)) {
    debug("Ignoring non IP packet (len: %d, v: %d)", pkt_len, ipver);
    return -1;
  }

  if(ipver == 4) {
    struct iphdr *ip_header = (struct iphdr*) pkt_buf;
    iphdr_len = ip_header->ihl * 4;

    if(pkt_len < iphdr_len) {
      debug("IPv4 packet too short: %d bytes", pkt_len);
      return -1;
    }

    pkt->tuple.src_ip.ip4 = ip_header->saddr;
    pkt->tuple.dst_ip.ip4 = ip_header->daddr;
    ipproto = ip_header->protocol;
  } else {
    struct ipv6_hdr *ip_header = (struct ipv6_hdr*) pkt_buf;

    if(pkt_len < sizeof(struct ipv6_hdr)) {
      debug("IPv6 packet too short: %d bytes", pkt_len);
      return -1;
    }

    iphdr_len = sizeof(struct ipv6_hdr);

    if(!is_upper_layer(ip_header->nexthdr)) {
      debug("IPv6 extensions not supported: %d", ip_header->nexthdr);
      return -1;
    }

    pkt->tuple.src_ip.ip6 = ip_header->saddr;
    pkt->tuple.dst_ip.ip6 = ip_header->daddr;

    // Treat IPPROTO_ICMPV6 as IPPROTO_ICMP for simplicity
    ipproto = (ip_header->nexthdr != IPPROTO_ICMPV6) ? ip_header->nexthdr : IPPROTO_ICMP;
  }

  pkt->buf = pkt_buf;
  pkt->l3 = pkt_buf;
  pkt->tuple.ipproto = ipproto;
  pkt->tuple.ipver = ipver;
  pkt->pkt_len = pkt_len;
  pkt->ip_hdr_len = iphdr_len;
  pkt->l4 = &pkt_buf[iphdr_len];

  if(ipproto == IPPROTO_TCP) {
    struct tcphdr *data = pkt->tcp;
    int32_t tcp_header_len;

    if(pkt_len < (iphdr_len + MIN_TCP_HEADER_LEN)) {
      debug("Packet too small for TCP[%d]", pkt_len);
      return -1;
    }

    tcp_header_len = data->th_off * 4;

    if(pkt_len < (iphdr_len + tcp_header_len)) {
      debug("Malformed TCP packet");
      return -1;
    }

    pkt->l4_hdr_len = tcp_header_len;
    pkt->tuple.src_port = data->th_sport;
    pkt->tuple.dst_port = data->th_dport;
  } else if(ipproto == IPPROTO_UDP) {
    struct udphdr *data = pkt->udp;

    if(pkt_len < (iphdr_len + UDP_HEADER_LEN)) {
      debug("Packet too small for UDP[%d]", pkt_len);
      return -1;
    }

    pkt->l4_hdr_len = 8;
    pkt->tuple.src_port = data->uh_sport;
    pkt->tuple.dst_port = data->uh_dport;
  } else if(ipproto == IPPROTO_ICMP) {
    struct icmphdr *data = (struct icmphdr*) &pkt_buf[iphdr_len];

    if(pkt_len < (iphdr_len + sizeof(struct icmphdr))) {
      debug("Packet too small for ICMP");
      return -1;
    }

    if((data->type != ICMP_ECHO) && (data->type != ICMP_ECHOREPLY)) {
      debug("Discarding unsupported ICMP[%d]", data->type);
      return -2;
    }

    pkt->l4_hdr_len = sizeof(struct icmphdr);
    pkt->tuple.echo_id = data->un.echo.id;
    pkt->tuple.dst_port = 0;
  } else {
    debug("Packet with unknown protocol: %u", ipproto);
    return -3;
  }

  pkt->l7_len = pkt_len - iphdr_len - pkt->l4_hdr_len;
  pkt->l7 = &pkt_buf[iphdr_len + pkt->l4_hdr_len];
  return 0;
}

/* ******************************************************* */

void zdtun_set_max_window_size(zdtun_t *tun, int max_len) {
  tun->max_window_size = max_len;
}

/* ******************************************************* */

static void fill_conn_sockaddr(zdtun_conn_t *conn,
        struct sockaddr_in6 *addr6, socklen_t *addrlen) {
  if(conn->tuple.ipver == 4) {
    // struct sockaddr_in is smaller than struct sockaddr_in6
    struct sockaddr_in *addr4 = (struct sockaddr_in*)addr6;

    addr4->sin_family = AF_INET;
    addr4->sin_addr.s_addr = conn->dnat ? conn->dnat->ip.ip4 : conn->tuple.dst_ip.ip4;
    addr4->sin_port = conn->dnat ? conn->dnat->port : conn->tuple.dst_port;
    *addrlen = sizeof(struct sockaddr_in);
  } else {
    addr6->sin6_family = AF_INET6;
    addr6->sin6_addr = conn->dnat ? conn->dnat->ip.ip6 : conn->tuple.dst_ip.ip6;
    addr6->sin6_port = conn->dnat ? conn->dnat->port : conn->tuple.dst_port;
    *addrlen = sizeof(struct sockaddr_in6);
  }
}

/* ******************************************************* */

// returns 0 on success
// returns <0 on error
// no_ack: can be used to avoid sending the ACK to the client and keep
// its sequence number unchanged. This is needed to implement out of band
// data.
static int handle_tcp_fwd(zdtun_t *tun, const zdtun_pkt_t *pkt,
          zdtun_conn_t *conn, uint8_t no_ack) {
  struct tcphdr *data = pkt->tcp;
  int family = (conn->tuple.ipver == 4) ? PF_INET : PF_INET6;
  int val;

  if(conn->status == CONN_STATUS_CONNECTING) {
    debug("ignore TCP packet, we are connecting");
    return 0;
  } else if(conn->status == CONN_STATUS_NEW) {
    debug("Allocating new TCP socket for port %d", ntohs(conn->tuple.dst_port));
    socket_t tcp_sock = open_socket(tun, family, SOCK_STREAM, IPPROTO_TCP);

    if(tcp_sock == INVALID_SOCKET) {
      error("Cannot create TCP socket[%d]", socket_errno);
      conn->status = CONN_STATUS_SOCKET_ERROR;
      return -1;
    }

    conn->sock = tcp_sock;

    // Enable TCP_NODELAY to avoid slowing down the connection
    val = 1;
    if(setsockopt(tcp_sock, SOL_TCP, TCP_NODELAY, &val, sizeof(val)) < 0)
      error("setsockopt TCP_NODELAY failed");

    // Setup for the connection
    struct sockaddr_in6 servaddr = {0};
    socklen_t addrlen;
    fill_conn_sockaddr(conn, &servaddr, &addrlen);

#ifdef WIN32
    unsigned nonblocking = 1;
    ioctlsocket(tcp_sock, FIONBIO, &nonblocking);
#else
    int flags = fcntl(tcp_sock, F_GETFL);

    if(fcntl(tcp_sock, F_SETFL, flags | O_NONBLOCK) == -1)
      error("Cannot set socket non blocking: %d", errno);
#endif

    bool in_progress = false;

    // Account the SYN
    if(tun->callbacks.account_packet)
      tun->callbacks.account_packet(tun, pkt->buf, pkt->pkt_len, 1 /* to zdtun */, conn);

    // connect with the server
    if(connect(tcp_sock, (struct sockaddr *) &servaddr, addrlen) == SOCKET_ERROR) {
      if(socket_errno == socket_in_progress) {
        debug("Connection in progress");
        in_progress = true;
      } else {
        close_with_socket_error(tun, conn, "TCP connect");
        return 0;
      }
    }

    conn->tcp.client_seq = ntohl(data->th_seq) + 1;
    conn->tcp.zdtun_seq = 0x77EB77EB;

    if(!in_progress)
      return tcp_socket_syn(tun, conn);

    conn->status = CONN_STATUS_CONNECTING;
    FD_SET(tcp_sock, &tun->tcp_connecting);
    return 0;
  }

  // Here a connection is already active
  if(tun->callbacks.account_packet)
     tun->callbacks.account_packet(tun, pkt->buf, pkt->pkt_len, 1 /* to zdtun */, conn);

  if(data->th_flags & TH_RST) {
    debug("Got TCP reset from client");
    close_conn(tun, conn, CONN_STATUS_CLOSED);

    return 0;
  } else if((data->th_flags & (TH_FIN | TH_ACK)) == (TH_FIN | TH_ACK)) {
    int rv;

    debug("Got TCP FIN+ACK from client");

    if(conn->sock != INVALID_SOCKET) {
      // Half close the socket to possibly signal the remote server
      // (e.g. in after an HTTP request is completed).

      if(shutdown(conn->sock, SHUT_WR) != 0)
        debug("shutdown failed[%d] %s", errno, strerror(errno));
    }

    conn->tcp.client_seq += pkt->l7_len + 1;
    conn->tcp.client_closed = true;

    // send the ACK
    build_reply_tcpip(tun, conn, TH_ACK, 0);
    rv = send_to_client(tun, conn, MIN_TCP_HEADER_LEN);

    if(conn->sock == INVALID_SOCKET)
      // Both the client and the server have closed, terminate the connection
      close_conn(tun, conn, CONN_STATUS_CLOSED);

    return rv;
  } else if(conn->sock == INVALID_SOCKET) {
    debug("Ignore write on closed socket");
    return 0;
  }

  if(data->th_flags & TH_ACK) {
    if((uint32_t)(ntohl(data->th_seq) + 1) == conn->tcp.client_seq) {
      debug("TCP KEEPALIVE");

      if(conn->sock != INVALID_SOCKET) {
        int val = 1;

        if(setsockopt(conn->sock, SOL_SOCKET, SO_KEEPALIVE, &val, sizeof(val)) != 0)
          error("setsockopt SO_KEEPALIVE failed[%d]: %s", errno, strerror(errno));

        // Assume that the server is alive until its socket is closed.
        build_reply_tcpip(tun, conn, TH_ACK, 0);

        if(send_to_client(tun, conn, MIN_TCP_HEADER_LEN) != 0)
          return -1;
      }
    } else {
      // Received ACK from the client, update the window. Take into account
      // the in flight bytes which the client has not ACK-ed yet.
      uint32_t ack_num = ntohl(data->th_ack);
      uint32_t in_flight;

      if(conn->tcp.zdtun_seq >= ack_num)
        in_flight = conn->tcp.zdtun_seq - ack_num;
      else
        // TCP seq wrapped
        in_flight = 0xFFFFFFFF - ack_num + conn->tcp.zdtun_seq + 1;

      conn->tcp.window_size = min(ntohs(data->th_win), tun->max_window_size) - in_flight;

      if(process_pending_tcp_packets(tun, conn) != 0)
        return -1;
    }
  }

  // payload data (avoid sending ACK to an ACK)
  if(pkt->l7_len > 0) {
    if(send(conn->sock, pkt->l7, pkt->l7_len, 0) < 0)
      return close_with_socket_error(tun, conn, "TCP send");

    if(!no_ack) {
      // send the ACK
      conn->tcp.client_seq += pkt->l7_len;
      build_reply_tcpip(tun, conn, TH_ACK, 0);

      return send_to_client(tun, conn, MIN_TCP_HEADER_LEN);
    }
  }

  return 0;
}

/* ******************************************************* */

static int handle_udp_fwd(zdtun_t *tun, const zdtun_pkt_t *pkt, zdtun_conn_t *conn) {
  struct udphdr *data = pkt->udp;
  int family = (conn->tuple.ipver == 4) ? PF_INET : PF_INET6;

  if(conn->status == CONN_STATUS_NEW) {
    socket_t udp_sock = open_socket(tun, family, SOCK_DGRAM, IPPROTO_UDP);
    debug("Allocating new UDP socket for port %d", ntohs(data->uh_sport));

    if(udp_sock == INVALID_SOCKET) {
      error("Cannot create UDP socket[%d]", socket_errno);
      return -1;
    }

    conn->sock = udp_sock;
    conn->status = CONN_STATUS_CONNECTED;
  }

  if(tun->callbacks.account_packet)
    tun->callbacks.account_packet(tun, pkt->buf, pkt->pkt_len, 1 /* to zdtun */, conn);

  struct sockaddr_in6 servaddr = {0};
  socklen_t addrlen;
  fill_conn_sockaddr(conn, &servaddr, &addrlen);

  if(sendto(conn->sock, pkt->l7, pkt->l7_len, 0, (struct sockaddr*)&servaddr, addrlen) < 0) {
    close_with_socket_error(tun, conn, "UDP sendto");
    return 0;
  }

  check_dns_request(conn, pkt->l7, pkt->l7_len);

  return 0;
}

/* ******************************************************* */

/* NOTE: a collision may occure between ICMP packets seq from host and tunneled packets, we ignore it */
static int handle_icmp_fwd(zdtun_t *tun, const zdtun_pkt_t *pkt, zdtun_conn_t *conn) {
  struct icmphdr *data = pkt->icmp;
  const uint16_t icmp_len = pkt->l4_hdr_len + pkt->l7_len;

  // NOTE: PF_INET6 is not currently supported by SOCK_DGRAM ICMP
  int family = (conn->tuple.ipver == 4) ? PF_INET : PF_INET6;

  if(conn->status == CONN_STATUS_NEW) {
    /*
     * Either a SOCK_RAW or SOCK_DGRAM can be used. The SOCK_DGRAM, however, does not require root
     * privileges, so it is a better choice (also for Android). See https://lwn.net/Articles/443051
     * for more details.
     *
     * However the SOCK_DGRAM:
     *  - Contrary to the RAW socket, requires a separate socket per ICMP connection.
     *  - The reply received via recv misses the IP header.
     *  - Does not honor all the ICMP header fields (e.g. the ICMP echo ID).
     */
    socket_t icmp_sock = open_socket(tun, family, SOCK_DGRAM, IPPROTO_ICMP);
    debug("Allocating new ICMP socket for id %d", ntohs(data->un.echo.id));

    if(icmp_sock == INVALID_SOCKET) {
      error("Cannot create ICMP socket[%d]", socket_errno);
      conn->status = CONN_STATUS_SOCKET_ERROR;
      return -1;
    }

    conn->sock = icmp_sock;
    conn->status = CONN_STATUS_CONNECTED;
    conn->tuple.src_port = data->un.echo.id;
  }

  debug("ICMP.fw[len=%u] id=%d seq=%d type=%d code=%d", icmp_len, data->un.echo.id,
          data->un.echo.sequence, data->type, data->code);

  if(tun->callbacks.account_packet)
    tun->callbacks.account_packet(tun, pkt->buf, pkt->pkt_len, 1 /* to zdtun */, conn);

  struct sockaddr_in6 servaddr = {0};
  socklen_t addrlen;
  fill_conn_sockaddr(conn, &servaddr, &addrlen);

  if(sendto(conn->sock, data, icmp_len, 0, (struct sockaddr*)&servaddr, addrlen) < 0) {
    close_with_socket_error(tun, conn, "ICMP sendto");
    return -1;
  }

  return 0;
}

/* ******************************************************* */

static int zdtun_forward_full(zdtun_t *tun, const zdtun_pkt_t *pkt, zdtun_conn_t *conn, uint8_t no_ack) {
  int rv = 0;

  if(conn->status >= CONN_STATUS_CLOSED) {
    debug("Refusing to forward closed connection");
    return 0;
  }

  switch(pkt->tuple.ipproto) {
    case IPPROTO_TCP:
      rv = handle_tcp_fwd(tun, pkt, conn, no_ack);
      break;
    case IPPROTO_UDP:
      rv = handle_udp_fwd(tun, pkt, conn);
      break;
    case IPPROTO_ICMP:
      rv = handle_icmp_fwd(tun, pkt, conn);
      break;
    default:
      error("Ignoring unhandled IP protocol %d", pkt->tuple.ipproto);
      return -2;
  }

  if(rv == 0) {
    conn->tstamp = time(NULL);

    if(conn->status == CONN_STATUS_NEW)
      error("Connection status must not be CONN_STATUS_NEW here!");
  }

  return rv;
}

/* ******************************************************* */

int zdtun_forward(zdtun_t *tun, const zdtun_pkt_t *pkt, zdtun_conn_t *conn) {
  return zdtun_forward_full(tun, pkt, conn, 0 /* send ACK to the client */);
}

/* ******************************************************* */

int zdtun_send_oob(zdtun_t *tun, const zdtun_pkt_t *pkt, zdtun_conn_t *conn) {
  return zdtun_forward_full(tun, pkt, conn, 1 /* do not send ACK to the client */);
}

/* ******************************************************* */

zdtun_conn_t* zdtun_easy_forward(zdtun_t *tun, const char *pkt_buf, int pkt_len) {
  zdtun_pkt_t pkt;

  if(zdtun_parse_pkt(pkt_buf, pkt_len, &pkt) != 0) {
    debug("zdtun_easy_forward: zdtun_parse_pkt failed");
    return NULL;
  }

  uint8_t is_tcp_established = ((pkt.tuple.ipproto == IPPROTO_TCP) &&
    (!(pkt.tcp->th_flags & TH_SYN) || (pkt.tcp->th_flags & TH_ACK)));

  zdtun_conn_t *conn = zdtun_lookup(tun, &pkt.tuple, !is_tcp_established);

  if(!conn) {
    if(is_tcp_established) {
      debug("TCP: ignoring non SYN connection");
    } else {
      debug("zdtun_lookup failed");
    }

    return NULL;
  }

  if(zdtun_forward(tun, &pkt, conn) != 0) {
    debug("zdtun_forward failed");

    /* Destroy the connection as soon an any error occurs */
    zdtun_destroy_conn(tun, conn);
    return NULL;
  }

  return conn;
}

/* ******************************************************* */

static int handle_icmp_reply(zdtun_t *tun, zdtun_conn_t *conn) {
  int iphdr_len = (conn->tuple.ipver == 4) ? IPV4_HEADER_LEN : IPV6_HEADER_LEN;
  int icmp_len = recv(conn->sock, tun->reply_buf + iphdr_len,
          REPLY_BUF_SIZE - iphdr_len, 0);

  if(icmp_len == SOCKET_ERROR) {
    close_with_socket_error(tun, conn, "ICMP recv");
    return -1;
  }

  if(icmp_len < sizeof(struct icmphdr)) {
    error("ICMP packet too small[%d]", icmp_len);
    close_conn(tun, conn, CONN_STATUS_ERROR);
    return -1;
  }

  struct icmphdr *data = (struct icmphdr*) &tun->reply_buf[iphdr_len];

  if((data->type != ICMP_ECHO) && (data->type != ICMP_ECHOREPLY)) {
    debug("Discarding unsupported ICMP[%d]", data->type);
    close_conn(tun, conn, CONN_STATUS_ERROR);
    return 0;
  }

  // Reset the correct ID (the kernel changes it)
  data->un.echo.id = conn->tuple.echo_id;

  debug("ICMP.re[len=%d] id=%d seq=%d type=%d code=%d", icmp_len, data->un.echo.id,
          data->un.echo.sequence, data->type, data->code);

  conn->tstamp = time(NULL);

  data->checksum = 0;
  data->checksum = ~calc_checksum(data->checksum, (u_int8_t*)data, icmp_len);

  build_reply_ip(conn, tun->reply_buf, icmp_len);

  return send_to_client(tun, conn, icmp_len);
}

/* ******************************************************* */

static int handle_tcp_reply(zdtun_t *tun, zdtun_conn_t *conn) {
  int iphdr_len = (conn->tuple.ipver == 4) ? IPV4_HEADER_LEN : IPV6_HEADER_LEN;
  char *payload_ptr = tun->reply_buf + iphdr_len + MIN_TCP_HEADER_LEN;
  int l4_len = recv(conn->sock, payload_ptr, REPLY_BUF_SIZE - iphdr_len - MIN_TCP_HEADER_LEN, 0);

  conn->tstamp = time(NULL);

  if(l4_len == SOCKET_ERROR)
    return close_with_socket_error(tun, conn, "TCP recv");
  else if(l4_len == 0) {
    debug("Server socket closed");

    if(conn->tcp.pending)
      log("[WARNING]: This should never happen!!");

    if(!conn->tcp.fin_ack_sent) {
      tcp_socket_fin_ack(tun, conn);
      conn->tcp.fin_ack_sent = true;
    }

    // close the socket, otherwise select will keep triggering
    // The client communication can still go on (e.g. client sending ACK to FIN+ACK)
    close_socket(tun, conn->sock);
    conn->sock = INVALID_SOCKET;

    if(conn->tcp.client_closed)
      // Both the client and the server have closed, terminate the connection
      close_conn(tun, conn, CONN_STATUS_CLOSED);

    return 0;
  }

  if((conn->tcp.pending) || (conn->tcp.window_size < l4_len)) {
    log_tcp_window("[%d] Insufficient window size detected [window=%d, l4=%d, pending=%d], queuing",
        conn->tuple.src_port, conn->tcp.window_size, l4_len, (conn->tcp.pending ? conn->tcp.pending->size : 0));

    struct tcp_pending_data *pending = conn->tcp.pending;

    if(!pending) {
      safe_alloc(pending, struct tcp_pending_data);
      pending->size = 0;
      pending->data = NULL;
      conn->tcp.pending = pending;
    }

    pending->data = (char*) realloc(pending->data, pending->size + l4_len);

    if(!pending->data)
        fatal("realloc tcp.pending_data failed");

    memcpy(pending->data + pending->size, payload_ptr, l4_len);
    pending->size += l4_len;

    // stop receiving updates for the socket
    FD_CLR(conn->sock, &tun->all_fds);

    // try to send a little bit of data right now
    return process_pending_tcp_packets(tun, conn);
  }

  // NAT back the TCP port and reconstruct the TCP header
  build_reply_tcpip(tun, conn, TH_PUSH | TH_ACK, l4_len);

  if(send_to_client(tun, conn, l4_len + MIN_TCP_HEADER_LEN) == 0) {
    conn->tcp.zdtun_seq += l4_len;
    conn->tcp.window_size -= l4_len;
  } else
    return -1;

  return 0;
}

/* ******************************************************* */

static int handle_udp_reply(zdtun_t *tun, zdtun_conn_t *conn) {
  int iphdr_len = (conn->tuple.ipver == 4) ? IPV4_HEADER_LEN : IPV6_HEADER_LEN;
  char *payload_ptr = tun->reply_buf + iphdr_len + sizeof(struct udphdr);
  int l4_len = recv(conn->sock, payload_ptr, REPLY_BUF_SIZE-iphdr_len-sizeof(struct udphdr), 0);

  if(l4_len == SOCKET_ERROR) {
    close_with_socket_error(tun, conn, "UDP recv");
    return -1;
  }

  // Reconstruct the UDP header
  int l3_len = l4_len + sizeof(struct udphdr);
  struct udphdr *data = (struct udphdr*) (tun->reply_buf + iphdr_len);
  data->uh_ulen = htons(l3_len);
  data->uh_sport = conn->tuple.dst_port;

  // NAT back the UDP port
  data->uh_dport = conn->tuple.src_port;

  // NOTE: UDP checksum not calculated, it is optional
  data->uh_sum = 0;

  build_reply_ip(conn, tun->reply_buf, l3_len);

  int rv = send_to_client(tun, conn, l3_len);

  if(rv == 0) {
    // ok
    conn->tstamp = time(NULL);

    check_dns_purge(tun, conn, payload_ptr, l4_len);
  }

  return rv;
}

/* ******************************************************* */

static int handle_tcp_connect_async(zdtun_t *tun, zdtun_conn_t *conn) {
  int optval = -1;
  socklen_t optlen = sizeof (optval);
  int rv = 0;

  if(getsockopt(conn->sock, SOL_SOCKET, SO_ERROR, (char*)&optval, &optlen) == SOCKET_ERROR) {
    error("getsockopt failed: %d", socket_errno);

    close_conn(tun, conn, CONN_STATUS_SOCKET_ERROR);
    rv = -1;
  } else {
    if(optval == 0) {
      debug("TCP non-blocking socket connected");
      tcp_socket_syn(tun, conn);
      conn->tstamp = time(NULL);
    } else {
      close_with_socket_error(tun, conn, "TCP non-blocking connect");
      rv = -1;
    }
  }

  return rv;
}

/* ******************************************************* */

int zdtun_handle_fd(zdtun_t *tun, const fd_set *rd_fds, const fd_set *wr_fds) {
  int num_hits = 0;
  zdtun_conn_t *conn, *tmp;

  HASH_ITER(hh, tun->conn_table, conn, tmp) {
    uint8_t ipproto = conn->tuple.ipproto;
    int rv = 0;

    if(conn->sock == INVALID_SOCKET)
      continue;

    if(FD_ISSET(conn->sock, rd_fds)) {
      if(ipproto == IPPROTO_TCP)
        rv = handle_tcp_reply(tun, conn);
      else if(ipproto == IPPROTO_UDP)
        rv = handle_udp_reply(tun, conn);
      else if(ipproto == IPPROTO_ICMP)
        rv = handle_icmp_reply(tun, conn);
      else
        error("Unhandled socket.rd proto: %d", ipproto);

      num_hits++;
    } else if(FD_ISSET(conn->sock, wr_fds)) {
      if(ipproto == IPPROTO_TCP)
        rv = handle_tcp_connect_async(tun, conn);
      else
        error("Unhandled socket.wr proto: %d", ipproto);

      num_hits++;
    }

    if(rv != 0)
      break;
  }

  return num_hits;
}

/* ******************************************************* */

// negative, zero, or positive <=> A before, equal to, or after B
static inline int zdtun_conn_cmp_timestamp_asc(zdtun_conn_t *a, zdtun_conn_t *b) {
  return(a->tstamp - b->tstamp);
}

// purges old connections. Harvests the closed connections (set by close_conn)
// and purges them (assuming no dangling pointers around).
void zdtun_purge_expired(zdtun_t *tun, time_t now) {
  zdtun_conn_t *conn, *tmp;

  /* Purge by idleness */
  HASH_ITER(hh, tun->conn_table, conn, tmp) {
    time_t timeout = 0;

    switch(conn->tuple.ipproto) {
    case IPPROTO_TCP:
      timeout = TCP_TIMEOUT_SEC;
      break;
    case IPPROTO_UDP:
      timeout = UDP_TIMEOUT_SEC;
      break;
    case IPPROTO_ICMP:
      timeout = ICMP_TIMEOUT_SEC;
      break;
    }

    if((conn->status >= CONN_STATUS_CLOSED) || (now >= (timeout + conn->tstamp))) {
      debug("IDLE (type=%d)", conn->tuple.ipproto);
      zdtun_destroy_conn(tun, conn);
    }
  }

  if(tun->stats.num_open_sockets >= MAX_NUM_SOCKETS) {
    int to_purge = tun->stats.num_open_sockets - NUM_SOCKETS_AFTER_PURGE;

    debug("FORCE PURGE %d items", to_purge);

    HASH_SORT(tun->conn_table, zdtun_conn_cmp_timestamp_asc);

    HASH_ITER(hh, tun->conn_table, conn, tmp) {
      if(to_purge == 0)
        break;

      zdtun_destroy_conn(tun, conn);
      to_purge--;
    }
  }
}

/* ******************************************************* */

int zdtun_iter_connections(zdtun_t *tun, zdtun_conn_iterator_t iterator, void *userdata) {
  zdtun_conn_t *conn, *tmp;

  HASH_ITER(hh, tun->conn_table, conn, tmp) {
    // Do not iterate closed connections. User may have already free some data in
    // on_connection_close so this may lead to invalid memory access.
    if(conn->status < CONN_STATUS_CLOSED) {
      if(iterator(tun, conn, userdata) != 0)
        return(1);
    }
  }

  return(0);
}

/* ******************************************************* */

int zdtun_get_num_connections(zdtun_t *tun) {
  return(tun->stats.num_tcp_conn + tun->stats.num_udp_conn + tun->stats.num_icmp_conn);
}

/* ******************************************************* */

void zdtun_get_stats(zdtun_t *tun, zdtun_statistics_t *stats) {
  *stats = tun->stats;
}

/* ******************************************************* */

const char* zdtun_proto2str(int ipproto) {
  switch (ipproto) {
    case IPPROTO_TCP:
        return "TCP";
    case IPPROTO_UDP:
        return "UDP";
    case IPPROTO_ICMP:
        return "ICMP";
    default:
        return "Unknown";
  }
}

/* ******************************************************* */

char* zdtun_5tuple2str(const zdtun_5tuple_t *tuple, char *buf, size_t bufsize) {
    char srcip[INET6_ADDRSTRLEN];
    char dstip[INET6_ADDRSTRLEN];
    int family = (tuple->ipver == 4) ? AF_INET : AF_INET6;

    inet_ntop(family, &tuple->src_ip, srcip, sizeof(srcip));
    inet_ntop(family, &tuple->dst_ip, dstip, sizeof(dstip));

    snprintf(buf, bufsize, "[%s%c] %s:%u -> %s:%u",
             zdtun_proto2str(tuple->ipproto),
             (tuple->ipver == 4) ? '4' : '6',
             srcip, ntohs(tuple->src_port),
             dstip, ntohs(tuple->dst_port));

    return buf;
}

/* ******************************************************* */

const char* zdtun_conn_status2str(zdtun_conn_status_t status) {
  switch(status) {
    case CONN_STATUS_NEW:
      return "NEW";
    case CONN_STATUS_CONNECTING:
      return "CONNECTING";
    case CONN_STATUS_CONNECTED:
      return "CONNECTED";
    case CONN_STATUS_CLOSED:
      return "CLOSED";
    case CONN_STATUS_ERROR:
      return "ERROR";
    case CONN_STATUS_SOCKET_ERROR:
      return "SOCKET_ERROR";
    case CONN_STATUS_CLIENT_ERROR:
      return "CLIENT_ERROR";
    case CONN_STATUS_RESET:
      return "RESET";
    case CONN_STATUS_UNREACHABLE:
      return "UNREACHABLE";
  }

  return "UNKNOWN";
}
