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
#define UDP_HEADER_LEN 8

#define ICMP_TIMEOUT_SEC 5
#define UDP_TIMEOUT_SEC 30
#define TCP_TIMEOUT_SEC 60

// 64 is the per-thread limit on Winsocks
// use a lower value to leave room for user defined connections
#define MAX_NUM_SOCKETS 55
#define NUM_SOCKETS_AFTER_PURGE 40

/* ******************************************************* */

typedef enum {
  CONN_STATUS_NEW = 0,
  CONN_STATUS_CONNECTING,
  CONN_STATUS_CONNECTED
} conn_status_t;

/* ******************************************************* */

struct tcp_pending_data {
  char *data;
  u_int16_t size;
  u_int16_t sofar;
};

typedef struct zdtun_conn {
  zdtun_5tuple_t tuple;
  time_t tstamp;
  socket_t sock;
  conn_status_t status;

  /* NAT information */
  u_int32_t dnat_ip;
  u_int16_t dnat_port;

  union {
    struct {
      u_int32_t client_seq;    // next client sequence number
      u_int32_t zdtun_seq;     // next proxy sequence number
      u_int16_t window_size;   // client window size
      struct tcp_pending_data *pending;
    } tcp;
    struct {
      u_int16_t echo_id;
      u_int16_t echo_seq;
    } icmp;
  };

  void *user_data;
  UT_hash_handle hh;  // tuple -> conn
} zdtun_conn_t;

/* ******************************************************* */

typedef struct zdtun_t {
  struct zdtun_callbacks callbacks;
  void *user_data;
  fd_set all_fds;
  fd_set tcp_connecting;
  int all_max_fd;
  int num_open_socks;
  int num_active_connections;
  u_int32_t num_icmp_opened;
  u_int32_t num_tcp_opened;
  u_int32_t num_udp_opened;
#ifndef ZDTUN_SKIP_ICMP
  socket_t icmp_socket;
#endif
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

void zdtun_fds(zdtun_t *tun, int *max_fd, fd_set *rdfd, fd_set *wrfd) {
  *max_fd = tun->all_max_fd;
  *rdfd = tun->all_fds;
  *wrfd = tun->tcp_connecting;
}

/* ******************************************************* */

static socket_t open_socket(zdtun_t *tun, int domain, int type, int protocol) {
  socket_t sock = socket(domain, type, protocol);

  if((sock != INVALID_SOCKET) && tun->callbacks.on_socket_open)
    tun->callbacks.on_socket_open(tun, sock);

  return(sock);
}

/* ******************************************************* */

static int close_socket(zdtun_t *tun, socket_t sock) {
  int rv = closesocket(sock);

  if((rv == 0) && tun->callbacks.on_socket_close)
    tun->callbacks.on_socket_close(tun, sock);

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

int zdtun_conn_dnat(zdtun_conn_t *conn, uint32_t dest_ip, uint16_t dest_port) {
  conn->dnat_ip = dest_ip;
  conn->dnat_port = dest_port;
  return 0;
}

const zdtun_5tuple_t* zdtun_conn_get_5tuple(const zdtun_conn_t *conn) {
  return &conn->tuple;
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
  memcpy(&tun->callbacks, callbacks, sizeof(tun->callbacks));

  FD_ZERO(&tun->all_fds);
  FD_ZERO(&tun->tcp_connecting);

#ifndef ZDTUN_SKIP_ICMP
  /* NOTE:
   *  - on linux, socket(PF_INET, SOCK_DGRAM, IPPROTO_ICMP) is not permitted
   *  - on Android, socket(PF_INET, SOCK_RAW, IPPROTO_ICMP) is not permitted
   *
   * Supporting a SOCK_DGRAM requires some changes as the IP data is missing
   * and sendto must be used.
   */
  tun->icmp_socket = open_socket(tun, PF_INET, SOCK_RAW, IPPROTO_ICMP);

  if(tun->icmp_socket == INVALID_SOCKET) {
    error("Cannot create ICMP socket[%d]", socket_errno);
    free(tun);
    return NULL;
  } else {
    FD_SET(tun->icmp_socket, &tun->all_fds);
#ifndef WIN32
    tun->all_max_fd = max(tun->all_max_fd, tun->icmp_socket);
#endif
    tun->num_open_socks++;
  }
#endif

  return tun;
}

/* ******************************************************* */

void ztdun_finalize(zdtun_t *tun) {
  zdtun_conn_t *conn, *tmp;

  HASH_ITER(hh, tun->conn_table, conn, tmp) {
    zdtun_destroy_conn(tun, conn);
  }

#ifndef ZDTUN_SKIP_ICMP
  if(tun->icmp_socket)
    close_socket(tun, tun->icmp_socket);
#endif

  free(tun);
}

/* ******************************************************* */

static inline int send_to_client(zdtun_t *tun, const zdtun_conn_t *conn, size_t size) {
  int rv = tun->callbacks.send_client(tun, tun->reply_buf, size, conn);

  if(tun->callbacks.account_packet)
      tun->callbacks.account_packet(tun, tun->reply_buf, size, 0 /* from zdtun */, conn);

  return(rv);
}

/* ******************************************************* */

static inline void finalize_zdtun_sock(zdtun_t *tun, zdtun_conn_t *conn) {
  close_socket(tun, conn->sock);
  FD_CLR(conn->sock, &tun->all_fds);
  FD_CLR(conn->sock, &tun->tcp_connecting);

#ifndef WIN32
  tun->all_max_fd = max(tun->all_max_fd, conn->sock-1);
#endif
  tun->num_open_socks--;

  // mark as closed
  conn->sock = 0;
}

/* ******************************************************* */

static inline int build_ip_header_raw(char *pkt_buf, u_int16_t tot_len, uint l3_proto, u_int32_t srcip, u_int32_t dstip) {
  struct iphdr *ip_header = (struct iphdr*)pkt_buf;

  memset(ip_header, 0, 20);
  ip_header->ihl = 5; // 5 * 4 = 20 = ZDTUN_IP_HEADER_SIZE
  ip_header->version = 4;
  ip_header->frag_off = htons(0x4000); // don't fragment
  ip_header->tot_len = htons(tot_len);
  ip_header->ttl = 64; // hops
  ip_header->protocol = l3_proto;
  ip_header->saddr = srcip;
  ip_header->daddr = dstip;

  return 0;
}

/* ******************************************************* */

#define build_ip_header(conn, pkt_buf, l3_len, l3_proto)\
  build_ip_header_raw(pkt_buf, l3_len + ZDTUN_IP_HEADER_SIZE, l3_proto, conn->tuple.dst_ip, conn->tuple.src_ip)

static inline void build_tcp_ip_header(zdtun_t *tun, zdtun_conn_t *conn, u_int8_t flags, u_int16_t l4_len) {
  const u_int16_t l3_len = l4_len + MIN_TCP_HEADER_LEN;
  struct tcphdr *tcp_synack = (struct tcphdr *)&tun->reply_buf[ZDTUN_IP_HEADER_SIZE];
  memset(tcp_synack, 0, MIN_TCP_HEADER_LEN);
  tcp_synack->th_sport = conn->tuple.dst_port;
  tcp_synack->th_dport = conn->tuple.src_port;
  tcp_synack->th_seq = htonl(conn->tcp.zdtun_seq);
  tcp_synack->th_ack = (flags & TH_ACK) ? htonl(conn->tcp.client_seq) : 0;
  tcp_synack->th_off = 5;
  tcp_synack->th_flags = flags;
  tcp_synack->th_win = htons(TCP_WINDOW_SIZE);

  build_ip_header(conn, tun->reply_buf, l3_len, IPPROTO_TCP);
  struct iphdr *ip_header = (struct iphdr*) tun->reply_buf;

  // TCP checksum (no data)
  tcp_synack->th_sum = 0;
#if 0
  tcp_synack->th_sum = wrapsum(in_cksum((char*)tcp_synack, MIN_TCP_HEADER_LEN, // TCP header
    in_cksum((char*)&ip_header->saddr, 8,      // Source + Dest IP
        IPPROTO_TCP + l3_len                   // Protocol + TCP Total Length
  )));
#else
  // this is more efficient then the multiple in_cksum
  tcp_synack->th_sum = tcp_checksum(tcp_synack, l3_len, ip_header->saddr, ip_header->daddr);
#endif

  ip_header->check = 0;
  ip_header->check = ip_checksum(ip_header, ZDTUN_IP_HEADER_SIZE);
}

/* ******************************************************* */

void zdtun_destroy_conn(zdtun_t *tun, zdtun_conn_t *conn) {
  debug("PURGE SOCKET (type=%d)", conn->tuple.ipproto);

  if(conn->tuple.ipproto == IPPROTO_TCP) {
    // Send TCP RST
    build_tcp_ip_header(tun, conn, TH_RST | TH_ACK, 0);
    send_to_client(tun, conn, MIN_TCP_HEADER_LEN + ZDTUN_IP_HEADER_SIZE);
  }

  if(conn->sock)
    finalize_zdtun_sock(tun, conn);

  if(conn->tcp.pending) {
    free(conn->tcp.pending->data);
    free(conn->tcp.pending);
  }

  if(tun->callbacks.on_connection_close)
    tun->callbacks.on_connection_close(tun, conn);

  tun->num_active_connections--;

  HASH_DELETE(hh, tun->conn_table, conn);
  free(conn);
}

/* ******************************************************* */

static int tcp_socket_syn(zdtun_t *tun, zdtun_conn_t *conn) {
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
  build_tcp_ip_header(tun, conn, TH_SYN | TH_ACK, 0);
  conn->tcp.zdtun_seq += 1;

  return send_to_client(tun, conn, MIN_TCP_HEADER_LEN + ZDTUN_IP_HEADER_SIZE);
}

/* ******************************************************* */

static void tcp_socket_fin_ack(zdtun_t *tun, zdtun_conn_t *conn) {
  build_tcp_ip_header(tun, conn, TH_FIN | TH_ACK, 0);
  conn->tcp.zdtun_seq += 1;

  send_to_client(tun, conn, MIN_TCP_HEADER_LEN + ZDTUN_IP_HEADER_SIZE);
}

/* ******************************************************* */

zdtun_conn_t* zdtun_lookup(zdtun_t *tun, const zdtun_5tuple_t *tuple, uint8_t create) {
  zdtun_conn_t *conn = NULL;

  HASH_FIND(hh, tun->conn_table, tuple, sizeof(*tuple), conn);

  if(!conn && create) {
    /* Add a new connection */
    safe_alloc(conn, zdtun_conn_t);
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

    tun->num_active_connections++;

    if(tun->num_open_socks >= MAX_NUM_SOCKETS) {
      debug("Force purge!");
      zdtun_purge_expired(tun, time(NULL));
    }
  }

  return conn;
}

/* ******************************************************* */

static void process_pending_tcp_packets(zdtun_t *tun, zdtun_conn_t *conn) {
  struct tcp_pending_data *pending = conn->tcp.pending;

  if(!conn->tcp.window_size || !pending || !conn->sock)
    return;

  u_int16_t remaining = pending->size - pending->sofar;
  u_int16_t to_send = min(conn->tcp.window_size, remaining);

  log_tcp_window("Sending %d/%d bytes pending data", to_send, remaining);
  memcpy(tun->reply_buf + MIN_TCP_HEADER_LEN + ZDTUN_IP_HEADER_SIZE, &pending->data[pending->sofar], to_send);

  // proxy back the TCP port and reconstruct the TCP header
  build_tcp_ip_header(tun, conn, TH_PUSH | TH_ACK, to_send);
  send_to_client(tun, conn, to_send + MIN_TCP_HEADER_LEN + ZDTUN_IP_HEADER_SIZE);

  conn->tcp.zdtun_seq += to_send;
  conn->tcp.window_size -= to_send;

  if(remaining == to_send) {
    free(pending->data);
    free(pending);
    conn->tcp.pending = NULL;

    // make the socket selectable again
    FD_SET(conn->sock, &tun->all_fds);
  } else
    pending->sofar += to_send;
}

/* ******************************************************* */

int zdtun_parse_pkt(const char *_pkt_buf, uint16_t pkt_len, zdtun_pkt_t *pkt) {
  char *pkt_buf = (char *)_pkt_buf; /* needed to set the zdtun_pkt_t pointers */
  struct iphdr *ip_header = (struct iphdr*) pkt_buf;
  int ip_hdr_len;

  if(ip_header->version != 4) {
    debug("Ignoring non IPv4 packet: %d", ip_header->version);
    return -1;
  }

  ip_hdr_len = ip_header->ihl * 4;

  if(pkt_len < ip_hdr_len) {
    debug("Malformed IP packet");
    return -1;
  }

  pkt->buf = pkt_buf;
  pkt->l3 = pkt_buf;
  pkt->tuple.src_ip = ip_header->saddr;
  pkt->tuple.dst_ip = ip_header->daddr;
  pkt->tuple.ipproto = ip_header->protocol;
  pkt->pkt_len = pkt_len;
  pkt->ip_hdr_len = ip_hdr_len;
  pkt->l4 = &pkt_buf[ip_hdr_len];

  if(ip_header->protocol == IPPROTO_TCP) {
    struct tcphdr *data = pkt->tcp;
    int32_t tcp_header_len;

    if(pkt_len < (ip_hdr_len + MIN_TCP_HEADER_LEN)) {
      debug("Packet too small for TCP[%d]", pkt_len);
      return -1;
    }

    tcp_header_len = data->th_off * 4;

    if(pkt_len < (ip_hdr_len + tcp_header_len)) {
      debug("Malformed TCP packet");
      return -1;
    }

    pkt->l4_hdr_len = tcp_header_len;
    pkt->tuple.src_port = data->th_sport;
    pkt->tuple.dst_port = data->th_dport;
  } else if(ip_header->protocol == IPPROTO_UDP) {
    struct udphdr *data = pkt->udp;

    if(pkt_len < (ip_hdr_len + UDP_HEADER_LEN)) {
      debug("Packet too small for UDP[%d]", pkt_len);
      return -1;
    }

    pkt->l4_hdr_len = 8;
    pkt->tuple.src_port = data->uh_sport;
    pkt->tuple.dst_port = data->uh_dport;
  } else if(ip_header->protocol == IPPROTO_ICMP) {
    struct icmphdr *data = (struct icmphdr*) &pkt_buf[ip_hdr_len];

    if(pkt_len < (ip_hdr_len + sizeof(struct icmphdr))) {
      debug("Packet too small for ICMP");
      return -1;
    }

    if((data->type != ICMP_ECHO) && (data->type != ICMP_ECHOREPLY)) {
      log_packet("Discarding unsupported ICMP[%d]", data->type);
      return -2;
    }

    pkt->l4_hdr_len = sizeof(struct icmphdr);
    pkt->tuple.echo_id = data->un.echo.id;
    pkt->tuple.echo_seq = data->un.echo.sequence;
  } else {
    debug("Packet with unknown protocol: %u", ip_header->protocol);
    return -3;
  }

  pkt->l7_len = pkt_len - ip_hdr_len - pkt->l4_hdr_len;
  pkt->l7 = &pkt_buf[ip_hdr_len + pkt->l4_hdr_len];
  return 0;
}

/* ******************************************************* */

// returns >=0 on success
// returns <0 on error
// no_ack: can be used to avoid sending the ACK to the client and keep
// its sequence number unchanged. This is needed to implement out of band
// data.
static int handle_tcp_fwd(zdtun_t *tun, const zdtun_pkt_t *pkt,
          zdtun_conn_t *conn, uint8_t no_ack) {
  char buf1[INET_ADDRSTRLEN], buf2[INET_ADDRSTRLEN];
  struct tcphdr *data = pkt->tcp;

  debug("[TCP]-> %s:%d -> %s:%d",
    ipv4str(conn->tuple.src_ip, buf1), ntohs(conn->tuple.src_port),
    ipv4str(conn->tuple.dst_ip, buf2), ntohs(conn->tuple.dst_port));

  if(conn->status == CONN_STATUS_CONNECTING) {
    debug("ignore TCP packet, we are connecting");
    return 0;
  } else if(conn->status == CONN_STATUS_NEW) {
    debug("Allocating new TCP socket for port %d", ntohs(conn->tuple.dst_port));
    socket_t tcp_sock = open_socket(tun, PF_INET, SOCK_STREAM, IPPROTO_TCP);

    if(tcp_sock == INVALID_SOCKET) {
      error("Cannot create TCP socket[%d]", socket_errno);
      return -1;
    }

    tun->num_tcp_opened++;

    // Setup for the connection
    struct sockaddr_in servaddr = {0};
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr =  conn->dnat_ip ? conn->dnat_ip : conn->tuple.dst_ip;
    servaddr.sin_port = conn->dnat_port ? conn->dnat_port : conn->tuple.dst_port;

#ifdef WIN32
    unsigned nonblocking = 1;
    ioctlsocket(tcp_sock, FIONBIO, &nonblocking);
#else
    int flags = fcntl(tcp_sock, F_GETFL);

    if(fcntl(tcp_sock, F_SETFL, flags | O_NONBLOCK) == -1)
      error("Cannot set socket non blocking: %d", errno);
#endif

    bool in_progress = false;

    // connect with the server
    if(connect(tcp_sock, (struct sockaddr *) &servaddr, sizeof(struct sockaddr_in)) == SOCKET_ERROR) {
      if(socket_errno == socket_in_progress) {
        debug("Connection in progress");
        in_progress = true;
      } else {
        log("TCP connection error");
        close_socket(tun, tcp_sock);
        return -1;
      }
    }

    FD_SET(tcp_sock, &tun->all_fds);
    conn->sock = tcp_sock;
    conn->tcp.client_seq = ntohl(data->th_seq) + 1;
    conn->tcp.zdtun_seq = 0x77EB77EB;

    if(tun->callbacks.account_packet)
      tun->callbacks.account_packet(tun, pkt->buf, pkt->pkt_len, 1 /* to zdtun */, conn);

#ifndef WIN32
    tun->all_max_fd = max(tun->all_max_fd, tcp_sock);
#endif
    tun->num_open_socks++;

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
    return 1;
  } else if((data->th_flags & (TH_FIN | TH_ACK)) == (TH_FIN | TH_ACK)) {
    debug("Got TCP FIN+ACK from client");

    conn->tcp.client_seq += pkt->l7_len + 1;
    build_tcp_ip_header(tun, conn, TH_FIN | TH_ACK, 0);

    send_to_client(tun, conn, MIN_TCP_HEADER_LEN + ZDTUN_IP_HEADER_SIZE);
    return 1;
  } else if(!conn->sock) {
    debug("Ignore write on closed socket");
    return 1;
  }

  if(data->th_flags & TH_ACK) {
    conn->tcp.window_size = (conn->tcp.zdtun_seq - ntohl(data->th_ack)) + ntohs(data->th_win);
    process_pending_tcp_packets(tun, conn);
  }

  // payload data (avoid sending ACK to an ACK)
  if(pkt->l7_len > 0) {
    if(send(conn->sock, pkt->l7, pkt->l7_len, 0) < 0) {
      error("TCP send error[%d]", socket_errno);
      return -1;
    }

    if(!no_ack) {
      // send the ACK
      conn->tcp.client_seq += pkt->l7_len;
      build_tcp_ip_header(tun, conn, TH_ACK, 0);

      return send_to_client(tun, conn, MIN_TCP_HEADER_LEN + ZDTUN_IP_HEADER_SIZE);
    }
  }

  return 0;
}

/* ******************************************************* */

static int handle_udp_fwd(zdtun_t *tun, const zdtun_pkt_t *pkt, zdtun_conn_t *conn) {
  struct udphdr *data = pkt->udp;

  char buf1[INET_ADDRSTRLEN], buf2[INET_ADDRSTRLEN];

  debug("[UDP]-> %s:%d -> %s:%d",
    ipv4str(conn->tuple.src_ip, buf1), ntohs(conn->tuple.src_port),
    ipv4str(conn->tuple.dst_ip, buf2), ntohs(conn->tuple.dst_port));

  if(conn->status == CONN_STATUS_NEW) {
    socket_t udp_sock = open_socket(tun, PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    debug("Allocating new UDP socket for port %d", ntohs(data->uh_sport));

    if(udp_sock == INVALID_SOCKET) {
      error("Cannot create UDP socket[%d]", socket_errno);
      return -1;
    }

    FD_SET(udp_sock, &tun->all_fds);
#ifndef WIN32    
    tun->all_max_fd = max(tun->all_max_fd, udp_sock);
#endif
    tun->num_open_socks++;
    tun->num_udp_opened++;

    conn->sock = udp_sock;
    conn->status = CONN_STATUS_CONNECTED;
  }

  if(tun->callbacks.account_packet)
    tun->callbacks.account_packet(tun, pkt->buf, pkt->pkt_len, 1 /* to zdtun */, conn);

  struct sockaddr_in servaddr = {0};
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = conn->dnat_ip ? conn->dnat_ip : conn->tuple.dst_ip;
  servaddr.sin_port = conn->dnat_port ? conn->dnat_port : conn->tuple.dst_port;

  if(sendto(conn->sock, pkt->l7, pkt->l7_len, 0, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
    error("UDP sendto error[%d]", socket_errno);
    return -1;
  }

  return 0;
}

/* ******************************************************* */

#ifndef ZDTUN_SKIP_ICMP

/* NOTE: a collision may occure between ICMP packets seq from host and tunneled packets, we ignore it */
static int handle_icmp_fwd(zdtun_t *tun, const zdtun_pkt_t *pkt, zdtun_conn_t *conn) {
  struct icmphdr *data = pkt->icmp;
  char buf1[INET_ADDRSTRLEN], buf2[INET_ADDRSTRLEN];
  const uint16_t icmp_len = pkt->l4_hdr_len + pkt->l7_len;

  debug("[ICMP.fw]-> %s -> %s", ipv4str(conn->tuple.src_ip, buf1),
    ipv4str(conn->tuple.dst_ip, buf2));
  debug("ICMP[len=%u] id=%d type=%d code=%d", icmp_len, data->un.echo.id, data->type, data->code);

  if(conn->status == CONN_STATUS_NEW) {
    tun->num_icmp_opened++;

    conn->status = CONN_STATUS_CONNECTED;
  }

  if(tun->callbacks.account_packet)
    tun->callbacks.account_packet(tun, pkt->buf, pkt->pkt_len, 1 /* to zdtun */, conn);

  struct sockaddr_in servaddr = {0};
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = conn->dnat_ip ? conn->dnat_ip : conn->tuple.dst_ip;

  if(sendto(tun->icmp_socket, data, icmp_len, 0, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
    error("ICMP sendto error[%d]", socket_errno);
    return -1;
  }

  return 0;
}

#endif

/* ******************************************************* */

static int zdtun_forward_full(zdtun_t *tun, const zdtun_pkt_t *pkt, zdtun_conn_t *conn, uint8_t no_hack) {
  int rv = 0;

  switch(pkt->tuple.ipproto) {
    case IPPROTO_TCP:
      rv = handle_tcp_fwd(tun, pkt, conn, no_hack);
      break;
    case IPPROTO_UDP:
      rv = handle_udp_fwd(tun, pkt, conn);
      break;
#ifndef ZDTUN_SKIP_ICMP
    case IPPROTO_ICMP:
      rv = handle_icmp_fwd(tun, pkt, conn);
      break;
#endif
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

zdtun_conn_t* zdtun_easy_forward(zdtun_t *tun, const char *pkt_buf, size_t pkt_len) {
  zdtun_pkt_t pkt;

  if(zdtun_parse_pkt(pkt_buf, pkt_len, &pkt) != 0)
    return NULL;

  uint8_t is_tcp_established = ((pkt.tuple.ipproto == IPPROTO_TCP) &&
    (!(pkt.tcp->th_flags & TH_SYN) || (pkt.tcp->th_flags & TH_ACK)));

  zdtun_conn_t *conn = zdtun_lookup(tun, &pkt.tuple, !is_tcp_established);

  if(!conn) {
    if(is_tcp_established)
      debug("TCP: ignoring non SYN connection");

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

#ifndef ZDTUN_SKIP_ICMP

static int handle_icmp_reply(zdtun_t *tun) {
  char *payload_ptr = tun->reply_buf;
  ssize_t l3_len = recv(tun->icmp_socket, payload_ptr, REPLY_BUF_SIZE, 0);

  if(l3_len == SOCKET_ERROR) {
    error("Error reading ICMP packet[%ld]: %d", l3_len, socket_errno);
    return -1;
  }

  struct iphdr *ip_header = (struct iphdr*)payload_ptr;
  int ip_header_size = ip_header->ihl * 4;
  ssize_t icmp_len = l3_len - ip_header_size;

  if(icmp_len < sizeof(struct icmphdr)) {
    error("ICMP packet too small[%ld]", icmp_len);
    return -1;
  }

  struct icmphdr *data = (struct icmphdr*) &payload_ptr[ip_header_size];
  char buf1[INET_ADDRSTRLEN], buf2[INET_ADDRSTRLEN];

  if((data->type != ICMP_ECHO) && (data->type != ICMP_ECHOREPLY)) {
    log_packet("Discarding unsupported ICMP[%d]", data->type);
    return 0;
  }

  zdtun_pkt_t pinfo;

  if(zdtun_parse_pkt(payload_ptr, l3_len, &pinfo) != 0) {
    debug("parse_pkt ICMP failed");
    return 0;
  }

  log_packet("[ICMP.re] %s -> %s", ipv4str(pinfo.tuple.src_ip, buf1), ipv4str(pinfo.tuple.dst_ip, buf2));
  debug("ICMP[len=%lu] id=%d type=%d code=%d", icmp_len, data->un.echo.id, data->type, data->code);

  zdtun_conn_t *conn;
  HASH_FIND(hh, tun->conn_table, &pinfo.tuple, sizeof(pinfo.tuple), conn);

  if(!conn || (conn->icmp.echo_seq != data->un.echo.sequence)) {
    log_packet("Discarding missing/out of sequence ICMP[%d]", ntohs(data->un.echo.id));
    return 0;
  }

  // update the conn for next iterations
  conn->tstamp = time(NULL);
  conn->icmp.echo_seq = 0;

  data->checksum = 0;
  data->checksum = htons(~in_cksum((char*)data, icmp_len, 0));

  build_ip_header_raw(payload_ptr, l3_len, IPPROTO_ICMP, conn->tuple.dst_ip, conn->tuple.src_ip);

  ip_header->check = 0;
  ip_header->check = ip_checksum(ip_header, ip_header_size);

  return send_to_client(tun, conn, l3_len);
}

#endif

/* ******************************************************* */

// return 0 if the conn was removed
static int handle_tcp_reply(zdtun_t *tun, zdtun_conn_t *conn) {
  char *payload_ptr = tun->reply_buf + ZDTUN_IP_HEADER_SIZE + MIN_TCP_HEADER_LEN;
  ssize_t l4_len = recv(conn->sock, payload_ptr, REPLY_BUF_SIZE - ZDTUN_IP_HEADER_SIZE - MIN_TCP_HEADER_LEN, 0);

  conn->tstamp = time(NULL);

  if(l4_len == SOCKET_ERROR) {
    if(socket_errno == socket_con_refused) {
      debug("TCP connection refused");
    } else {
      error("Error reading TCP packet[%ld]: %d", l4_len, socket_errno);
    }

    zdtun_destroy_conn(tun, conn);
    return 0;
  } else if(l4_len == 0) {
    debug("Server socket closed");

    if(conn->tcp.pending)
      log("[WARNING]: This should never happen!!");

    // close the socket, otherwise select will keep triggering
    finalize_zdtun_sock(tun, conn);

    tcp_socket_fin_ack(tun, conn);
    return 1;
  }

  char buf1[INET_ADDRSTRLEN], buf2[INET_ADDRSTRLEN];
  debug("[TCP] %s:%d -> %s:%d", ipv4str(conn->tuple.dst_ip, buf1), ntohs(conn->tuple.dst_port),
            ipv4str(conn->tuple.src_ip, buf2), ntohs(conn->tuple.src_port));

  if((conn->tcp.pending) || (conn->tcp.window_size < l4_len)) {
    log_tcp_window("Insufficient window size detected [%d], queuing", conn->tcp.window_size);

    struct tcp_pending_data *pending;

    safe_alloc(pending, struct tcp_pending_data);
    pending->size = l4_len;
    pending->data = (char*) malloc(l4_len);
    if(!pending->data)
      fatal("malloc tcp.pending_data failed");

    memcpy(pending->data, payload_ptr, l4_len);
    conn->tcp.pending = pending;

    // stop receiving updates for the socket
    FD_CLR(conn->sock, &tun->all_fds);

    // try to send a little bit of data right now
    process_pending_tcp_packets(tun, conn);

    return 1;
  }

  // NAT back the TCP port and reconstruct the TCP header
  build_tcp_ip_header(tun, conn, TH_PUSH | TH_ACK, l4_len);
  conn->tcp.zdtun_seq += l4_len;
  conn->tcp.window_size -= l4_len;

  send_to_client(tun, conn, l4_len + MIN_TCP_HEADER_LEN + ZDTUN_IP_HEADER_SIZE);

  // ok
  return 1;
}

/* ******************************************************* */

static int check_dns_purge(zdtun_t *tun, zdtun_conn_t *conn,
        char *l4_payload, uint16_t l4_len) {
    struct dns_packet *dns;

    if((l4_len < sizeof(struct dns_packet)) || (conn->tuple.dst_port != ntohs(53)))
        return(1);

    dns = (struct dns_packet*)l4_payload;

    if((dns->flags & DNS_FLAGS_MASK) == DNS_TYPE_RESPONSE) {
        /* DNS response received, can now purge the conn */
        debug("DNS purge");
        zdtun_destroy_conn(tun, conn);

        /* purged */
        return(0);
    }

    return(1);
}

/* ******************************************************* */

// return 0 if the conn was removed
static int handle_udp_reply(zdtun_t *tun, zdtun_conn_t *conn) {
  char *payload_ptr = tun->reply_buf + ZDTUN_IP_HEADER_SIZE + sizeof(struct udphdr);
  ssize_t l4_len = recv(conn->sock, payload_ptr, REPLY_BUF_SIZE-ZDTUN_IP_HEADER_SIZE-sizeof(struct udphdr), 0);

  if(l4_len == SOCKET_ERROR) {
    error("Error reading UDP packet[%ld]: %d", l4_len, socket_errno);
    zdtun_destroy_conn(tun, conn);
    return 0;
  }

  // Reconstruct the UDP header
  ssize_t l3_len = l4_len + sizeof(struct udphdr);
  struct udphdr *data = (struct udphdr*) (tun->reply_buf + ZDTUN_IP_HEADER_SIZE);
  data->uh_ulen = htons(l3_len);
  data->uh_sport = conn->tuple.dst_port;

  // NAT back the UDP port
  data->uh_dport = conn->tuple.src_port;

  char buf1[INET_ADDRSTRLEN], buf2[INET_ADDRSTRLEN];

  log_packet("[UDP] %s:%d -> %s:%d", ipv4str(conn->tuple.dst_ip, buf1), ntohs(conn->tuple.dst_port),
            ipv4str(conn->tuple.src_ip, buf2), ntohs(conn->tuple.src_port));

  // Recalculate the checksum
  data->uh_sum = 0;

  // NOTE: not needed (UDP checksum is optional) and inefficient
#if 0
  data->check = wrapsum(in_cksum((char*)data, sizeof(struct udphdr), // UDP header
    in_cksum(payload_ptr, l4_len,
      in_cksum((char*)&conn->tuple.dst_ip, 4,
        in_cksum((char*)&conn->tuple.src_ip, 4,
          IPPROTO_UDP + l3_len
  )))));
#endif

  build_ip_header(conn, tun->reply_buf, l3_len, IPPROTO_UDP);

  struct iphdr *ip_header = (struct iphdr*)tun->reply_buf;
  ip_header->check = 0;
  ip_header->check = ip_checksum(ip_header, ZDTUN_IP_HEADER_SIZE);

  send_to_client(tun, conn, l3_len + ZDTUN_IP_HEADER_SIZE);

  // ok
  conn->tstamp = time(NULL);

  return check_dns_purge(tun, conn, payload_ptr, l4_len);
}

/* ******************************************************* */

// return 0 if the conn was removed
static int handle_tcp_connect_async(zdtun_t *tun, zdtun_conn_t *conn) {
  int optval = -1;
  socklen_t optlen = sizeof (optval);
  int rv = 1;

  if(getsockopt(conn->sock, SOL_SOCKET, SO_ERROR, (char*)&optval, &optlen) == SOCKET_ERROR) {
    error("getsockopt failed: %d", socket_errno);
    zdtun_destroy_conn(tun, conn);

    // purged
    rv = 0;
  } else {
    if(optval == 0) {
      debug("TCP non-blocking socket connected");
      tcp_socket_syn(tun, conn);
      conn->tstamp = time(NULL);
    } else {
      debug("TCP non-blocking socket connection failed");
      zdtun_destroy_conn(tun, conn);
      // purged
      rv = 0;
    }
  }

  return rv;
}

/* ******************************************************* */

int zdtun_handle_fd(zdtun_t *tun, const fd_set *rd_fds, const fd_set *wr_fds) {
  int num_hits = 0;
  zdtun_conn_t *conn, *tmp;

#ifndef ZDTUN_SKIP_ICMP
  if(FD_ISSET(tun->icmp_socket, rd_fds)) {
    handle_icmp_reply(tun);
    num_hits++;
  }
#endif

  HASH_ITER(hh, tun->conn_table, conn, tmp) {
    uint8_t ipproto = conn->tuple.ipproto;

    if(conn->sock == INVALID_SOCKET)
      continue;

    if(FD_ISSET(conn->sock, rd_fds)) {
      if(ipproto == IPPROTO_TCP)
        handle_tcp_reply(tun, conn);
      else if(ipproto == IPPROTO_UDP)
        handle_udp_reply(tun, conn);
      else
        error("Unhandled socket.rd proto: %d", ipproto);

      num_hits++;
    } else if(FD_ISSET(conn->sock, wr_fds)) {
      if(ipproto == IPPROTO_TCP)
        handle_tcp_connect_async(tun, conn);
      else
        error("Unhandled socket.wr proto: %d", ipproto);

      num_hits++;
    }
  }

  return num_hits;
}

/* ******************************************************* */

// negative, zero, or positive <=> A before, equal to, or after B
static inline int zdtun_conn_cmp_timestamp_asc(zdtun_conn_t *a, zdtun_conn_t *b) {
  return(a->tstamp - b->tstamp);
}

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

    if(now >= (timeout + conn->tstamp)) {
      debug("IDLE (type=%d)", conn->tuple.ipproto);
      zdtun_destroy_conn(tun, conn);
    }
  }

  if(tun->num_open_socks > MAX_NUM_SOCKETS) {
    int to_purge = tun->num_open_socks - NUM_SOCKETS_AFTER_PURGE;

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
    if(iterator(tun, conn, userdata) != 0)
      return(1);
  }

  return(0);
}

/* ******************************************************* */

int zdtun_get_num_connections(zdtun_t *tun) {
    return(tun->num_active_connections);
}

/* ******************************************************* */

void zdtun_get_stats(zdtun_t *tun, zdtun_statistics_t *stats) {
  zdtun_conn_t *conn, *tmp;

  memset(stats, 0, sizeof(*stats));

  HASH_ITER(hh, tun->conn_table, conn, tmp) {
    switch(conn->tuple.ipproto) {
      case IPPROTO_ICMP:
        stats->num_icmp_conn++;
        stats->oldest_icmp_conn = (stats->oldest_icmp_conn) ? (min(stats->oldest_icmp_conn, conn->tstamp)) : conn->tstamp;
        break;
      case IPPROTO_TCP:
        stats->num_tcp_conn++;
        stats->oldest_tcp_conn = (stats->oldest_tcp_conn) ? (min(stats->oldest_tcp_conn, conn->tstamp)) : conn->tstamp;
        break;
      case IPPROTO_UDP:
        stats->num_udp_conn++;
        stats->oldest_udp_conn = (stats->oldest_udp_conn) ? (min(stats->oldest_udp_conn, conn->tstamp)) : conn->tstamp;
        break;
    }
  }

  stats->num_open_sockets = tun->num_open_socks;

  // totals
  stats->num_icmp_opened = tun->num_icmp_opened;
  stats->num_udp_opened = tun->num_udp_opened;
  stats->num_tcp_opened = tun->num_tcp_opened;
}
