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
#include "third_party/uthlist.h"
#include "third_party/net_headers.h"

#define REPLY_BUF_SIZE 65535
#define TCP_WINDOW_SIZE 64240
#define MIN_TCP_HEADER_LEN 20

#define ICMP_TIMEOUT_SEC 3
#define UDP_TIMEOUT_SEC 20
#define TCP_TIMEOUT_SEC 15

// 64 is the per-thread limit on Winsocks
// use a lower value to leave room for user defined connections
#define MAX_NUM_SOCKETS 55
#define NUM_SOCKETS_AFTER_PURGE 40

/* ******************************************************* */

struct tcp_pending_data {
  char *data;
  u_int16_t size;
  u_int16_t sofar;
};

struct nat_entry {
  time_t tstamp;
  socket_t sock;
  zdtun_conn_t conn;

  union {
    struct {
      u_int32_t client_seq;    // next client sequence number
      u_int32_t zdtun_seq;     // next NAT sequence number
      u_int16_t window_size;   // client window size
      struct tcp_pending_data *pending;
    } tcp;
    struct {
      u_int16_t echo_id;
      u_int16_t icmp_seq;
    } icmp;
  };

  struct nat_entry *next;
};

/* ******************************************************* */

typedef struct zdtun_t {
  struct zdtun_callbacks callbacks;
  void *user_data;
  fd_set all_fds;
  fd_set tcp_connecting;
  int all_max_fd;
  int num_open_socks;
  u_int32_t num_icmp_opened;
  u_int32_t num_tcp_opened;
  u_int32_t num_udp_opened;
#ifndef ZDTUN_SKIP_ICMP
  socket_t icmp_socket;
#endif
  char reply_buf[REPLY_BUF_SIZE];

  struct nat_entry *icmp_nat_table;
  struct nat_entry *tcp_nat_table;
  struct nat_entry *udp_nat_table;
  u_int32_t client_addr;
} zdtun_t;

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
  // purge all
  zdtun_purge_expired(tun, 0);

#ifndef ZDTUN_SKIP_ICMP
  if(tun->icmp_socket)
    close_socket(tun, tun->icmp_socket);
#endif

  free(tun);
}

/* ******************************************************* */

static inline int send_to_client(zdtun_t *tun, const struct nat_entry *entry, size_t size) {
  int rv = tun->callbacks.send_client(tun, tun->reply_buf, size, &entry->conn);

  if(tun->callbacks.account_packet)
      tun->callbacks.account_packet(tun, tun->reply_buf, size, 0 /* from zdtun */, &entry->conn);

  return(rv);
}

/* ******************************************************* */

static inline void finalize_zdtun_sock(zdtun_t *tun, struct nat_entry *entry) {
  close_socket(tun, entry->sock);
  FD_CLR(entry->sock, &tun->all_fds);
  FD_CLR(entry->sock, &tun->tcp_connecting);

#ifndef WIN32
  tun->all_max_fd = max(tun->all_max_fd, entry->sock-1);
#endif
  tun->num_open_socks--;

  // mark as closed
  entry->sock = 0;
}

/* ******************************************************* */

static void purge_nat_entry(zdtun_t *tun, struct nat_entry *entry,
          struct nat_entry **head, struct nat_entry *prev) {
  u_int8_t ipproto = (*head == tun->tcp_nat_table) ? IPPROTO_TCP :
    ((*head == tun->udp_nat_table) ? IPPROTO_UDP : IPPROTO_ICMP);

  debug("PURGE %s SOCKET", (*head == tun->tcp_nat_table) ? "TCP" :
    ((*head == tun->udp_nat_table) ? "UDP" : "ICMP"));

  if(entry->sock)
    finalize_zdtun_sock(tun, entry);

  if(entry->tcp.pending) {
    free(entry->tcp.pending->data);
    free(entry->tcp.pending);
  }

  if(tun->callbacks.on_connection_close)
    tun->callbacks.on_connection_close(tun, &entry->conn);

  if(prev)
    prev->next = entry->next;
  else
    *head = entry->next;

  free(entry);
}

/* ******************************************************* */

// call this if prev is unknown
static inline void purge_nat_entry_full(zdtun_t *tun, struct nat_entry *entry, struct nat_entry **head) {
  struct nat_entry *item, *prev = NULL;

  LL_FOREACH(*head, item) {
    if(item == entry) {
      purge_nat_entry(tun, entry, head, prev);
      break;
    }

    prev = item;
  }
}

/* ******************************************************* */

static inline int build_ip_header_raw(char *pkt_buf, u_int16_t tot_len, uint l3_proto, u_int32_t srcip, u_int32_t dstip) {
  struct iphdr *ip_header = (struct iphdr*)pkt_buf;

  memset(ip_header, 0, 20);
  ip_header->ihl = 5; // 5 * 4 = 20 = NAT_IP_HEADER_SIZE
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

#define build_ip_header(entry, pkt_buf, l3_len, l3_proto)\
  build_ip_header_raw(pkt_buf, l3_len + NAT_IP_HEADER_SIZE, l3_proto, entry->conn.dst_ip, entry->conn.src_ip)

static inline void build_tcp_ip_header(zdtun_t *tun, struct nat_entry *entry, u_int8_t flags, u_int16_t l4_len) {
  const u_int16_t l3_len = l4_len + MIN_TCP_HEADER_LEN;
  struct tcphdr *tcp_synack = (struct tcphdr *)&tun->reply_buf[NAT_IP_HEADER_SIZE];
  memset(tcp_synack, 0, MIN_TCP_HEADER_LEN);
  tcp_synack->th_sport = entry->conn.dst_port;
  tcp_synack->th_dport = entry->conn.src_port;
  tcp_synack->th_seq = htonl(entry->tcp.zdtun_seq);
  tcp_synack->th_ack = (flags & TH_ACK) ? htonl(entry->tcp.client_seq) : 0;
  tcp_synack->th_off = 5;
  tcp_synack->th_flags = flags;
  tcp_synack->th_win = htons(TCP_WINDOW_SIZE);

  build_ip_header(entry, tun->reply_buf, l3_len, IPPROTO_TCP);
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
  ip_header->check = ip_checksum(ip_header, NAT_IP_HEADER_SIZE);
}

/* ******************************************************* */

static int tcp_socket_syn(zdtun_t *tun, struct nat_entry *entry) {
  // disable non-blocking mode from now on

#ifdef WIN32
  unsigned nonblocking = 0;
  ioctlsocket(entry->sock, FIONBIO, &nonblocking);
#else
  int flags = fcntl(entry->sock, F_GETFL);

  if(fcntl(entry->sock, F_SETFL, flags &(~O_NONBLOCK)) == -1)
    error("Cannot disable non-blocking: %d", errno);
#endif

  FD_CLR(entry->sock, &tun->tcp_connecting);

  // send the SYN+ACK
  build_tcp_ip_header(tun, entry, TH_SYN | TH_ACK, 0);
  entry->tcp.zdtun_seq += 1;

  return send_to_client(tun, entry, MIN_TCP_HEADER_LEN + NAT_IP_HEADER_SIZE);
}

/* ******************************************************* */

static void tcp_socket_fin_ack(zdtun_t *tun, struct nat_entry *entry) {
  build_tcp_ip_header(tun, entry, TH_FIN | TH_ACK, 0);
  entry->tcp.zdtun_seq += 1;

  send_to_client(tun, entry, MIN_TCP_HEADER_LEN + NAT_IP_HEADER_SIZE);
}

/* ******************************************************* */

static void process_pending_tcp_packets(zdtun_t *tun, struct nat_entry *entry) {
  struct tcp_pending_data *pending = entry->tcp.pending;

  if(!entry->tcp.window_size || !pending || !entry->sock)
    return;

  u_int16_t remaining = pending->size - pending->sofar;
  u_int16_t to_send = min(entry->tcp.window_size, remaining);

  log_tcp_window("Sending %d/%d bytes pending data", to_send, remaining);
  memcpy(tun->reply_buf + MIN_TCP_HEADER_LEN + NAT_IP_HEADER_SIZE, &pending->data[pending->sofar], to_send);

  // NAT back the TCP port and reconstruct the TCP header
  build_tcp_ip_header(tun, entry, TH_PUSH | TH_ACK, to_send);
  send_to_client(tun, entry, to_send + MIN_TCP_HEADER_LEN + NAT_IP_HEADER_SIZE);

  entry->tcp.zdtun_seq += to_send;
  entry->tcp.window_size -= to_send;

  if(remaining == to_send) {
    free(pending->data);
    free(pending);
    entry->tcp.pending = NULL;

    // make the socket selectable again
    FD_SET(entry->sock, &tun->all_fds);
  } else
    pending->sofar += to_send;
}

/* ******************************************************* */

// returns >=0 on success
// returns <0 on error
static int handle_tcp_nat(zdtun_t *tun, char *pkt_buf, size_t pkt_len, zdtun_conn_t *conn_info) {
  struct iphdr *ip_header = (struct iphdr*) pkt_buf;
  size_t ip_hdr_len = ip_header->ihl * 4;
  char buf1[INET_ADDRSTRLEN], buf2[INET_ADDRSTRLEN];

  if(pkt_len < (ip_hdr_len + MIN_TCP_HEADER_LEN)) {
    error("Packet too small for TCP[%lu]", pkt_len);
    return -1;
  }

  struct tcphdr *data = (struct tcphdr*) &pkt_buf[ip_hdr_len];
  const size_t tcp_header_len = data->th_off * 4;

  if(pkt_len < (ip_hdr_len + tcp_header_len)) {
    error("Malformed TCP packet");
    return -2;
  }

  debug("[TCP]-> %s:%d -> %s:%d", ipv4str(ip_header->saddr, buf1), ntohs(data->th_sport), ipv4str(ip_header->daddr, buf2), ntohs(data->th_dport));

  struct nat_entry *entry = NULL;
  LL_SEARCH_2SCALARS(tun->tcp_nat_table, entry, conn.src_port, conn.dst_port, data->th_sport, data->th_dport);

  if(!entry) {
    // New connection
    zdtun_conn_t conn = {
      .ipproto = IPPROTO_TCP,
      .src_ip = ip_header->saddr,
      .dst_ip = ip_header->daddr,
      .src_port = data->th_sport,
      .dst_port = data->th_dport,
      .user_data = NULL,
    };

    if(!(data->th_flags & TH_SYN) || (data->th_flags & TH_ACK)) {
      debug("TCP: ignoring non SYN connection");
      return 1;
    }

    if(tun->callbacks.on_connection_open) {
      if(tun->callbacks.on_connection_open(tun, &conn, &conn.user_data) != 0) {
        debug("Dropping TCP connection");
        return 2;
      }
    }

    if(tun->num_open_socks >= MAX_NUM_SOCKETS) {
      debug("Force purge!");
      zdtun_purge_expired(tun, time(NULL));
    }

    debug("Allocating new TCP socket for port %d", ntohs(data->th_sport));
    socket_t tcp_sock = open_socket(tun, PF_INET, SOCK_STREAM, IPPROTO_TCP);

    if(tcp_sock == INVALID_SOCKET) {
      error("Cannot create TCP socket[%d]", socket_errno);
      return -1;
    }

    tun->num_tcp_opened++;

    // Setup for the connection
    struct sockaddr_in servaddr = {0};
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = ip_header->daddr;
    servaddr.sin_port = data->th_dport;

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

    // proceed
    safe_alloc(entry, struct nat_entry);
    LL_PREPEND(tun->tcp_nat_table, entry);

    FD_SET(tcp_sock, &tun->all_fds);
    entry->sock = tcp_sock;
    entry->tcp.client_seq = ntohl(data->th_seq) + 1;
    entry->tcp.zdtun_seq = 0x77EB77EB;
    entry->tstamp = time(NULL);
    entry->conn = conn;

    if(conn_info)
      *conn_info = conn;

    if(tun->callbacks.account_packet)
      tun->callbacks.account_packet(tun, pkt_buf, pkt_len, 1 /* to zdtun */, &entry->conn);

#ifndef WIN32
    tun->all_max_fd = max(tun->all_max_fd, tcp_sock);
#endif
    tun->num_open_socks++;

    if(!in_progress)
      return tcp_socket_syn(tun, entry);

    FD_SET(tcp_sock, &tun->tcp_connecting);
    return 0;
  }

  // Here a connection is already active
  entry->tstamp = time(NULL);
  entry->conn.src_ip = ip_header->saddr;
  entry->conn.dst_ip = ip_header->daddr;

  if(conn_info)
      *conn_info = entry->conn;

  if(tun->callbacks.account_packet)
     tun->callbacks.account_packet(tun, pkt_buf, pkt_len, 1 /* to zdtun */, &entry->conn);

  const size_t tcp_payload_size = pkt_len - ip_hdr_len - tcp_header_len;

  if(data->th_flags & TH_RST) {
    debug("Got TCP reset from client");
    purge_nat_entry_full(tun, entry, &tun->tcp_nat_table);
    return 1;
  } else if((data->th_flags & (TH_FIN | TH_ACK)) == (TH_FIN | TH_ACK)) {
    debug("Got TCP FIN+ACK from client");

    entry->tcp.client_seq += tcp_payload_size + 1;
    build_tcp_ip_header(tun, entry, TH_FIN | TH_ACK, 0);

    send_to_client(tun, entry, MIN_TCP_HEADER_LEN + NAT_IP_HEADER_SIZE);
    purge_nat_entry_full(tun, entry, &tun->tcp_nat_table);
    return 1;
  } else if(!entry->sock) {
    debug("Ignore write on closed socket");
    return 1;
  }

  if(data->th_flags & TH_ACK) {
    entry->tcp.window_size = (entry->tcp.zdtun_seq - ntohl(data->th_ack)) + ntohs(data->th_win);
    process_pending_tcp_packets(tun, entry);
  }

  // payload data (avoid sending ACK to an ACK)
  if(tcp_payload_size > 0) {
    if(send(entry->sock, ((char*)data) + tcp_header_len, tcp_payload_size, 0) < 0) {
      error("TCP send error[%d]", socket_errno);
      purge_nat_entry_full(tun, entry, &tun->tcp_nat_table);
      return -1;
    }

    // send the ACK
    entry->tcp.client_seq += tcp_payload_size;
    build_tcp_ip_header(tun, entry, TH_ACK, 0);

    return send_to_client(tun, entry, MIN_TCP_HEADER_LEN + NAT_IP_HEADER_SIZE);
  }

  return 0;
}

/* ******************************************************* */

static int handle_udp_nat(zdtun_t *tun, char *pkt_buf, size_t pkt_len, zdtun_conn_t *conn_info) {
  struct iphdr *ip_header = (struct iphdr*) pkt_buf;
  size_t ip_hdr_len = ip_header->ihl * 4;
  const size_t udp_header_len = sizeof(struct udphdr);

  if(pkt_len < (ip_hdr_len + udp_header_len)) {
    error("Packet too small for UDP[%lu]", pkt_len);
    return -1;
  }

  struct udphdr *data = (struct udphdr*) &pkt_buf[ip_hdr_len];

  char buf1[INET_ADDRSTRLEN], buf2[INET_ADDRSTRLEN];
  log_packet("[UDP] %s:%d -> %s:%d", ipv4str(ip_header->saddr, buf1), ntohs(data->uh_sport), ipv4str(ip_header->daddr, buf2), ntohs(data->uh_dport));

  struct nat_entry *entry = NULL;
  LL_SEARCH_2SCALARS(tun->udp_nat_table, entry, conn.src_port, conn.dst_port, data->uh_sport, data->uh_dport);

  if(!entry) {
    zdtun_conn_t conn = {
      .ipproto = IPPROTO_UDP,
      .src_ip = ip_header->saddr,
      .dst_ip = ip_header->daddr,
      .src_port = data->uh_sport,
      .dst_port = data->uh_dport,
      .user_data = NULL,
    };

    if(tun->num_open_socks >= MAX_NUM_SOCKETS) {
      debug("Force purge!");
      zdtun_purge_expired(tun, time(NULL));
    }

    if(tun->callbacks.on_connection_open) {
      if(tun->callbacks.on_connection_open(tun, &conn, &conn.user_data) != 0) {
        debug("Dropping UDP connection");
        return 2;
      }
    }

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
    safe_alloc(entry, struct nat_entry);
    LL_PREPEND(tun->udp_nat_table, entry);

    entry->sock = udp_sock;
    entry->conn = conn;
  }

  entry->tstamp = time(NULL);
  entry->conn.src_ip = ip_header->saddr;
  entry->conn.dst_ip = ip_header->daddr;

  if(conn_info)
    *conn_info = entry->conn;

  if(tun->callbacks.account_packet)
    tun->callbacks.account_packet(tun, pkt_buf, pkt_len, 1 /* to zdtun */, &entry->conn);

  struct sockaddr_in servaddr = {0};
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = ip_header->daddr;
  servaddr.sin_port = data->uh_dport;

  if(sendto(entry->sock, ((char*)data) + udp_header_len, pkt_len - ip_hdr_len - udp_header_len, 0, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
    error("UDP sendto error[%d]", socket_errno);
    purge_nat_entry_full(tun, entry, &tun->udp_nat_table);
    return -1;
  }

  return 0;
}

/* ******************************************************* */

#ifndef ZDTUN_SKIP_ICMP

/* NOTE: a collision may occure between ICMP packets seq from host and tunneled packets, we ignore it */
static int handle_icmp_nat(zdtun_t *tun, char *pkt_buf, size_t pkt_len, zdtun_conn_t *conn_info) {
  struct iphdr *ip_header = (struct iphdr*) pkt_buf;
  size_t ip_hdr_len = ip_header->ihl * 4;
  char buf1[INET_ADDRSTRLEN], buf2[INET_ADDRSTRLEN];

  if(pkt_len < (ip_hdr_len + sizeof(struct icmphdr))) {
    error("Packet too small for ICMP");
    return -1;
  }

  struct icmphdr *data = (struct icmphdr*) &pkt_buf[ip_hdr_len];

  if(data->type != ICMP_ECHO) {
    log_packet("Discarding non echo ICMP[%d]", data->type);
    return 1;
  }

  log_packet("[ICMP] %s -> %s", ipv4str(ip_header->saddr, buf1), ipv4str(ip_header->daddr, buf2));
  debug("ICMP[len=%lu] id=%d type=%d code=%d", pkt_len - ip_hdr_len, data->un.echo.id, data->type, data->code);

  struct nat_entry *entry = NULL;
  LL_SEARCH_SCALAR(tun->icmp_nat_table, entry, icmp.echo_id, data->un.echo.id);

  if(!entry) {
    zdtun_conn_t conn = {
      .ipproto = IPPROTO_ICMP,
      .src_ip = ip_header->saddr,
      .dst_ip = ip_header->daddr,
      .src_port = 0,
      .dst_port = 0,
      .user_data = NULL,
    };

    if(tun->callbacks.on_connection_open) {
      if(tun->callbacks.on_connection_open(tun, &conn, &conn.user_data) != 0) {
        debug("Dropping ICMP connection");
        return 2;
      }
    }

    safe_alloc(entry, struct nat_entry);
    entry->conn = conn;
    LL_PREPEND(tun->icmp_nat_table, entry);

    tun->num_icmp_opened++;
  }

  entry->tstamp = time(NULL);
  entry->icmp.icmp_seq = data->un.echo.sequence;
  entry->icmp.echo_id = data->un.echo.id;

  if(conn_info)
    *conn_info = entry->conn;

  if(tun->callbacks.account_packet)
    tun->callbacks.account_packet(tun, pkt_buf, pkt_len, 1 /* to zdtun */, &entry->conn);

  struct sockaddr_in servaddr = {0};
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = ip_header->daddr;

  if(sendto(tun->icmp_socket, (char*)data, pkt_len - ip_hdr_len, 0, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
    error("ICMP sendto error[%d]", socket_errno);
    return -1;
  }

  return 0;
}

#endif

/* ******************************************************* */

int zdtun_forward(zdtun_t *tun, char *pkt_buf, size_t pkt_len, zdtun_conn_t *conn_info) {
  struct iphdr *ip_header = (struct iphdr*) pkt_buf;
  int rv = 0;

  if(ip_header->version != 4) {
    debug("Ignoring non IPv4 packet: %d", ip_header->version);
    return -1;
  }

  if(tun->client_addr && (tun->client_addr != ip_header->saddr)) {
    char buf1[INET_ADDRSTRLEN], buf2[INET_ADDRSTRLEN];
    log("[WARNING] multiple client addresses not supported (was %s, now %s), connections will break!",
      ipv4str(tun->client_addr, buf1), ipv4str(ip_header->saddr, buf2));
  }

  tun->client_addr = ip_header->saddr;

  switch(ip_header->protocol) {
    case IPPROTO_TCP:
      rv = handle_tcp_nat(tun, pkt_buf, pkt_len, conn_info);
      break;
    case IPPROTO_UDP:
      rv = handle_udp_nat(tun, pkt_buf, pkt_len, conn_info);
      break;
#ifndef ZDTUN_SKIP_ICMP
    case IPPROTO_ICMP:
      rv = handle_icmp_nat(tun, pkt_buf, pkt_len, conn_info);
      break;
#endif
    default:
      error("Ignoring unhandled IP protocol %d", ip_header->protocol);
      return -2;
  }

  return rv;
}

/* ******************************************************* */

#ifndef ZDTUN_SKIP_ICMP

static int handle_icmp_reply(zdtun_t *tun) {
  char *payload_ptr = tun->reply_buf;
  ssize_t l2_len = recv(tun->icmp_socket, payload_ptr, REPLY_BUF_SIZE, 0);

  if(l2_len == SOCKET_ERROR) {
    error("Error reading ICMP packet[%ld]: %d", l2_len, socket_errno);
    return -1;
  }

  struct iphdr *ip_header = (struct iphdr*)tun->reply_buf;
  int ip_header_size = ip_header->ihl * 4;
  ssize_t l3_len = l2_len - ip_header_size;

  if(l3_len < sizeof(struct icmphdr)) {
    error("ICMP packet too small[%ld]", l3_len);
    return -1;
  }

  struct icmphdr *data = (struct icmphdr*) &payload_ptr[ip_header_size];
  char buf1[INET_ADDRSTRLEN], buf2[INET_ADDRSTRLEN];

  if(data->type != ICMP_ECHOREPLY) {
    log_packet("Discarding non ICMP reply[%d]", data->type);
    return 0;
  }

  struct nat_entry *entry;
  LL_SEARCH_SCALAR(tun->icmp_nat_table, entry, icmp.echo_id, data->un.echo.id);

  if(!entry || (entry->icmp.icmp_seq != data->un.echo.sequence)) {
    log_packet("Discarding out of sequence ICMP[%d]", ntohs(data->un.echo.id));
    return 0;
  }

  log_packet("[ICMP] %s -> %s", ipv4str(entry->conn.dst_ip, buf1), ipv4str(entry->conn.src_ip, buf2));
  debug("ICMP[len=%lu] id=%d type=%d code=%d", l3_len, data->un.echo.id, data->type, data->code);

  // update the entry for next iterations
  entry->tstamp = time(NULL);
  entry->icmp.icmp_seq = 0;

  data->checksum = 0;
  data->checksum = htons(~in_cksum((char*)data, l3_len, 0));

  build_ip_header_raw(tun->reply_buf, l2_len, IPPROTO_ICMP, entry->conn.dst_ip, entry->conn.src_ip);

  ip_header->check = 0;
  ip_header->check = ip_checksum(ip_header, ip_header_size);

  return send_to_client(tun, entry, l2_len);
}

#endif

/* ******************************************************* */

// return 0 if the entry was removed
static int handle_tcp_reply(zdtun_t *tun, struct nat_entry *entry, struct nat_entry *prev) {
  char *payload_ptr = tun->reply_buf + NAT_IP_HEADER_SIZE + MIN_TCP_HEADER_LEN;
  ssize_t l4_len = recv(entry->sock, payload_ptr, REPLY_BUF_SIZE - NAT_IP_HEADER_SIZE - MIN_TCP_HEADER_LEN, 0);

  entry->tstamp = time(NULL);

  if(l4_len == SOCKET_ERROR) {
    if(socket_errno == socket_con_refused) {
      debug("TCP connection refused");
    } else {
      error("Error reading TCP packet[%ld]: %d", l4_len, socket_errno);
    }

    purge_nat_entry(tun, entry, &tun->tcp_nat_table, prev);
    return 0;
  } else if(l4_len == 0) {
    debug("Server socket closed");

    if(entry->tcp.pending)
      log("[WARNING]: This should never happen!!");

    // close the socket, otherwise select will keep triggering
    finalize_zdtun_sock(tun, entry);

    tcp_socket_fin_ack(tun, entry);
    return 1;
  }

  char buf1[INET_ADDRSTRLEN], buf2[INET_ADDRSTRLEN];
  debug("[TCP] %s:%d -> %s:%d", ipv4str(entry->conn.dst_ip, buf1), ntohs(entry->conn.dst_port),
            ipv4str(entry->conn.src_ip, buf2), ntohs(entry->conn.src_port));

  if((entry->tcp.pending) || (entry->tcp.window_size < l4_len)) {
    log_tcp_window("Insufficient window size detected [%d], queuing", entry->tcp.window_size);

    struct tcp_pending_data *pending;

    safe_alloc(pending, struct tcp_pending_data);
    pending->size = l4_len;
    pending->data = (char*) malloc(l4_len);
    if(!pending->data)
      fatal("malloc tcp.pending_data failed");

    memcpy(pending->data, payload_ptr, l4_len);
    entry->tcp.pending = pending;

    // stop receiving updates for the socket
    FD_CLR(entry->sock, &tun->all_fds);

    // try to send a little bit of data right now
    process_pending_tcp_packets(tun, entry);

    return 1;
  }

  // NAT back the TCP port and reconstruct the TCP header
  build_tcp_ip_header(tun, entry, TH_PUSH | TH_ACK, l4_len);
  entry->tcp.zdtun_seq += l4_len;
  entry->tcp.window_size -= l4_len;

  send_to_client(tun, entry, l4_len + MIN_TCP_HEADER_LEN + NAT_IP_HEADER_SIZE);

  // ok
  return 1;
}

/* ******************************************************* */

// return 0 if the entry was removed
static int handle_udp_reply(zdtun_t *tun, struct nat_entry *entry, struct nat_entry *prev) {
  char *payload_ptr = tun->reply_buf + NAT_IP_HEADER_SIZE + sizeof(struct udphdr);
  ssize_t l4_len = recv(entry->sock, payload_ptr, REPLY_BUF_SIZE-NAT_IP_HEADER_SIZE-sizeof(struct udphdr), 0);

  if(l4_len == SOCKET_ERROR) {
    error("Error reading UDP packet[%ld]: %d", l4_len, socket_errno);
    purge_nat_entry(tun, entry, &tun->udp_nat_table, prev);
    return 0;
  }

  // Reconstruct the UDP header
  ssize_t l3_len = l4_len + sizeof(struct udphdr);
  struct udphdr *data = (struct udphdr*) (tun->reply_buf + NAT_IP_HEADER_SIZE);
  data->uh_ulen = htons(l3_len);
  data->uh_sport = entry->conn.dst_port;

  // NAT back the UDP port
  data->uh_dport = entry->conn.src_port;

  char buf1[INET_ADDRSTRLEN], buf2[INET_ADDRSTRLEN];

  log_packet("[UDP] %s:%d -> %s:%d", ipv4str(entry->conn.dst_ip, buf1), ntohs(entry->conn.dst_port),
            ipv4str(entry->conn.src_ip, buf2), ntohs(entry->conn.src_port));

  // Recalculate the checksum
  data->uh_sum = 0;

  // NOTE: not needed (UDP checksum is optional) and inefficient
#if 0
  data->check = wrapsum(in_cksum((char*)data, sizeof(struct udphdr), // UDP header
    in_cksum(payload_ptr, l4_len,
      in_cksum((char*)&entry->conn.dst_ip, 4,
        in_cksum((char*)&entry->conn.src_ip, 4,
          IPPROTO_UDP + l3_len
  )))));
#endif

  build_ip_header(entry, tun->reply_buf, l3_len, IPPROTO_UDP);

  struct iphdr *ip_header = (struct iphdr*)tun->reply_buf;
  ip_header->check = 0;
  ip_header->check = ip_checksum(ip_header, NAT_IP_HEADER_SIZE);

  send_to_client(tun, entry, l3_len + NAT_IP_HEADER_SIZE);

  // ok
  entry->tstamp = time(NULL);
  return 1;
}

/* ******************************************************* */

// return 0 if the entry was removed
static int handle_tcp_connect_async(zdtun_t *tun, struct nat_entry *entry, struct nat_entry *prev) {
  int optval = -1;
  socklen_t optlen = sizeof (optval);
  int rv = 1;

  if(getsockopt(entry->sock, SOL_SOCKET, SO_ERROR, (char*)&optval, &optlen) == SOCKET_ERROR) {
    error("getsockopt failed: %d", socket_errno);
    purge_nat_entry(tun, entry, &tun->tcp_nat_table, prev);

    // purged
    rv = 0;
  } else {
    if(optval == 0) {
      debug("TCP non-blocking socket connected");
      tcp_socket_syn(tun, entry);
      entry->tstamp = time(NULL);
    } else {
      debug("TCP non-blocking socket connection failed");
      purge_nat_entry(tun, entry, &tun->tcp_nat_table, prev);
      // purged
      rv = 0;
    }
  }

  return rv;
}

/* ******************************************************* */

int zdtun_handle_fd(zdtun_t *tun, const fd_set *rd_fds, const fd_set *wr_fds) {
  int num_hits = 0;
  struct nat_entry *entry, *prev, *tmp;

#ifndef ZDTUN_SKIP_ICMP
  if(FD_ISSET(tun->icmp_socket, rd_fds)) {
    handle_icmp_reply(tun);
    num_hits++;
  }
#endif

  prev = NULL;
  LL_FOREACH_SAFE(tun->tcp_nat_table, entry, tmp) {
    bool purged = false;

    if(FD_ISSET(entry->sock, rd_fds)) {
      if(handle_tcp_reply(tun, entry, prev) == 0)
        purged = true;

      num_hits++;
    } else if(FD_ISSET(entry->sock, wr_fds)) {
      if(handle_tcp_connect_async(tun, entry, prev) == 0)
        purged = true;

      num_hits++;
    }

    if(!purged)
      prev = entry;
  }

  prev = NULL;
  LL_FOREACH_SAFE(tun->udp_nat_table, entry, tmp) {
    bool purged = false;

    if(FD_ISSET(entry->sock, rd_fds)) {
      if(handle_udp_reply(tun, entry, prev) == 0)
        purged = true;

      num_hits++;
    }

    if(!purged)
      prev = entry;
  }

  //if(!num_hits)
    //log("WARNING: no socket match!");

  return num_hits;
}

/* ******************************************************* */

// negative, zero, or positive <=> A before, equal to, or after B
static inline int nat_entry_cmp_timestamp_asc(struct nat_entry *a, struct nat_entry *b) {
  return(a->tstamp - b->tstamp);
}

static void purge_tcp_entry(zdtun_t *tun, struct nat_entry *entry, struct nat_entry *prev) {
  // Send TCP RST
  build_tcp_ip_header(tun, entry, TH_RST | TH_ACK, 0);
  send_to_client(tun, entry, MIN_TCP_HEADER_LEN + NAT_IP_HEADER_SIZE);

  purge_nat_entry(tun, entry, &tun->tcp_nat_table, prev);
}

void zdtun_purge_expired(zdtun_t *tun, time_t now) {
  int max_purge = 0;
  int forced_tcp_purge = 0;
  int forced_udp_purge = 0;
  int forced_icmp_purge = 0;
  struct nat_entry *entry, *tmp, *prev;

  if(now == 0) {
    /* Purge all */
    forced_tcp_purge = forced_udp_purge = forced_icmp_purge = 1;
    max_purge = tun->num_open_socks;
  }

  debug("zdtun_purge_expired called");

  /* TCP/UDP */
  if(tun->num_open_socks >= MAX_NUM_SOCKETS) {
    int num_opened_tcp, num_opened_udp;

    LL_COUNT(tun->tcp_nat_table, entry, num_opened_tcp);
    LL_COUNT(tun->udp_nat_table, entry, num_opened_udp);

    if(num_opened_tcp > num_opened_udp) {
      forced_tcp_purge = 1;
      max_purge = tun->num_open_socks - NUM_SOCKETS_AFTER_PURGE;
    } else {
      forced_udp_purge = 1;
      max_purge = tun->num_open_socks - NUM_SOCKETS_AFTER_PURGE;
    }
  }

  /* ICMP */
  if(forced_icmp_purge) {
    /* Force purge */
    LL_SORT(tun->icmp_nat_table, nat_entry_cmp_timestamp_asc);

    LL_FOREACH_SAFE(tun->icmp_nat_table, entry, tmp) {
      debug("FORCE ICMP PURGE");
      purge_nat_entry(tun, entry, &tun->icmp_nat_table, NULL);

      if(--max_purge <= 0)
        break;
    }
  } else {
    prev = NULL;
    LL_FOREACH_SAFE(tun->icmp_nat_table, entry, tmp) {
      if((now - entry->tstamp) >= ICMP_TIMEOUT_SEC) {
        debug("IDLE ICMP");
        purge_nat_entry(tun, entry, &tun->icmp_nat_table, prev);
      } else
        prev = entry;
    }
  }


  /* TCP */
  if(forced_tcp_purge) {
    /* Force purge */
    LL_SORT(tun->tcp_nat_table, nat_entry_cmp_timestamp_asc);

    LL_FOREACH_SAFE(tun->tcp_nat_table, entry, tmp) {
      debug("FORCE TCP PURGE");
      purge_tcp_entry(tun, entry, NULL);

      if(--max_purge <= 0)
        break;
    }
  } else {
    /* Idle purge */
    prev = NULL;
    LL_FOREACH_SAFE(tun->tcp_nat_table, entry, tmp) {
      if((now - entry->tstamp) >= TCP_TIMEOUT_SEC) {
        debug("IDLE TCP");
        purge_tcp_entry(tun, entry, prev);
      } else
        prev = entry;
    }
  }

  /* UDP */
  if(forced_udp_purge) {
    /* Force purge */
    LL_SORT(tun->udp_nat_table, nat_entry_cmp_timestamp_asc);

    LL_FOREACH_SAFE(tun->udp_nat_table, entry, tmp) {
      debug("FORCE UDP PURGE");
      purge_nat_entry(tun, entry, &tun->udp_nat_table, NULL);

      if(--max_purge <= 0)
        break;
    }
  } else {
    /* Idle purge */
    prev = NULL;
    LL_FOREACH_SAFE(tun->udp_nat_table, entry, tmp) {
      if((now - entry->tstamp) >= UDP_TIMEOUT_SEC) {
        debug("IDLE UDP");

        purge_nat_entry(tun, entry, &tun->udp_nat_table, prev);
      } else
        prev = entry;
    }
  }
}

/* ******************************************************* */

void zdtun_get_stats(zdtun_t *tun, zdtun_statistics_t *stats) {
  struct nat_entry *icmp_entry;
  struct nat_entry *entry;

  memset(stats, 0, sizeof(*stats));
  
  LL_FOREACH(tun->icmp_nat_table, icmp_entry) {
    stats->num_icmp_entries++;
    stats->oldest_icmp_entry = (stats->oldest_icmp_entry) ? (min(stats->oldest_icmp_entry, icmp_entry->tstamp)) : icmp_entry->tstamp;
  }

  LL_FOREACH(tun->tcp_nat_table, entry) {
    stats->num_tcp_entries++;
    stats->oldest_tcp_entry = (stats->oldest_tcp_entry) ? (min(stats->oldest_tcp_entry, entry->tstamp)) : entry->tstamp;
  }

  LL_FOREACH(tun->udp_nat_table, entry) {
    stats->num_udp_entries++;
    stats->oldest_udp_entry = (stats->oldest_udp_entry) ? (min(stats->oldest_udp_entry, entry->tstamp)) : entry->tstamp;
  }

  stats->num_open_sockets = tun->num_open_socks;

  // totals
  stats->num_icmp_opened = tun->num_icmp_opened;
  stats->num_udp_opened = tun->num_udp_opened;
  stats->num_tcp_opened = tun->num_tcp_opened;
}
