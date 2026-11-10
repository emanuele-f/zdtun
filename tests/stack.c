/* ----------------------------------------------------------------------------
 * Zero Dep Tunnel: VPN library without dependencies
 * ----------------------------------------------------------------------------
 *
 * Copyright (C) 2026 - Emanuele Faranda
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
 * General tests of the zdtun TCP/IP stack.
 *
 * The test acts as the client, by crafting the IP packets and capturing the
 * zdtun replies, and as the server, via a loopback socket.
 */

#include "test_utils.h"

#define CLIENT_IP6 "fd00::2"
#define SERVER_IP6 "fd00::1"
#define IPV4_TCP_HEADERS_LEN (sizeof(struct iphdr) + sizeof(struct tcphdr))
#define TCP_OPT_MSS 2
#define TCP_OPT_MSS_LEN 4
#define TCP_OPT_END 0
#define TCP_OPT_NOP 1
#define TCP_OPT_WSCALE 3
#define TCP_OPT_WSCALE_LEN 3
#define MAX_WINDOW_SCALE 14
#define DEFAULT_MTU 1500
#define POLL_TIMEOUT_USEC 100000
#define SOCKS5_REQ_LEN 10
#define SOCKS5_REQ6_LEN 22

static char client_rx[STREAM_SIZE];
static uint8_t force_connect_in_progress;
static int force_connect_error;
static int force_socket_error;

/* ******************************************************* */

int __real_connect(int sock, const struct sockaddr *addr, socklen_t addr_len);

// A loopback connect normally completes immediately
int __wrap_connect(int sock, const struct sockaddr *addr, socklen_t addr_len) {
  if(force_connect_error) {
    errno = force_connect_error;
    return -1;
  }

  int rv = __real_connect(sock, addr, addr_len);

  if(force_connect_in_progress && (rv == 0)) {
    errno = EINPROGRESS;
    return -1;
  }

  return rv;
}

/* ******************************************************* */

int __real_socket(int domain, int type, int protocol);

int __wrap_socket(int domain, int type, int protocol) {
  if(force_socket_error) {
    errno = force_socket_error;
    return -1;
  }

  return __real_socket(domain, type, protocol);
}

/* ******************************************************* */

static uint32_t checksum_add(uint32_t sum, const void *data, int len) {
  const uint8_t *p = (const uint8_t*) data;

  for(int i = 0; i < len; i++)
    sum += (i & 1) ? p[i] : (p[i] << 8);

  return sum;
}

/* ******************************************************* */

// Verifies that the reply is addressed to the client and has a valid L4 checksum
static void verify_reply(test_ctx_t *ctx, zdtun_pkt_t *pkt) {
  uint16_t l4_len = pkt->len - pkt->ip_hdr_len;
  uint8_t ipproto = pkt->tuple.ipproto;
  uint8_t pseudo[4] = {0, ipproto, l4_len >> 8, l4_len & 0xFF};
  uint32_t sum = 0;

  assert(pkt->tuple.ipver == ctx->ipver);
  assert(zdtun_cmp_ip(ctx->ipver, &pkt->tuple.src_ip, &ctx->server_ip) == 0);
  assert(zdtun_cmp_ip(ctx->ipver, &pkt->tuple.dst_ip, &ctx->client_ip) == 0);

  if((ipproto == IPPROTO_UDP) && (pkt->udp->uh_sum == 0)) {
    // the UDP checksum is optional on IPv4, while on IPv6 0 is invalid (RFC 8200 8.1)
    assert(ctx->ipver == 4);
    return;
  }

  if(ctx->ipver == 4) {
    sum = checksum_add(sum, &pkt->ip4->saddr, 4);
    sum = checksum_add(sum, &pkt->ip4->daddr, 4);
  } else {
    sum = checksum_add(sum, &pkt->ip6->saddr, 16);
    sum = checksum_add(sum, &pkt->ip6->daddr, 16);
  }

  sum = checksum_add(sum, pseudo, sizeof(pseudo));
  sum = checksum_add(sum, pkt->l4, l4_len);

  while(sum >> 16)
    sum = (sum & 0xFFFF) + (sum >> 16);

  assert(sum == 0xFFFF);
}

/* ******************************************************* */

// Returns the Window Scale option of the segment, -1 if missing
static int tcp_window_scale_opt(const struct tcphdr *tcp) {
  const uint8_t *opts = (const uint8_t*) tcp + sizeof(*tcp);
  int optslen = tcp->th_off * 4 - sizeof(*tcp);

  while(optslen > 0) {
    uint8_t kind = opts[0];

    if(kind == TCP_OPT_END)
      break;

    if(kind == TCP_OPT_NOP) {
      opts++;
      optslen--;
      continue;
    }

    assert((optslen >= 2) && (opts[1] >= 2) && (opts[1] <= optslen));

    if((kind == TCP_OPT_WSCALE) && (opts[1] == TCP_OPT_WSCALE_LEN))
      return opts[2];

    optslen -= opts[1];
    opts += opts[1];
  }

  return -1;
}

/* ******************************************************* */

static void store_client_rx(test_ctx_t *ctx, zdtun_pkt_t *pkt) {
  assert((ctx->rx_len + pkt->l7_len) <= STREAM_SIZE);
  memcpy(client_rx + ctx->rx_len, pkt->l7, pkt->l7_len);

  ctx->rx_len += pkt->l7_len;
}

/* ******************************************************* */

// Captures the packets sent to the client
static int on_send_client(zdtun_t *tun, zdtun_pkt_t *pkt, const zdtun_conn_t *conn_info) {
  test_ctx_t *ctx = (test_ctx_t*) zdtun_userdata(tun);

  verify_reply(ctx, pkt);

  if(pkt->tuple.ipproto == IPPROTO_UDP) {
    store_client_rx(ctx, pkt);
    return 0;
  }

  // The client is in SYN_SENT until the SYN+ACK
  if(!(pkt->tcp->th_flags & (TH_SYN | TH_RST)))
    assert(ctx->syn_ack_received);

  // A RST is only accepted if its sequence number is exactly the next expected one
  // (RFC 5961 3.2), except in SYN_SENT, where only its ACK is checked (RFC 9293 3.10.7.3)
  if(!(pkt->tcp->th_flags & TH_SYN) && ctx->syn_ack_received)
    assert(ntohl(pkt->tcp->th_seq) == ctx->server_seq);

  if(pkt->tcp->th_flags & TH_RST) {
    ctx->num_rsts++;

    if(ctx->fail_rst)
      return -1;
  }

  if(pkt->len > ctx->max_pkt_len)
    ctx->max_pkt_len = pkt->len;

  if(pkt->tcp->th_flags & TH_ACK)
    ctx->last_ack = ntohl(pkt->tcp->th_ack);

  // The data is queued until the client ACKs the SYN+ACK (RFC 9293 3.10.2)
  if(pkt->l7_len > 0)
    assert(ctx->syn_ack_acked);

  if(pkt->tcp->th_flags & TH_SYN) {
    ctx->syn_ack_received = 1;
    ctx->server_seq = ntohl(pkt->tcp->th_seq) + 1;
    ctx->syn_ack_window = ntohs(pkt->tcp->th_win);
    ctx->syn_ack_wscale = tcp_window_scale_opt(pkt->tcp);
  } else {
    store_client_rx(ctx, pkt);
    ctx->server_seq += pkt->l7_len;
  }

  if(pkt->tcp->th_flags & TH_FIN) {
    ctx->num_server_fins++;
    ctx->server_seq += 1;
  }

  return 0;
}

/* ******************************************************* */

// Acknowledges the data only up to the ack sequence number
static void client_ack_up_to(test_ctx_t *ctx, uint32_t ack) {
  uint32_t server_seq = ctx->server_seq;

  ctx->server_seq = ack;
  client_ack(ctx);
  ctx->server_seq = server_seq;
}

/* ******************************************************* */

static void client_syn_with_window(test_ctx_t *ctx, uint16_t window) {
  ctx->client_seq = CLIENT_ISN;
  ctx->client_window = window;
  client_send(ctx, TH_SYN, NULL, 0);
}

/* ******************************************************* */

// Like process_events, for when the sockets are expected not to be polled
static void poll_events(test_ctx_t *ctx) {
  fd_set rd_fds;
  fd_set wr_fds;
  int max_fd = 0;
  struct timeval timeout = {.tv_usec = POLL_TIMEOUT_USEC};

  zdtun_fds(ctx->tun, &max_fd, &rd_fds, &wr_fds);

  assert(select(max_fd + 1, &rd_fds, &wr_fds, NULL, &timeout) >= 0);

  zdtun_handle_fd(ctx->tun, &rd_fds, &wr_fds);
}

/* ******************************************************* */

static void test_connect_with_mss(test_ctx_t *ctx, uint16_t mss) {
  uint8_t opts[TCP_OPT_MSS_LEN] = {TCP_OPT_MSS, TCP_OPT_MSS_LEN, mss >> 8, mss & 0xFF};

  test_connect(ctx, opts, sizeof(opts));
}

/* ******************************************************* */

static void test_setup_with_mss(test_ctx_t *ctx, uint16_t mss) {
  test_init(ctx, on_send_client);
  test_connect_with_mss(ctx, mss);
}

/* ******************************************************* */

// Sends the first len bytes of the stream from the server, with the client
// ACKing the data, until it has been fully delivered to the client
static void transfer_stream(test_ctx_t *ctx, int len) {
  int sent = 0;

  while(ctx->rx_len < len) {
    if(sent < len) {
      // Non blocking, as this thread is also the one reading from the socket
      int rv = send(ctx->server_sock, stream + sent, len - sent, MSG_DONTWAIT);

      assert((rv > 0) || (errno == EAGAIN));

      if(rv > 0)
        sent += rv;
    }

    process_events(ctx);
    client_ack(ctx);
  }
}

/* ******************************************************* */

static int client_received_stream(test_ctx_t *ctx, int len) {
  return((ctx->rx_len == len) && (memcmp(client_rx, stream, len) == 0));
}

/* ******************************************************* */

static void test_large_mss_clamped_to_mtu() {
  test_ctx_t ctx;
  test_setup_with_mss(&ctx, 65535);

  transfer_stream(&ctx, STREAM_SIZE);

  assert(ctx.max_pkt_len <= DEFAULT_MTU);
  assert(client_received_stream(&ctx, STREAM_SIZE));

  test_teardown(&ctx);
}

/* ******************************************************* */

static void test_mss_clamped_to_configured_mtu() {
  int mtu = 1000;
  test_ctx_t ctx;

  test_init(&ctx, on_send_client);
  zdtun_set_mtu(ctx.tun, mtu);
  test_connect_with_mss(&ctx, DEFAULT_MTU - IPV4_TCP_HEADERS_LEN);

  transfer_stream(&ctx, STREAM_SIZE);

  assert(ctx.max_pkt_len <= mtu);
  assert(client_received_stream(&ctx, STREAM_SIZE));

  test_teardown(&ctx);
}

/* ******************************************************* */

static void test_small_mss_honored() {
  int mss = 536;
  test_ctx_t ctx;

  test_setup_with_mss(&ctx, mss);

  transfer_stream(&ctx, STREAM_SIZE);

  assert(ctx.max_pkt_len <= (int)(mss + IPV4_TCP_HEADERS_LEN));
  assert(client_received_stream(&ctx, STREAM_SIZE));

  test_teardown(&ctx);
}

/* ******************************************************* */

// A 0 bytes recv would be mistaken for the server closing the connection
static void test_zero_mss_ignored() {
  test_ctx_t ctx;
  test_setup_with_mss(&ctx, 0);

  assert(send(ctx.server_sock, stream, PAYLOAD_SIZE, 0) == PAYLOAD_SIZE);
  process_events(&ctx);

  assert(ctx.num_server_fins == 0);
  assert(client_received_stream(&ctx, PAYLOAD_SIZE));

  test_teardown(&ctx);
}

/* ******************************************************* */

// The buffer has the exact size of the headers, for ASan to detect reads past the packet
static char* alloc_syn(test_ctx_t *ctx, uint8_t ihl, uint8_t th_off) {
  char *buf = calloc(1, IPV4_TCP_HEADERS_LEN);
  assert(buf != NULL);

  struct iphdr *ip = (struct iphdr*) buf;
  struct tcphdr *tcp = (struct tcphdr*) (buf + sizeof(struct iphdr));

  ip->version = 4;
  ip->ihl = ihl;
  ip->tot_len = htons(IPV4_TCP_HEADERS_LEN);
  ip->ttl = 64;
  ip->protocol = IPPROTO_TCP;
  ip->saddr = inet_addr(CLIENT_IP);
  ip->daddr = inet_addr(SERVER_IP);

  tcp->th_sport = htons(CLIENT_PORT);
  tcp->th_dport = htons(ctx->server_port);
  tcp->th_seq = htonl(CLIENT_ISN);
  tcp->th_off = th_off;
  tcp->th_flags = TH_SYN;
  tcp->th_win = htons(CLIENT_WINDOW);

  return buf;
}

/* ******************************************************* */

static int parse_syn(test_ctx_t *ctx, uint8_t ihl, uint8_t th_off) {
  char *buf = alloc_syn(ctx, ihl, th_off);
  zdtun_pkt_t pkt;
  int rv = zdtun_parse_pkt(ctx->tun, buf, IPV4_TCP_HEADERS_LEN, &pkt);

  free(buf);
  return rv;
}

/* ******************************************************* */

static void test_short_tcp_data_offset_rejected() {
  test_ctx_t ctx;
  test_init(&ctx, on_send_client);

  for(uint8_t th_off = 0; th_off < 5; th_off++)
    assert(parse_syn(&ctx, 5, th_off) == -1);

  assert(parse_syn(&ctx, 5, 5) == 0);

  test_teardown(&ctx);
}

/* ******************************************************* */

static void test_short_ipv4_ihl_rejected() {
  test_ctx_t ctx;
  test_init(&ctx, on_send_client);

  for(uint8_t ihl = 0; ihl < 5; ihl++)
    assert(parse_syn(&ctx, ihl, 5) == -1);

  assert(parse_syn(&ctx, 5, 5) == 0);

  test_teardown(&ctx);
}

/* ******************************************************* */

// The options length would underflow, reading the options past the end of the packet
static void test_syn_short_data_offset_not_forwarded() {
  test_ctx_t ctx;
  test_init(&ctx, on_send_client);

  char *buf = alloc_syn(&ctx, 5, 0);

  assert(zdtun_easy_forward(ctx.tun, buf, IPV4_TCP_HEADERS_LEN) == NULL);
  assert(!ctx.syn_ack_received);

  free(buf);
  test_teardown(&ctx);
}

/* ******************************************************* */

static zdtun_conn_t* lookup_client_conn(test_ctx_t *ctx, uint8_t create) {
  char *buf = alloc_syn(ctx, 5, 5);
  zdtun_pkt_t pkt;

  assert(zdtun_parse_pkt(ctx->tun, buf, IPV4_TCP_HEADERS_LEN, &pkt) == 0);

  zdtun_conn_t *conn = zdtun_lookup(ctx->tun, &pkt.tuple, create);
  assert(conn != NULL);

  free(buf);
  return conn;
}

/* ******************************************************* */

static void test_rst_delivered_on_close() {
  test_ctx_t ctx;
  test_setup_with_mss(&ctx, 1000);

  zdtun_conn_t *conn = lookup_client_conn(&ctx, 0);
  zdtun_conn_close(ctx.tun, conn, CONN_STATUS_SOCKET_ERROR);

  assert(ctx.num_rsts == 1);
  assert(ctx.num_closes == 1);
  assert(ctx.close_status == CONN_STATUS_SOCKET_ERROR);

  test_teardown(&ctx);
}

/* ******************************************************* */

static void test_failed_rst_closes_once() {
  test_ctx_t ctx;
  test_setup_with_mss(&ctx, 1000);

  ctx.fail_rst = 1;

  zdtun_conn_t *conn = lookup_client_conn(&ctx, 0);
  zdtun_conn_close(ctx.tun, conn, CONN_STATUS_SOCKET_ERROR);

  assert(ctx.num_rsts == 1);
  assert(ctx.num_closes == 1);
  assert(ctx.close_status == CONN_STATUS_SOCKET_ERROR);
  assert(zdtun_conn_get_status(conn) == CONN_STATUS_SOCKET_ERROR);

  test_teardown(&ctx);
}

/* ******************************************************* */

static void test_failed_rst_on_destroy_closes_once() {
  test_ctx_t ctx;
  test_setup_with_mss(&ctx, 1000);

  ctx.fail_rst = 1;

  test_teardown(&ctx);

  assert(ctx.num_rsts == 1);
  assert(ctx.num_closes == 1);
  assert(ctx.close_status == CONN_STATUS_CLOSED);
}

/* ******************************************************* */

// A client in SYN_SENT only accepts a RST which acknowledges its SYN
static void test_connect_error_rst_acks_syn() {
  test_ctx_t ctx;
  test_init(&ctx, on_send_client);

  force_connect_error = ENETUNREACH;
  client_syn_with_window(&ctx, CLIENT_WINDOW);
  force_connect_error = 0;

  assert(!ctx.syn_ack_received);
  assert(ctx.num_rsts == 1);
  assert(ctx.last_ack == (CLIENT_ISN + 1));
  assert(ctx.num_closes == 1);
  assert(ctx.close_status == CONN_STATUS_UNREACHABLE);

  test_teardown(&ctx);
}

/* ******************************************************* */

// Like a connection blocked by the integrator, which is created but never forwarded
static void test_unforwarded_conn_close_sends_no_rst() {
  test_ctx_t ctx;
  test_init(&ctx, on_send_client);

  zdtun_conn_t *conn = lookup_client_conn(&ctx, 1);
  zdtun_conn_close(ctx.tun, conn, CONN_STATUS_CLOSED);

  assert(ctx.num_rsts == 0);
  assert(ctx.num_closes == 1);

  test_teardown(&ctx);

  assert(ctx.num_rsts == 0);
  assert(ctx.num_closes == 1);
}

/* ******************************************************* */

static void test_unforwarded_conn_destroy_sends_no_rst() {
  test_ctx_t ctx;
  test_init(&ctx, on_send_client);

  zdtun_conn_t *conn = lookup_client_conn(&ctx, 1);
  assert(zdtun_conn_get_status(conn) == CONN_STATUS_NEW);

  test_teardown(&ctx);

  assert(ctx.num_rsts == 0);
  assert(ctx.num_closes == 1);
  assert(ctx.close_status == CONN_STATUS_CLOSED);
}

/* ******************************************************* */

// Like PCAPdroid, which closes the connection when zdtun_forward fails
static void forward_with_socket_error(test_ctx_t *ctx, const char *buf, int len) {
  zdtun_pkt_t pkt;

  assert(zdtun_parse_pkt(ctx->tun, buf, len, &pkt) == 0);

  zdtun_conn_t *conn = zdtun_lookup(ctx->tun, &pkt.tuple, 1);
  assert(conn != NULL);

  force_socket_error = EMFILE;
  assert(zdtun_forward(ctx->tun, &pkt, conn) != 0);
  force_socket_error = 0;

  assert(zdtun_conn_get_status(conn) == CONN_STATUS_SOCKET_ERROR);
  zdtun_conn_close(ctx->tun, conn, CONN_STATUS_ERROR);
}

/* ******************************************************* */

static void test_tcp_socket_error_closes_conn() {
  test_ctx_t ctx;
  test_init(&ctx, on_send_client);

  char *buf = alloc_syn(&ctx, 5, 5);
  forward_with_socket_error(&ctx, buf, IPV4_TCP_HEADERS_LEN);
  free(buf);

  assert(ctx.num_closes == 1);
  assert(ctx.close_status == CONN_STATUS_SOCKET_ERROR);
  assert(ctx.num_rsts == 1);
  assert(ctx.last_ack == (CLIENT_ISN + 1));

  test_teardown(&ctx);

  assert(ctx.num_closes == 1);
  assert(ctx.num_rsts == 1);
}

/* ******************************************************* */

static void test_icmp_socket_error_closes_conn() {
  char buf[sizeof(struct iphdr) + sizeof(struct icmphdr)] __attribute__((aligned(4)));
  test_ctx_t ctx;
  test_init(&ctx, on_send_client);

  int iphdr_len = client_iphdr(&ctx, buf, IPPROTO_ICMP, sizeof(struct icmphdr));
  struct icmphdr *icmp = (struct icmphdr*) (buf + iphdr_len);

  memset(icmp, 0, sizeof(*icmp));
  icmp->type = ICMP_ECHO;
  icmp->un.echo.id = htons(CLIENT_PORT);

  forward_with_socket_error(&ctx, buf, sizeof(buf));

  assert(ctx.num_closes == 1);
  assert(ctx.close_status == CONN_STATUS_SOCKET_ERROR);

  test_teardown(&ctx);

  assert(ctx.num_closes == 1);
}

/* ******************************************************* */

static void server_send(test_ctx_t *ctx, int len) {
  assert(send(ctx->server_sock, stream, len, 0) == len);
}

/* ******************************************************* */

static void assert_connection_alive(test_ctx_t *ctx) {
  assert(ctx->num_server_fins == 0);
  assert(ctx->num_closes == 0);
}

/* ******************************************************* */

// Reopens the window, then expects the pending server data to be delivered
static void assert_data_flows_after_window_update(test_ctx_t *ctx, int total_len) {
  ctx->client_window = CLIENT_WINDOW;
  client_ack(ctx);

  while(ctx->rx_len < total_len) {
    process_events(ctx);
    client_ack(ctx);
  }

  assert_connection_alive(ctx);
  assert(client_received_stream(ctx, total_len));
}

/* ******************************************************* */

static void test_zero_window_ack_keeps_connection() {
  test_ctx_t ctx;
  test_setup_with_mss(&ctx, PAYLOAD_SIZE);

  server_send(&ctx, 2 * PAYLOAD_SIZE);

  ctx.client_window = 0;
  client_ack(&ctx);

  poll_events(&ctx);

  assert_connection_alive(&ctx);
  assert(ctx.rx_len == 0);
  assert(!zdtun_polls_reads(&ctx));

  assert_data_flows_after_window_update(&ctx, 2 * PAYLOAD_SIZE);

  // The server EOF must still be detected
  assert(shutdown(ctx.server_sock, SHUT_WR) == 0);
  process_events(&ctx);

  assert(ctx.num_server_fins == 1);

  test_teardown(&ctx);
}

/* ******************************************************* */

static void test_window_filled_by_in_flight_keeps_connection() {
  test_ctx_t ctx;
  test_setup_with_mss(&ctx, PAYLOAD_SIZE);

  uint32_t first_ack = ctx.server_seq;

  server_send(&ctx, 2 * PAYLOAD_SIZE);
  process_events(&ctx);

  assert(ctx.rx_len == PAYLOAD_SIZE);

  ctx.client_window = PAYLOAD_SIZE;
  client_ack_up_to(&ctx, first_ack);

  poll_events(&ctx);

  assert_connection_alive(&ctx);
  assert(ctx.rx_len == PAYLOAD_SIZE);
  assert(!zdtun_polls_reads(&ctx));

  assert_data_flows_after_window_update(&ctx, 2 * PAYLOAD_SIZE);

  test_teardown(&ctx);
}

/* ******************************************************* */

static void test_window_shrink_not_overrun() {
  test_ctx_t ctx;
  test_setup_with_mss(&ctx, PAYLOAD_SIZE);

  uint32_t first_ack = ctx.server_seq;

  server_send(&ctx, 3 * PAYLOAD_SIZE);
  process_events(&ctx);

  assert(ctx.rx_len == PAYLOAD_SIZE);

  // Smaller than the bytes in flight
  ctx.client_window = PAYLOAD_SIZE / 2;
  client_ack_up_to(&ctx, first_ack);

  poll_events(&ctx);

  assert_connection_alive(&ctx);
  assert(ctx.rx_len == PAYLOAD_SIZE);

  // Only the advertised window can be used
  client_ack(&ctx);
  poll_events(&ctx);
  poll_events(&ctx);

  assert_connection_alive(&ctx);
  assert(ctx.rx_len == (PAYLOAD_SIZE + (PAYLOAD_SIZE / 2)));

  assert_data_flows_after_window_update(&ctx, 3 * PAYLOAD_SIZE);

  test_teardown(&ctx);
}

/* ******************************************************* */

static void test_zero_window_syn_keeps_connection() {
  test_ctx_t ctx;
  test_init(&ctx, on_send_client);

  client_syn_with_window(&ctx, 0);

  // A loopback connect can either complete immediately or be in progress
  while(!ctx.syn_ack_received)
    process_events(&ctx);

  accept_server_sock(&ctx);
  server_send(&ctx, PAYLOAD_SIZE);

  poll_events(&ctx);

  assert_connection_alive(&ctx);
  assert(ctx.rx_len == 0);

  assert_data_flows_after_window_update(&ctx, PAYLOAD_SIZE);

  test_teardown(&ctx);
}

/* ******************************************************* */

// The connect result must not be hidden by the readable event of the server data
static void test_zero_window_syn_connect_in_progress() {
  test_ctx_t ctx;
  test_init(&ctx, on_send_client);

  force_connect_in_progress = 1;
  client_syn_with_window(&ctx, 0);
  assert(!ctx.syn_ack_received);

  accept_server_sock(&ctx);
  server_send(&ctx, PAYLOAD_SIZE);

  process_events(&ctx);

  assert(ctx.syn_ack_received);
  assert_connection_alive(&ctx);
  assert(!zdtun_polls_reads(&ctx));

  assert_data_flows_after_window_update(&ctx, PAYLOAD_SIZE);

  test_teardown(&ctx);
}

/* ******************************************************* */

// The client can reduce the window after zdtun_fds has reported the socket as readable
static void test_stale_read_event_with_zero_window() {
  test_ctx_t ctx;
  fd_set rd_fds;
  fd_set wr_fds;
  int max_fd = 0;
  struct timeval timeout = {.tv_sec = IO_TIMEOUT_SEC};

  test_setup_with_mss(&ctx, PAYLOAD_SIZE);
  server_send(&ctx, PAYLOAD_SIZE);

  zdtun_fds(ctx.tun, &max_fd, &rd_fds, &wr_fds);
  assert(select(max_fd + 1, &rd_fds, &wr_fds, NULL, &timeout) == 1);

  ctx.client_window = 0;
  client_ack(&ctx);

  zdtun_handle_fd(ctx.tun, &rd_fds, &wr_fds);

  assert_connection_alive(&ctx);
  assert(ctx.rx_len == 0);

  assert_data_flows_after_window_update(&ctx, PAYLOAD_SIZE);

  test_teardown(&ctx);
}

/* ******************************************************* */

static void test_zero_window_upload_delivered() {
  test_ctx_t ctx;
  test_setup_with_mss(&ctx, PAYLOAD_SIZE);
  server_send(&ctx, PAYLOAD_SIZE);

  ctx.client_window = 0;
  client_send(&ctx, TH_ACK | TH_PUSH, stream, PAYLOAD_SIZE);

  process_events(&ctx);

  assert_connection_alive(&ctx);
  assert(ctx.rx_len == 0);

  assert(server_received_stream(&ctx, PAYLOAD_SIZE));

  assert_data_flows_after_window_update(&ctx, PAYLOAD_SIZE);

  test_teardown(&ctx);
}

/* ******************************************************* */

// The SOCKS5 handshake is not delivered to the client, so its window does not apply
static void test_zero_window_syn_socks5_handshake() {
  test_ctx_t ctx;
  zdtun_ip_t proxy_ip = {0};
  char rx[16];
  const char srv_choice[] = {5, 0};
  const char connect_reply[SOCKS5_REQ_LEN] = {5, 0, 0, 1};

  test_init(&ctx, on_send_client);

  proxy_ip.ip4 = inet_addr(SERVER_IP);
  zdtun_set_socks5_proxy(ctx.tun, &proxy_ip, htons(ctx.server_port), 4);
  zdtun_conn_proxy(lookup_client_conn(&ctx, 1));

  client_syn_with_window(&ctx, 0);
  accept_server_sock(&ctx);

  // Completes the connect, if in progress
  poll_events(&ctx);

  assert(recv(ctx.server_sock, rx, sizeof(rx), 0) == 3);
  assert(send(ctx.server_sock, srv_choice, sizeof(srv_choice), 0) == sizeof(srv_choice));
  process_events(&ctx);

  assert(recv(ctx.server_sock, rx, sizeof(rx), 0) == SOCKS5_REQ_LEN);
  assert(send(ctx.server_sock, connect_reply, sizeof(connect_reply), 0) == sizeof(connect_reply));
  process_events(&ctx);

  assert(ctx.syn_ack_received);
  assert_connection_alive(&ctx);
  assert(!zdtun_polls_reads(&ctx));

  server_send(&ctx, PAYLOAD_SIZE);
  poll_events(&ctx);

  assert_connection_alive(&ctx);
  assert(ctx.rx_len == 0);

  assert_data_flows_after_window_update(&ctx, PAYLOAD_SIZE);

  test_teardown(&ctx);
}

/* ******************************************************* */

// The client is still waiting for the SYN+ACK, so it only accepts a RST
static void test_socks5_server_close_during_handshake() {
  test_ctx_t ctx;
  zdtun_ip_t proxy_ip = {0};
  char rx[16];

  test_init(&ctx, on_send_client);

  proxy_ip.ip4 = inet_addr(SERVER_IP);
  zdtun_set_socks5_proxy(ctx.tun, &proxy_ip, htons(ctx.server_port), 4);
  zdtun_conn_proxy(lookup_client_conn(&ctx, 1));

  client_syn_with_window(&ctx, CLIENT_WINDOW);
  accept_server_sock(&ctx);

  // Completes the connect, if in progress
  poll_events(&ctx);

  assert(recv(ctx.server_sock, rx, sizeof(rx), 0) == 3);
  close_server_socket(&ctx);

  assert(!ctx.syn_ack_received);
  assert(ctx.num_rsts == 1);
  assert(ctx.last_ack == (CLIENT_ISN + 1));
  assert(ctx.num_closes == 1);
  assert(ctx.close_status == CONN_STATUS_SOCKS5_ERROR);

  test_teardown(&ctx);
}

/* ******************************************************* */

// Sends a SYN with the Window Scale option, then waits for the SYN+ACK
static void connect_with_window_scale(test_ctx_t *ctx, uint16_t window, uint8_t scale) {
  uint8_t opts[] = {
    TCP_OPT_MSS, TCP_OPT_MSS_LEN, 0xFF, 0xFF,
    TCP_OPT_NOP, TCP_OPT_WSCALE, TCP_OPT_WSCALE_LEN, scale,
  };

  ctx->client_seq = CLIENT_ISN;
  ctx->client_window = window;
  client_send_opts(ctx, TH_SYN, opts, sizeof(opts), NULL, 0);

  while(!ctx->syn_ack_received)
    process_events(ctx);

  accept_server_sock(ctx);
}

/* ******************************************************* */

static void test_large_window_scale_clamped() {
  test_ctx_t ctx;
  test_init(&ctx, on_send_client);

  connect_with_window_scale(&ctx, 1, 200);

  // The scale advertised by zdtun is independent, it only has to be valid
  assert((ctx.syn_ack_wscale >= 0) && (ctx.syn_ack_wscale <= MAX_WINDOW_SCALE));

  // The client window must be interpreted with a shift of 14 (RFC 7323 2.3)
  client_ack(&ctx);
  server_send(&ctx, 20 * PAYLOAD_SIZE);

  for(int i = 0; i < 32; i++)
    poll_events(&ctx);

  assert_connection_alive(&ctx);
  assert(ctx.rx_len == (1 << MAX_WINDOW_SCALE));

  assert_data_flows_after_window_update(&ctx, 20 * PAYLOAD_SIZE);

  test_teardown(&ctx);
}

/* ******************************************************* */

static void test_syn_ack_window_not_scaled() {
  test_ctx_t ctx;
  test_init(&ctx, on_send_client);

  connect_with_window_scale(&ctx, CLIENT_WINDOW, 7);
  assert(ctx.syn_ack_wscale == 7);

  // Nothing has been sent yet, so the whole send buffer is available
  int sndbuf = 0;
  socklen_t len = sizeof(sndbuf);

  assert(getsockopt(ctx.zdtun_sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, &len) == 0);
  assert(ctx.syn_ack_window == ((sndbuf < 0xFFFF) ? sndbuf : 0xFFFF));

  test_teardown(&ctx);
}

/* ******************************************************* */

static void test_window_scale_not_sent_unsolicited() {
  test_ctx_t ctx;
  test_setup_with_mss(&ctx, PAYLOAD_SIZE);

  assert(ctx.syn_ack_wscale == -1);

  transfer_stream(&ctx, PAYLOAD_SIZE);
  assert(client_received_stream(&ctx, PAYLOAD_SIZE));

  test_teardown(&ctx);
}

/* ******************************************************* */

// Waits for the socket to become readable, so that the server data or EOF is
// already there when zdtun handles the connect completion
static void select_when_readable(test_ctx_t *ctx, fd_set *rd_fds, fd_set *wr_fds) {
  int max_fd = 0;
  struct timeval timeout = {.tv_sec = IO_TIMEOUT_SEC};

  zdtun_fds(ctx->tun, &max_fd, rd_fds, wr_fds);
  assert(select(max_fd + 1, rd_fds, NULL, NULL, &timeout) == 1);

  zdtun_fds(ctx->tun, &max_fd, rd_fds, wr_fds);
  assert(select(max_fd + 1, rd_fds, wr_fds, NULL, &timeout) == 2);
}

/* ******************************************************* */

static void process_events_when_readable(test_ctx_t *ctx) {
  fd_set rd_fds;
  fd_set wr_fds;

  select_when_readable(ctx, &rd_fds, &wr_fds);
  zdtun_handle_fd(ctx->tun, &rd_fds, &wr_fds);
}

/* ******************************************************* */

static void connect_in_progress(test_ctx_t *ctx) {
  force_connect_in_progress = 1;
  client_syn_with_window(ctx, CLIENT_WINDOW);
  assert(!ctx->syn_ack_received);

  accept_server_sock(ctx);
}

/* ******************************************************* */

static void test_server_data_before_connect_handled() {
  test_ctx_t ctx;

  test_init(&ctx, on_send_client);
  connect_in_progress(&ctx);
  server_send(&ctx, PAYLOAD_SIZE);

  process_events_when_readable(&ctx);

  assert(ctx.syn_ack_received);
  client_ack(&ctx);

  while(ctx.rx_len < PAYLOAD_SIZE) {
    process_events(&ctx);
    client_ack(&ctx);
  }

  assert_connection_alive(&ctx);
  assert(client_received_stream(&ctx, PAYLOAD_SIZE));
  assert(ctx.last_ack == ctx.client_seq);

  test_teardown(&ctx);
}

/* ******************************************************* */

static void test_server_eof_before_connect_handled() {
  test_ctx_t ctx;

  test_init(&ctx, on_send_client);
  connect_in_progress(&ctx);

  close(ctx.server_sock);
  ctx.server_sock = -1;

  process_events_when_readable(&ctx);

  assert(ctx.syn_ack_received);
  client_ack(&ctx);

  while(ctx.num_server_fins == 0)
    process_events(&ctx);

  assert(ctx.num_server_fins == 1);
  assert(ctx.rx_len == 0);
  assert(ctx.num_rsts == 0);
  assert(ctx.num_closes == 0);

  test_teardown(&ctx);
}

/* ******************************************************* */

static void test_server_reset_before_connect_handled() {
  test_ctx_t ctx;
  struct linger linger = {.l_onoff = 1, .l_linger = 0};

  test_init(&ctx, on_send_client);
  connect_in_progress(&ctx);

  zdtun_conn_t *conn = lookup_client_conn(&ctx, 0);

  assert(setsockopt(ctx.server_sock, SOL_SOCKET, SO_LINGER, &linger, sizeof(linger)) == 0);
  close(ctx.server_sock);
  ctx.server_sock = -1;

  process_events_when_readable(&ctx);

  assert(!ctx.syn_ack_received);
  assert(ctx.num_rsts == 1);
  assert(ctx.num_closes == 1);
  assert(ctx.close_status == CONN_STATUS_RESET);
  assert(zdtun_conn_get_error(conn) == ECONNRESET);

  test_teardown(&ctx);
}

/* ******************************************************* */

// The data is queued until the client ACKs the SYN+ACK (RFC 9293 3.10.2)
static void test_server_data_queued_until_handshake_ack() {
  test_ctx_t ctx;
  test_init(&ctx, on_send_client);

  connect_with_window_scale(&ctx, CLIENT_WINDOW, 7);
  server_send(&ctx, 5 * PAYLOAD_SIZE);

  poll_events(&ctx);
  poll_events(&ctx);

  assert_connection_alive(&ctx);
  assert(ctx.rx_len == 0);
  assert(!zdtun_polls_reads(&ctx));

  assert_data_flows_after_window_update(&ctx, 5 * PAYLOAD_SIZE);

  test_teardown(&ctx);
}

/* ******************************************************* */

// The read event reported with the connect completion must not deliver the data
static void test_stale_read_event_before_handshake_ack() {
  test_ctx_t ctx;
  fd_set rd_fds;
  fd_set wr_fds;

  test_init(&ctx, on_send_client);
  connect_in_progress(&ctx);
  server_send(&ctx, PAYLOAD_SIZE);

  select_when_readable(&ctx, &rd_fds, &wr_fds);
  zdtun_handle_fd(ctx.tun, &rd_fds, &wr_fds);
  assert(ctx.syn_ack_received);

  FD_ZERO(&wr_fds);
  zdtun_handle_fd(ctx.tun, &rd_fds, &wr_fds);

  assert_connection_alive(&ctx);
  assert(ctx.rx_len == 0);

  assert_data_flows_after_window_update(&ctx, PAYLOAD_SIZE);

  test_teardown(&ctx);
}

/* ******************************************************* */

static void client_retransmit(test_ctx_t *ctx, uint8_t flags, uint32_t seq, const char *data, int len) {
  uint32_t client_seq = ctx->client_seq;

  ctx->client_seq = seq;
  client_send(ctx, flags, data, len);

  if(!(flags & TH_FIN))
    ctx->client_seq = client_seq;
}

/* ******************************************************* */

static void test_retransmitted_byte_delivered_once() {
  test_ctx_t ctx;
  char rx[PAYLOAD_SIZE];

  test_setup_with_mss(&ctx, PAYLOAD_SIZE);

  uint32_t data_seq = ctx.client_seq;

  client_send(&ctx, TH_ACK | TH_PUSH, stream, 1);
  process_events(&ctx);

  assert(ctx.last_ack == ctx.client_seq);

  client_retransmit(&ctx, TH_ACK | TH_PUSH, data_seq, stream, 1);

  assert(ctx.last_ack == ctx.client_seq);

  client_send(&ctx, TH_ACK | TH_PUSH, stream + 1, PAYLOAD_SIZE - 1);
  process_events(&ctx);

  assert(ctx.last_ack == ctx.client_seq);

  assert(server_received_stream(&ctx, PAYLOAD_SIZE));
  assert(recv(ctx.server_sock, rx, sizeof(rx), MSG_DONTWAIT) < 0);

  assert_connection_alive(&ctx);

  test_teardown(&ctx);
}

/* ******************************************************* */

// The FIN is new, while the byte is a retransmission
static void test_retransmitted_byte_with_fin_delivered_once() {
  test_ctx_t ctx;
  char rx[2];

  test_setup_with_mss(&ctx, PAYLOAD_SIZE);

  uint32_t data_seq = ctx.client_seq;

  client_send(&ctx, TH_ACK | TH_PUSH, stream, 1);
  process_events(&ctx);

  client_retransmit(&ctx, TH_FIN | TH_ACK | TH_PUSH, data_seq, stream, 1);

  assert(ctx.client_seq == (data_seq + 2));
  assert(ctx.last_ack == ctx.client_seq);

  assert(recv(ctx.server_sock, rx, sizeof(rx), MSG_WAITALL) == 1);
  assert(rx[0] == stream[0]);

  test_teardown(&ctx);
}

/* ******************************************************* */

static void test_retransmitted_byte_delivered_once_after_server_eof() {
  test_ctx_t ctx;

  test_setup_with_mss(&ctx, PAYLOAD_SIZE);

  // The server half closes the connection, but keeps reading
  assert(shutdown(ctx.server_sock, SHUT_WR) == 0);
  process_events(&ctx);

  assert(ctx.num_server_fins == 1);

  uint32_t data_seq = ctx.client_seq;

  client_send(&ctx, TH_ACK | TH_PUSH, stream, 1);
  process_events(&ctx);

  assert(ctx.last_ack == ctx.client_seq);

  client_retransmit(&ctx, TH_ACK | TH_PUSH, data_seq, stream, 1);

  assert(ctx.last_ack == ctx.client_seq);

  client_send(&ctx, TH_ACK | TH_PUSH, stream + 1, PAYLOAD_SIZE - 1);
  process_events(&ctx);

  assert(ctx.last_ack == ctx.client_seq);
  assert(ctx.num_closes == 0);
  assert(server_received_stream(&ctx, PAYLOAD_SIZE));

  test_teardown(&ctx);
}

/* ******************************************************* */

static void test_init_ipv6(test_ctx_t *ctx) {
  test_init(ctx, on_send_client);

  ctx->ipver = 6;
  assert(inet_pton(AF_INET6, CLIENT_IP6, &ctx->client_ip.ip6) == 1);
  assert(inet_pton(AF_INET6, SERVER_IP6, &ctx->server_ip.ip6) == 1);
}

/* ******************************************************* */

static zdtun_conn_t* create_client_conn(test_ctx_t *ctx, uint8_t ipproto) {
  zdtun_5tuple_t tuple;

  memset(&tuple, 0, sizeof(tuple));
  tuple.src_ip = ctx->client_ip;
  tuple.dst_ip = ctx->server_ip;
  tuple.src_port = htons(CLIENT_PORT);
  tuple.dst_port = htons(ctx->server_port);
  tuple.ipver = ctx->ipver;
  tuple.ipproto = ipproto;

  zdtun_conn_t *conn = zdtun_lookup(ctx->tun, &tuple, 1);
  assert(conn != NULL);

  return conn;
}

/* ******************************************************* */

static void dnat_to_ipv4_server(test_ctx_t *ctx, uint8_t ipproto) {
  zdtun_ip_t server_ip = {0};

  server_ip.ip4 = inet_addr(SERVER_IP);
  zdtun_conn_dnat(create_client_conn(ctx, ipproto), &server_ip, htons(ctx->server_port), 4);
}

/* ******************************************************* */

static void assert_upload_delivered(test_ctx_t *ctx) {
  client_send(ctx, TH_ACK | TH_PUSH, stream, PAYLOAD_SIZE);
  process_events(ctx);

  assert(ctx->last_ack == ctx->client_seq);
  assert(server_received_stream(ctx, PAYLOAD_SIZE));
}

/* ******************************************************* */

static void test_ipv6_client_tcp_dnat_to_ipv4() {
  test_ctx_t ctx;

  test_init_ipv6(&ctx);
  dnat_to_ipv4_server(&ctx, IPPROTO_TCP);
  test_connect_with_mss(&ctx, 65535);

  transfer_stream(&ctx, STREAM_SIZE);

  assert(ctx.max_pkt_len <= DEFAULT_MTU);
  assert(client_received_stream(&ctx, STREAM_SIZE));

  assert_upload_delivered(&ctx);
  assert_connection_alive(&ctx);

  test_teardown(&ctx);
}

/* ******************************************************* */

static void open_udp_server(test_ctx_t *ctx) {
  struct sockaddr_in addr = {0};
  socklen_t addr_len = sizeof(addr);

  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = inet_addr(SERVER_IP);

  ctx->server_sock = socket(AF_INET, SOCK_DGRAM, 0);
  assert(ctx->server_sock >= 0);

  set_recv_timeout(ctx->server_sock);

  assert(bind(ctx->server_sock, (struct sockaddr*) &addr, sizeof(addr)) == 0);
  assert(getsockname(ctx->server_sock, (struct sockaddr*) &addr, &addr_len) == 0);

  ctx->server_port = ntohs(addr.sin_port);
}

/* ******************************************************* */

static void client_send_udp(test_ctx_t *ctx, const char *data, int len) {
  static char buf[sizeof(struct ipv6_hdr) + sizeof(struct udphdr) + PAYLOAD_SIZE] __attribute__((aligned(4)));
  int l4_len = sizeof(struct udphdr) + len;

  assert(len <= PAYLOAD_SIZE);

  int iphdr_len = client_iphdr(ctx, buf, IPPROTO_UDP, l4_len);
  struct udphdr *udp = (struct udphdr*) (buf + iphdr_len);

  udp->uh_sport = htons(CLIENT_PORT);
  udp->uh_dport = htons(ctx->server_port);
  udp->uh_ulen = htons(l4_len);
  udp->uh_sum = 0;

  memcpy(buf + iphdr_len + sizeof(struct udphdr), data, len);

  assert(zdtun_easy_forward(ctx->tun, buf, iphdr_len + l4_len) != NULL);
}

/* ******************************************************* */

static void test_ipv6_client_udp_dnat_to_ipv4() {
  test_ctx_t ctx;
  char rx[PAYLOAD_SIZE];
  struct sockaddr_in addr;
  socklen_t addr_len = sizeof(addr);

  test_init_ipv6(&ctx);
  open_udp_server(&ctx);
  dnat_to_ipv4_server(&ctx, IPPROTO_UDP);

  client_send_udp(&ctx, stream, PAYLOAD_SIZE);

  assert(recvfrom(ctx.server_sock, rx, sizeof(rx), 0, (struct sockaddr*) &addr, &addr_len) == PAYLOAD_SIZE);
  assert(memcmp(rx, stream, PAYLOAD_SIZE) == 0);

  assert(sendto(ctx.server_sock, stream, PAYLOAD_SIZE, 0, (struct sockaddr*) &addr, addr_len) == PAYLOAD_SIZE);
  process_events(&ctx);

  assert(client_received_stream(&ctx, PAYLOAD_SIZE));
  assert(ctx.num_closes == 0);

  test_teardown(&ctx);
}

/* ******************************************************* */

// Returns a payload word which makes the checksum of the UDP reply 0
static uint16_t zero_udp_checksum_word(test_ctx_t *ctx) {
  uint16_t l4_len = sizeof(struct udphdr) + 2;
  uint8_t pseudo[4] = {0, IPPROTO_UDP, l4_len >> 8, l4_len & 0xFF};
  uint8_t udp[8] = {ctx->server_port >> 8, ctx->server_port & 0xFF,
          CLIENT_PORT >> 8, CLIENT_PORT & 0xFF, l4_len >> 8, l4_len & 0xFF, 0, 0};
  uint32_t sum = 0;

  sum = checksum_add(sum, &ctx->server_ip.ip6, 16);
  sum = checksum_add(sum, &ctx->client_ip.ip6, 16);
  sum = checksum_add(sum, pseudo, sizeof(pseudo));
  sum = checksum_add(sum, udp, sizeof(udp));

  while(sum >> 16)
    sum = (sum & 0xFFFF) + (sum >> 16);

  return 0xFFFF - sum;
}

/* ******************************************************* */

static void test_ipv6_udp_zero_checksum_not_sent() {
  test_ctx_t ctx;
  char rx[PAYLOAD_SIZE];
  struct sockaddr_in addr;
  socklen_t addr_len = sizeof(addr);

  test_init_ipv6(&ctx);
  open_udp_server(&ctx);
  dnat_to_ipv4_server(&ctx, IPPROTO_UDP);

  client_send_udp(&ctx, stream, PAYLOAD_SIZE);
  assert(recvfrom(ctx.server_sock, rx, sizeof(rx), 0, (struct sockaddr*) &addr, &addr_len) == PAYLOAD_SIZE);

  uint16_t word = zero_udp_checksum_word(&ctx);
  uint8_t payload[2] = {word >> 8, word & 0xFF};

  assert(sendto(ctx.server_sock, payload, sizeof(payload), 0, (struct sockaddr*) &addr, addr_len) == sizeof(payload));
  process_events(&ctx);

  assert(ctx.rx_len == sizeof(payload));
  assert(memcmp(client_rx, payload, sizeof(payload)) == 0);

  test_teardown(&ctx);
}

/* ******************************************************* */

static void assert_udp_to_scoped_addr_dropped(const char *dst_ip) {
  test_ctx_t ctx;

  test_init_ipv6(&ctx);
  assert(inet_pton(AF_INET6, dst_ip, &ctx.server_ip.ip6) == 1);
  ctx.server_port = 5353;

  // the closed connection is replaced by a new one on the next packet
  for(int i = 1; i <= 2; i++) {
    client_send_udp(&ctx, stream, PAYLOAD_SIZE);
    assert(ctx.num_closes == i);
    assert(ctx.close_status == CONN_STATUS_UNREACHABLE);
  }

  test_teardown(&ctx);
}

/* ******************************************************* */

static void test_ipv6_udp_to_scoped_addr_dropped() {
  assert_udp_to_scoped_addr_dropped("ff02::fb");
  assert_udp_to_scoped_addr_dropped("ff01::1");
  assert_udp_to_scoped_addr_dropped("fe80::1");
}

/* ******************************************************* */

static void test_ipv6_client_ipv4_socks5_proxy() {
  test_ctx_t ctx;
  zdtun_ip_t proxy_ip = {0};
  uint8_t rx[32];
  const char srv_choice[] = {5, 0};
  const char connect_reply[SOCKS5_REQ_LEN] = {5, 0, 0, 1};

  test_init_ipv6(&ctx);

  proxy_ip.ip4 = inet_addr(SERVER_IP);
  zdtun_set_socks5_proxy(ctx.tun, &proxy_ip, htons(ctx.server_port), 4);
  zdtun_conn_proxy(create_client_conn(&ctx, IPPROTO_TCP));

  client_syn_with_window(&ctx, CLIENT_WINDOW);
  accept_server_sock(&ctx);

  // Completes the connect, if in progress
  poll_events(&ctx);

  assert(recv(ctx.server_sock, rx, sizeof(rx), 0) == 3);
  assert(send(ctx.server_sock, srv_choice, sizeof(srv_choice), 0) == sizeof(srv_choice));
  process_events(&ctx);

  // The proxy must connect to the original IPv6 destination
  assert(recv(ctx.server_sock, rx, sizeof(rx), 0) == SOCKS5_REQ6_LEN);
  assert(rx[3] == 4);
  assert(memcmp(rx + 4, &ctx.server_ip.ip6, 16) == 0);
  assert(((rx[20] << 8) | rx[21]) == ctx.server_port);

  assert(send(ctx.server_sock, connect_reply, sizeof(connect_reply), 0) == sizeof(connect_reply));
  process_events(&ctx);

  assert(ctx.syn_ack_received);
  client_ack(&ctx);

  transfer_stream(&ctx, STREAM_SIZE);

  assert(ctx.max_pkt_len <= DEFAULT_MTU);
  assert(client_received_stream(&ctx, STREAM_SIZE));

  assert_upload_delivered(&ctx);
  assert_connection_alive(&ctx);

  test_teardown(&ctx);
}

/* ******************************************************* */

static const test_t tests[] = {
  {"large_mss_clamped_to_mtu", test_large_mss_clamped_to_mtu},
  {"mss_clamped_to_configured_mtu", test_mss_clamped_to_configured_mtu},
  {"small_mss_honored", test_small_mss_honored},
  {"zero_mss_ignored", test_zero_mss_ignored},
  {"short_tcp_data_offset_rejected", test_short_tcp_data_offset_rejected},
  {"short_ipv4_ihl_rejected", test_short_ipv4_ihl_rejected},
  {"syn_short_data_offset_not_forwarded", test_syn_short_data_offset_not_forwarded},
  {"rst_delivered_on_close", test_rst_delivered_on_close},
  {"failed_rst_closes_once", test_failed_rst_closes_once},
  {"failed_rst_on_destroy_closes_once", test_failed_rst_on_destroy_closes_once},
  {"connect_error_rst_acks_syn", test_connect_error_rst_acks_syn},
  {"unforwarded_conn_close_sends_no_rst", test_unforwarded_conn_close_sends_no_rst},
  {"unforwarded_conn_destroy_sends_no_rst", test_unforwarded_conn_destroy_sends_no_rst},
  {"tcp_socket_error_closes_conn", test_tcp_socket_error_closes_conn},
  {"icmp_socket_error_closes_conn", test_icmp_socket_error_closes_conn},
  {"zero_window_ack_keeps_connection", test_zero_window_ack_keeps_connection},
  {"window_filled_by_in_flight_keeps_connection", test_window_filled_by_in_flight_keeps_connection},
  {"window_shrink_not_overrun", test_window_shrink_not_overrun},
  {"zero_window_syn_keeps_connection", test_zero_window_syn_keeps_connection},
  {"zero_window_syn_connect_in_progress", test_zero_window_syn_connect_in_progress},
  {"stale_read_event_with_zero_window", test_stale_read_event_with_zero_window},
  {"zero_window_upload_delivered", test_zero_window_upload_delivered},
  {"zero_window_syn_socks5_handshake", test_zero_window_syn_socks5_handshake},
  {"socks5_server_close_during_handshake", test_socks5_server_close_during_handshake},
  {"large_window_scale_clamped", test_large_window_scale_clamped},
  {"syn_ack_window_not_scaled", test_syn_ack_window_not_scaled},
  {"window_scale_not_sent_unsolicited", test_window_scale_not_sent_unsolicited},
  {"server_data_before_connect_handled", test_server_data_before_connect_handled},
  {"server_eof_before_connect_handled", test_server_eof_before_connect_handled},
  {"server_reset_before_connect_handled", test_server_reset_before_connect_handled},
  {"server_data_queued_until_handshake_ack", test_server_data_queued_until_handshake_ack},
  {"stale_read_event_before_handshake_ack", test_stale_read_event_before_handshake_ack},
  {"retransmitted_byte_delivered_once", test_retransmitted_byte_delivered_once},
  {"retransmitted_byte_with_fin_delivered_once", test_retransmitted_byte_with_fin_delivered_once},
  {"retransmitted_byte_delivered_once_after_server_eof", test_retransmitted_byte_delivered_once_after_server_eof},
  {"ipv6_client_tcp_dnat_to_ipv4", test_ipv6_client_tcp_dnat_to_ipv4},
  {"ipv6_client_udp_dnat_to_ipv4", test_ipv6_client_udp_dnat_to_ipv4},
  {"ipv6_udp_zero_checksum_not_sent", test_ipv6_udp_zero_checksum_not_sent},
  {"ipv6_udp_to_scoped_addr_dropped", test_ipv6_udp_to_scoped_addr_dropped},
  {"ipv6_client_ipv4_socks5_proxy", test_ipv6_client_ipv4_socks5_proxy},
};

/* ******************************************************* */

int main(int argc, char **argv) {
  return run_test(argc, argv, tests, sizeof(tests) / sizeof(tests[0]));
}
