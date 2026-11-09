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

// the tests must not become no-op on release builds
#undef NDEBUG

#include <assert.h>
#include <signal.h>
#include <sys/select.h>
#include <sys/socket.h>
#include "zdtun.h"
#include "third_party/net_headers.h"

#define CLIENT_IP "10.0.0.2"
#define SERVER_IP "127.0.0.1"
#define CLIENT_PORT 12345
#define CLIENT_ISN 1000
#define CLIENT_WINDOW 65535
#define IPV4_TCP_HEADERS_LEN (sizeof(struct iphdr) + sizeof(struct tcphdr))
#define MAX_TCP_OPTIONS_LEN 40
#define TCP_OPT_MSS 2
#define TCP_OPT_MSS_LEN 4
#define DEFAULT_MTU 1500
#define PAYLOAD_SIZE 1000
#define STREAM_SIZE 200000
#define IO_TIMEOUT_SEC 5
#define POLL_TIMEOUT_USEC 100000
#define SOCKS5_REQ_LEN 10

typedef struct {
  zdtun_t *tun;
  int listen_sock;
  int server_sock;
  uint16_t server_port;
  uint32_t client_seq;
  uint32_t server_seq;
  uint16_t client_window;
  int num_server_fins;
  int max_pkt_len;
  int rx_len;
  int num_rsts;
  int num_closes;
  zdtun_conn_status_t close_status;
  uint8_t syn_ack_received;
  uint8_t fail_rst;
} test_ctx_t;

static char stream[STREAM_SIZE];
static char client_rx[STREAM_SIZE];
static uint8_t force_connect_in_progress;

/* ******************************************************* */

int __real_connect(int sock, const struct sockaddr *addr, socklen_t addr_len);

// A loopback connect normally completes immediately
int __wrap_connect(int sock, const struct sockaddr *addr, socklen_t addr_len) {
  int rv = __real_connect(sock, addr, addr_len);

  if(force_connect_in_progress && (rv == 0)) {
    errno = EINPROGRESS;
    return -1;
  }

  return rv;
}

/* ******************************************************* */

// Captures the packets sent to the client
static int on_send_client(zdtun_t *tun, zdtun_pkt_t *pkt, const zdtun_conn_t *conn_info) {
  test_ctx_t *ctx = (test_ctx_t*) zdtun_userdata(tun);

  if(pkt->tcp->th_flags & TH_RST) {
    ctx->num_rsts++;

    if(ctx->fail_rst)
      return -1;
  }

  if(pkt->len > ctx->max_pkt_len)
    ctx->max_pkt_len = pkt->len;

  if(pkt->tcp->th_flags & TH_SYN) {
    ctx->syn_ack_received = 1;
    ctx->server_seq = ntohl(pkt->tcp->th_seq) + 1;
  } else {
    assert((ctx->rx_len + pkt->l7_len) <= STREAM_SIZE);
    memcpy(client_rx + ctx->rx_len, pkt->l7, pkt->l7_len);

    ctx->rx_len += pkt->l7_len;
    ctx->server_seq += pkt->l7_len;
  }

  if(pkt->tcp->th_flags & TH_FIN) {
    ctx->num_server_fins++;
    ctx->server_seq += 1;
  }

  return 0;
}

/* ******************************************************* */

static void on_connection_close(zdtun_t *tun, const zdtun_conn_t *conn_info) {
  test_ctx_t *ctx = (test_ctx_t*) zdtun_userdata(tun);

  ctx->num_closes++;
  ctx->close_status = zdtun_conn_get_status(conn_info);
}

/* ******************************************************* */

static void client_send(test_ctx_t *ctx, uint8_t flags, const uint8_t *opts, int opts_len,
        const char *data, int len) {
  static char buf[IPV4_TCP_HEADERS_LEN + MAX_TCP_OPTIONS_LEN + PAYLOAD_SIZE] __attribute__((aligned(4)));
  struct iphdr *ip = (struct iphdr*) buf;
  struct tcphdr *tcp = (struct tcphdr*) (buf + sizeof(struct iphdr));
  int pkt_len = IPV4_TCP_HEADERS_LEN + opts_len + len;

  assert((opts_len % 4) == 0);
  assert(opts_len <= MAX_TCP_OPTIONS_LEN);
  assert(len <= PAYLOAD_SIZE);

  memset(buf, 0, IPV4_TCP_HEADERS_LEN);

  ip->version = 4;
  ip->ihl = 5;
  ip->tot_len = htons(pkt_len);
  ip->ttl = 64;
  ip->protocol = IPPROTO_TCP;
  ip->saddr = inet_addr(CLIENT_IP);
  ip->daddr = inet_addr(SERVER_IP);

  tcp->th_sport = htons(CLIENT_PORT);
  tcp->th_dport = htons(ctx->server_port);
  tcp->th_seq = htonl(ctx->client_seq);
  tcp->th_ack = htonl(ctx->server_seq);
  tcp->th_off = 5 + (opts_len / 4);
  tcp->th_flags = flags;
  tcp->th_win = htons(ctx->client_window);

  if(opts_len > 0)
    memcpy(buf + IPV4_TCP_HEADERS_LEN, opts, opts_len);

  if(len > 0)
    memcpy(buf + IPV4_TCP_HEADERS_LEN + opts_len, data, len);

  assert(zdtun_easy_forward(ctx->tun, buf, pkt_len) != NULL);

  ctx->client_seq += len + ((flags & (TH_SYN | TH_FIN)) ? 1 : 0);
}

/* ******************************************************* */

static void client_ack(test_ctx_t *ctx) {
  client_send(ctx, TH_ACK, NULL, 0, NULL, 0);
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
  client_send(ctx, TH_SYN, NULL, 0, NULL, 0);
}

/* ******************************************************* */

// Handles a single batch of socket events
static void process_events(test_ctx_t *ctx) {
  fd_set rd_fds;
  fd_set wr_fds;
  int max_fd = 0;
  struct timeval timeout = {.tv_sec = IO_TIMEOUT_SEC};

  zdtun_fds(ctx->tun, &max_fd, &rd_fds, &wr_fds);

  int num_ready = select(max_fd + 1, &rd_fds, &wr_fds, NULL, &timeout);
  assert(num_ready > 0);

  zdtun_handle_fd(ctx->tun, &rd_fds, &wr_fds);
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

static int zdtun_polls_reads(test_ctx_t *ctx) {
  fd_set rd_fds;
  fd_set wr_fds;
  int max_fd = 0;

  zdtun_fds(ctx->tun, &max_fd, &rd_fds, &wr_fds);

  for(int fd = 0; fd <= max_fd; fd++) {
    if(FD_ISSET(fd, &rd_fds))
      return 1;
  }

  return 0;
}

/* ******************************************************* */

static void set_recv_timeout(int sock) {
  struct timeval timeout = {.tv_sec = IO_TIMEOUT_SEC};
  int rv = setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

  assert(rv == 0);
}

/* ******************************************************* */

static void open_listen_socket(test_ctx_t *ctx) {
  struct sockaddr_in addr = {0};
  socklen_t addr_len = sizeof(addr);

  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = inet_addr(SERVER_IP);

  ctx->listen_sock = socket(AF_INET, SOCK_STREAM, 0);
  assert(ctx->listen_sock >= 0);

  set_recv_timeout(ctx->listen_sock);

  assert(bind(ctx->listen_sock, (struct sockaddr*) &addr, sizeof(addr)) == 0);
  assert(listen(ctx->listen_sock, 1) == 0);
  assert(getsockname(ctx->listen_sock, (struct sockaddr*) &addr, &addr_len) == 0);

  ctx->server_port = ntohs(addr.sin_port);
}

/* ******************************************************* */

// Separated from test_connect to allow configuring the tun before the SYN
static void test_init(test_ctx_t *ctx) {
  static zdtun_callbacks_t callbacks = {
    .send_client = on_send_client,
    .on_connection_close = on_connection_close,
  };

  memset(ctx, 0, sizeof(*ctx));

  for(int i = 0; i < STREAM_SIZE; i++)
    stream[i] = (char) (i % 251);

  open_listen_socket(ctx);

  ctx->tun = zdtun_init(&callbacks, ctx);
  assert(ctx->tun != NULL);
}

/* ******************************************************* */

static void accept_server_sock(test_ctx_t *ctx) {
  ctx->server_sock = accept(ctx->listen_sock, NULL, NULL);
  assert(ctx->server_sock >= 0);

  set_recv_timeout(ctx->server_sock);
}

/* ******************************************************* */

// Establishes a connection from the client to the server, via zdtun
static void test_connect(test_ctx_t *ctx, const uint8_t *syn_opts, int syn_opts_len) {
  ctx->client_seq = CLIENT_ISN;
  ctx->client_window = CLIENT_WINDOW;
  client_send(ctx, TH_SYN, syn_opts, syn_opts_len, NULL, 0);

  // A loopback connect can either complete immediately or be in progress
  while(!ctx->syn_ack_received)
    process_events(ctx);

  accept_server_sock(ctx);
  client_ack(ctx);
}

/* ******************************************************* */

static void test_connect_with_mss(test_ctx_t *ctx, uint16_t mss) {
  uint8_t opts[TCP_OPT_MSS_LEN] = {TCP_OPT_MSS, TCP_OPT_MSS_LEN, mss >> 8, mss & 0xFF};

  test_connect(ctx, opts, sizeof(opts));
}

/* ******************************************************* */

static void test_setup_with_mss(test_ctx_t *ctx, uint16_t mss) {
  test_init(ctx);
  test_connect_with_mss(ctx, mss);
}

/* ******************************************************* */

static void test_teardown(test_ctx_t *ctx) {
  zdtun_finalize(ctx->tun);
  close(ctx->server_sock);
  close(ctx->listen_sock);
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

  test_init(&ctx);
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

static void test_finalize_unconnected(test_ctx_t *ctx) {
  zdtun_finalize(ctx->tun);
  close(ctx->listen_sock);
}

/* ******************************************************* */

static void test_short_tcp_data_offset_rejected() {
  test_ctx_t ctx;
  test_init(&ctx);

  for(uint8_t th_off = 0; th_off < 5; th_off++)
    assert(parse_syn(&ctx, 5, th_off) == -1);

  assert(parse_syn(&ctx, 5, 5) == 0);

  test_finalize_unconnected(&ctx);
}

/* ******************************************************* */

static void test_short_ipv4_ihl_rejected() {
  test_ctx_t ctx;
  test_init(&ctx);

  for(uint8_t ihl = 0; ihl < 5; ihl++)
    assert(parse_syn(&ctx, ihl, 5) == -1);

  assert(parse_syn(&ctx, 5, 5) == 0);

  test_finalize_unconnected(&ctx);
}

/* ******************************************************* */

// The options length would underflow, reading the options past the end of the packet
static void test_syn_short_data_offset_not_forwarded() {
  test_ctx_t ctx;
  test_init(&ctx);

  char *buf = alloc_syn(&ctx, 5, 0);

  assert(zdtun_easy_forward(ctx.tun, buf, IPV4_TCP_HEADERS_LEN) == NULL);
  assert(!ctx.syn_ack_received);

  free(buf);
  test_finalize_unconnected(&ctx);
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

// Like a connection blocked by the integrator, which is created but never forwarded
static void test_failed_rst_on_destroy_closes_once() {
  test_ctx_t ctx;
  test_init(&ctx);

  ctx.fail_rst = 1;

  zdtun_conn_t *conn = lookup_client_conn(&ctx, 1);
  assert(zdtun_conn_get_status(conn) == CONN_STATUS_NEW);

  test_finalize_unconnected(&ctx);

  assert(ctx.num_rsts == 1);
  assert(ctx.num_closes == 1);
  assert(ctx.close_status == CONN_STATUS_CLOSED);
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
  test_init(&ctx);

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
  test_init(&ctx);

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
  char rx[PAYLOAD_SIZE];

  test_setup_with_mss(&ctx, PAYLOAD_SIZE);
  server_send(&ctx, PAYLOAD_SIZE);

  ctx.client_window = 0;
  client_send(&ctx, TH_ACK | TH_PUSH, NULL, 0, stream, PAYLOAD_SIZE);

  process_events(&ctx);

  assert_connection_alive(&ctx);
  assert(ctx.rx_len == 0);

  assert(recv(ctx.server_sock, rx, PAYLOAD_SIZE, MSG_WAITALL) == PAYLOAD_SIZE);
  assert(memcmp(rx, stream, PAYLOAD_SIZE) == 0);

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

  test_init(&ctx);

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

typedef struct {
  const char *name;
  void (*run)();
} test_t;

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
  {"zero_window_ack_keeps_connection", test_zero_window_ack_keeps_connection},
  {"window_filled_by_in_flight_keeps_connection", test_window_filled_by_in_flight_keeps_connection},
  {"window_shrink_not_overrun", test_window_shrink_not_overrun},
  {"zero_window_syn_keeps_connection", test_zero_window_syn_keeps_connection},
  {"zero_window_syn_connect_in_progress", test_zero_window_syn_connect_in_progress},
  {"stale_read_event_with_zero_window", test_stale_read_event_with_zero_window},
  {"zero_window_upload_delivered", test_zero_window_upload_delivered},
  {"zero_window_syn_socks5_handshake", test_zero_window_syn_socks5_handshake},
};

/* ******************************************************* */

int main(int argc, char **argv) {
  if(argc != 2) {
    fprintf(stderr, "Usage: %s test_name\n", argv[0]);
    return 2;
  }

  // a send on a closed socket must fail with EPIPE, like in the zdtun integrations
  signal(SIGPIPE, SIG_IGN);

  for(size_t i = 0; i < (sizeof(tests) / sizeof(tests[0])); i++) {
    if(!strcmp(argv[1], tests[i].name)) {
      tests[i].run();
      return 0;
    }
  }

  fprintf(stderr, "Unknown test: %s\n", argv[1]);
  return 2;
}
