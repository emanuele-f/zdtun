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
  uint8_t syn_ack_received;
} test_ctx_t;

static char stream[STREAM_SIZE];
static char client_rx[STREAM_SIZE];

/* ******************************************************* */

// Captures the packets sent to the client
static int on_send_client(zdtun_t *tun, zdtun_pkt_t *pkt, const zdtun_conn_t *conn_info) {
  test_ctx_t *ctx = (test_ctx_t*) zdtun_userdata(tun);

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
  };

  memset(ctx, 0, sizeof(*ctx));

  for(int i = 0; i < STREAM_SIZE; i++)
    stream[i] = (char) (i % 251);

  open_listen_socket(ctx);

  ctx->tun = zdtun_init(&callbacks, ctx);
  assert(ctx->tun != NULL);
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

  ctx->server_sock = accept(ctx->listen_sock, NULL, NULL);
  assert(ctx->server_sock >= 0);

  set_recv_timeout(ctx->server_sock);

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
