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
 * Tests the client side close of a TCP connection.
 *
 * The test acts as the client, by crafting the IP packets and reading the
 * zdtun replies, and as the server, via a loopback socket. Since zdtun only
 * writes the client data to the socket from zdtun_handle_fd, a test defines
 * the order of the events by choosing when to call it. The results of send
 * and the clock seen by zdtun are scripted, see the __wrap_ functions.
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
#define PAYLOAD_SIZE 1000
#define PARTIAL_SEND_SIZE 40
#define START_TIME_SEC 1000
#define IO_TIMEOUT_SEC 5
#define NUM_EAGAIN_FOREVER 1000000

typedef struct {
  zdtun_t *tun;
  int listen_sock;
  int server_sock;
  uint16_t server_port;
  uint32_t client_seq;
  uint32_t server_seq;
  uint32_t last_ack;
  uint16_t client_window;
  int num_replies;
  int num_closed;
  int num_server_fins;
  uint8_t syn_ack_received;
} test_ctx_t;

static char payload[PAYLOAD_SIZE];

static int send_eagain_count = 0;
static size_t send_max_bytes = 0;
static int send_errno = 0;
static int shutdown_calls = 0;
static time_t fake_now = START_TIME_SEC;

ssize_t __real_send(int fd, const void *buf, size_t len, int flags);
int __real_shutdown(int fd, int how);

/* ******************************************************* */

ssize_t __wrap_send(int fd, const void *buf, size_t len, int flags) {
  if(send_errno != 0) {
    errno = send_errno;
    return -1;
  }

  if(send_eagain_count > 0) {
    send_eagain_count--;
    errno = EAGAIN;
    return -1;
  }

  if((send_max_bytes > 0) && (len > send_max_bytes))
    len = send_max_bytes;

  return __real_send(fd, buf, len, flags);
}

/* ******************************************************* */

int __wrap_shutdown(int fd, int how) {
  shutdown_calls++;

  return __real_shutdown(fd, how);
}

/* ******************************************************* */

int __wrap_clock_gettime(clockid_t clk_id, struct timespec *ts) {
  ts->tv_sec = fake_now;
  ts->tv_nsec = 0;

  return 0;
}

/* ******************************************************* */

static int on_send_client(zdtun_t *tun, zdtun_pkt_t *pkt, const zdtun_conn_t *conn_info) {
  test_ctx_t *ctx = (test_ctx_t*) zdtun_userdata(tun);

  if(pkt->tcp->th_flags & TH_SYN) {
    ctx->syn_ack_received = 1;
    ctx->server_seq = ntohl(pkt->tcp->th_seq) + 1;
  } else if(pkt->tcp->th_flags & TH_ACK)
    ctx->last_ack = ntohl(pkt->tcp->th_ack);

  if(pkt->tcp->th_flags & TH_FIN)
    ctx->num_server_fins++;

  ctx->num_replies++;

  return 0;
}

/* ******************************************************* */

static void on_connection_close(zdtun_t *tun, const zdtun_conn_t *conn_info) {
  test_ctx_t *ctx = (test_ctx_t*) zdtun_userdata(tun);

  ctx->num_closed++;
}

/* ******************************************************* */

static void client_send(test_ctx_t *ctx, uint8_t flags, const char *data, int len) {
  static char buf[sizeof(struct iphdr) + sizeof(struct tcphdr) + PAYLOAD_SIZE] __attribute__((aligned(4)));
  struct iphdr *ip = (struct iphdr*) buf;
  struct tcphdr *tcp = (struct tcphdr*) (buf + sizeof(struct iphdr));
  int pkt_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + len;

  memset(buf, 0, sizeof(struct iphdr) + sizeof(struct tcphdr));

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
  tcp->th_off = 5;
  tcp->th_flags = flags;
  tcp->th_win = htons(ctx->client_window);

  if(len > 0)
    memcpy(buf + sizeof(struct iphdr) + sizeof(struct tcphdr), data, len);

  assert(zdtun_easy_forward(ctx->tun, buf, pkt_len) != NULL);

  ctx->client_seq += len + ((flags & (TH_SYN | TH_FIN)) ? 1 : 0);
}

/* ******************************************************* */

static void client_retransmit_fin(test_ctx_t *ctx) {
  ctx->client_seq -= 1;
  client_send(ctx, TH_FIN | TH_ACK, NULL, 0);
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

// Establishes a connection from the client to the server, via zdtun
static void test_setup(test_ctx_t *ctx) {
  static zdtun_callbacks_t callbacks = {
    .send_client = on_send_client,
    .on_connection_close = on_connection_close,
  };

  memset(ctx, 0, sizeof(*ctx));

  for(int i = 0; i < PAYLOAD_SIZE; i++)
    payload[i] = (char) (i % 251);

  open_listen_socket(ctx);

  ctx->tun = zdtun_init(&callbacks, ctx);
  assert(ctx->tun != NULL);

  ctx->client_seq = CLIENT_ISN;
  ctx->client_window = CLIENT_WINDOW;
  client_send(ctx, TH_SYN, NULL, 0);

  // A loopback connect can either complete immediately or be in progress
  while(!ctx->syn_ack_received)
    process_events(ctx);

  ctx->server_sock = accept(ctx->listen_sock, NULL, NULL);
  assert(ctx->server_sock >= 0);

  set_recv_timeout(ctx->server_sock);

  client_send(ctx, TH_ACK, NULL, 0);
  ctx->num_replies = 0;
}

/* ******************************************************* */

static void test_teardown(test_ctx_t *ctx) {
  zdtun_finalize(ctx->tun);

  if(ctx->server_sock >= 0)
    close(ctx->server_sock);

  close(ctx->listen_sock);
}

/* ******************************************************* */

static void close_server_socket(test_ctx_t *ctx) {
  close(ctx->server_sock);
  ctx->server_sock = -1;

  // zdtun reads the server EOF and closes its own socket
  process_events(ctx);
}

/* ******************************************************* */

static void server_eof_while_queued(test_ctx_t *ctx) {
  send_eagain_count = NUM_EAGAIN_FOREVER;
  client_send(ctx, TH_ACK | TH_PUSH, payload, PAYLOAD_SIZE);
  client_send(ctx, TH_FIN | TH_ACK, NULL, 0);

  assert(__real_shutdown(ctx->server_sock, SHUT_WR) == 0);

  // zdtun reads the server EOF
  process_events(ctx);
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

static void server_send_payload(test_ctx_t *ctx) {
  assert(__real_send(ctx->server_sock, payload, PAYLOAD_SIZE, 0) == PAYLOAD_SIZE);
}

/* ******************************************************* */

static int server_read(test_ctx_t *ctx, char *buf, int size) {
  int total = 0;

  while(total < size) {
    int rv = recv(ctx->server_sock, buf + total, size - total, 0);

    if(rv <= 0)
      break;

    total += rv;
  }

  return total;
}

/* ******************************************************* */

// The extra byte detects excess data
static int server_received_payload(test_ctx_t *ctx) {
  char received[PAYLOAD_SIZE + 1];

  if(server_read(ctx, received, sizeof(received)) != PAYLOAD_SIZE)
    return 0;

  return(memcmp(received, payload, PAYLOAD_SIZE) == 0);
}

/* ******************************************************* */

static void test_queued_data_delivered() {
  test_ctx_t ctx;
  test_setup(&ctx);

  client_send(&ctx, TH_ACK | TH_PUSH, payload, PAYLOAD_SIZE);
  client_send(&ctx, TH_FIN | TH_ACK, NULL, 0);
  process_events(&ctx);

  assert(server_received_payload(&ctx));

  test_teardown(&ctx);
}

/* ******************************************************* */

// Data without TH_PUSH is sent with MSG_MORE and buffered by the kernel
static void test_unpushed_queued_data_delivered() {
  test_ctx_t ctx;
  test_setup(&ctx);

  client_send(&ctx, TH_ACK, payload, PAYLOAD_SIZE);
  client_send(&ctx, TH_FIN | TH_ACK, NULL, 0);
  process_events(&ctx);

  assert(server_received_payload(&ctx));

  test_teardown(&ctx);
}

/* ******************************************************* */

static void test_fin_payload_delivered() {
  test_ctx_t ctx;
  test_setup(&ctx);

  client_send(&ctx, TH_FIN | TH_ACK | TH_PUSH, payload, PAYLOAD_SIZE);
  process_events(&ctx);

  assert(server_received_payload(&ctx));

  test_teardown(&ctx);
}

/* ******************************************************* */

static void test_fin_propagated_to_server() {
  test_ctx_t ctx;
  char received[PAYLOAD_SIZE];
  char after_eof;

  test_setup(&ctx);

  client_send(&ctx, TH_ACK | TH_PUSH, payload, PAYLOAD_SIZE);
  client_send(&ctx, TH_FIN | TH_ACK, NULL, 0);
  process_events(&ctx);

  server_read(&ctx, received, sizeof(received));

  assert(recv(ctx.server_sock, &after_eof, 1, 0) == 0);

  test_teardown(&ctx);
}

/* ******************************************************* */

static void test_shutdown_deferred_while_queued() {
  test_ctx_t ctx;
  test_setup(&ctx);

  send_eagain_count = 1;
  client_send(&ctx, TH_ACK | TH_PUSH, payload, PAYLOAD_SIZE);
  client_send(&ctx, TH_FIN | TH_ACK, NULL, 0);
  process_events(&ctx);

  assert(shutdown_calls == 0);

  test_teardown(&ctx);
}

/* ******************************************************* */

static void test_fin_not_acked_while_queued() {
  test_ctx_t ctx;
  test_setup(&ctx);

  send_eagain_count = 1;
  client_send(&ctx, TH_ACK | TH_PUSH, payload, PAYLOAD_SIZE);
  client_send(&ctx, TH_FIN | TH_ACK, NULL, 0);
  process_events(&ctx);

  assert(ctx.num_replies == 0);

  test_teardown(&ctx);
}

/* ******************************************************* */

static void test_partial_send_acks_written_bytes() {
  test_ctx_t ctx;
  test_setup(&ctx);

  uint32_t data_seq = ctx.client_seq;

  send_max_bytes = PARTIAL_SEND_SIZE;
  client_send(&ctx, TH_ACK | TH_PUSH, payload, PAYLOAD_SIZE);
  client_send(&ctx, TH_FIN | TH_ACK, NULL, 0);
  process_events(&ctx);

  assert(ctx.last_ack == (data_seq + PARTIAL_SEND_SIZE));

  test_teardown(&ctx);
}

/* ******************************************************* */

static void test_fin_acked_after_drain() {
  test_ctx_t ctx;
  test_setup(&ctx);

  uint32_t data_seq = ctx.client_seq;

  client_send(&ctx, TH_ACK | TH_PUSH, payload, PAYLOAD_SIZE);
  client_send(&ctx, TH_FIN | TH_ACK, NULL, 0);
  process_events(&ctx);

  assert(ctx.last_ack == (data_seq + PAYLOAD_SIZE + 1));

  test_teardown(&ctx);
}

/* ******************************************************* */

static void test_fin_payload_acked() {
  test_ctx_t ctx;
  test_setup(&ctx);

  uint32_t data_seq = ctx.client_seq;

  client_send(&ctx, TH_FIN | TH_ACK | TH_PUSH, payload, PAYLOAD_SIZE);
  process_events(&ctx);

  assert(ctx.last_ack == (data_seq + PAYLOAD_SIZE + 1));

  test_teardown(&ctx);
}

/* ******************************************************* */

static void test_fin_acked_immediately_when_queue_empty() {
  test_ctx_t ctx;
  test_setup(&ctx);

  uint32_t data_seq = ctx.client_seq;

  client_send(&ctx, TH_ACK | TH_PUSH, payload, PAYLOAD_SIZE);
  process_events(&ctx);
  client_send(&ctx, TH_FIN | TH_ACK, NULL, 0);

  assert(ctx.last_ack == (data_seq + PAYLOAD_SIZE + 1));

  test_teardown(&ctx);
}

/* ******************************************************* */

// The ACK must not cover the data which is still queued, nor the FIN
static void test_fin_retransmission_while_queued() {
  test_ctx_t ctx;
  test_setup(&ctx);

  uint32_t data_seq = ctx.client_seq;

  send_max_bytes = PARTIAL_SEND_SIZE;
  client_send(&ctx, TH_ACK | TH_PUSH, payload, PAYLOAD_SIZE);
  client_send(&ctx, TH_FIN | TH_ACK, NULL, 0);
  process_events(&ctx);

  ctx.last_ack = 0;
  client_retransmit_fin(&ctx);

  assert(ctx.last_ack == (data_seq + PARTIAL_SEND_SIZE));

  test_teardown(&ctx);
}

/* ******************************************************* */

static void test_fin_retransmission_after_close() {
  test_ctx_t ctx;
  test_setup(&ctx);

  client_send(&ctx, TH_FIN | TH_ACK, NULL, 0);

  uint32_t fin_ack = ctx.last_ack;

  ctx.last_ack = 0;
  client_retransmit_fin(&ctx);

  assert(ctx.last_ack == fin_ack);

  test_teardown(&ctx);
}

/* ******************************************************* */

// The connection must not be purged as idle while the upload makes progress
static void test_drain_progress_refreshes_idle_timeout() {
  test_ctx_t ctx;
  test_setup(&ctx);

  send_max_bytes = PARTIAL_SEND_SIZE;
  client_send(&ctx, TH_ACK | TH_PUSH, payload, PAYLOAD_SIZE);
  client_send(&ctx, TH_FIN | TH_ACK, NULL, 0);

  fake_now += 50;
  process_events(&ctx);

  // past the 60 seconds TCP timeout, if counted from the connection start
  fake_now += 20;
  zdtun_purge_expired(ctx.tun);

  assert(zdtun_get_num_connections(ctx.tun) == 1);

  test_teardown(&ctx);
}

/* ******************************************************* */

static void test_window_update_applied_while_queued() {
  test_ctx_t ctx;
  test_setup(&ctx);

  ctx.client_window = PAYLOAD_SIZE;
  client_send(&ctx, TH_ACK, NULL, 0);

  send_eagain_count = NUM_EAGAIN_FOREVER;
  client_send(&ctx, TH_ACK | TH_PUSH, payload, PAYLOAD_SIZE);
  client_send(&ctx, TH_FIN | TH_ACK, NULL, 0);

  server_send_payload(&ctx);
  server_send_payload(&ctx);
  process_events(&ctx);

  // the window is now exhausted, the second chunk must not be read
  assert(ctx.num_replies == 1);

  ctx.num_replies = 0;
  process_events(&ctx);
  assert(ctx.num_replies == 0);

  ctx.server_seq += PAYLOAD_SIZE;
  ctx.client_window = CLIENT_WINDOW;
  client_send(&ctx, TH_ACK, NULL, 0);
  process_events(&ctx);

  assert(ctx.num_replies == 1);

  test_teardown(&ctx);
}

/* ******************************************************* */

static void test_rst_after_fin_while_queued() {
  test_ctx_t ctx;
  char received[PAYLOAD_SIZE];

  test_setup(&ctx);

  send_eagain_count = NUM_EAGAIN_FOREVER;
  client_send(&ctx, TH_ACK | TH_PUSH, payload, PAYLOAD_SIZE);
  client_send(&ctx, TH_FIN | TH_ACK, NULL, 0);
  client_send(&ctx, TH_RST | TH_ACK, NULL, 0);

  assert(ctx.num_closed == 1);
  assert(server_read(&ctx, received, sizeof(received)) == 0);

  test_teardown(&ctx);
}

/* ******************************************************* */

static void test_server_eof_keeps_connection_while_queued() {
  test_ctx_t ctx;
  test_setup(&ctx);

  server_eof_while_queued(&ctx);

  assert(ctx.num_closed == 0);

  test_teardown(&ctx);
}

/* ******************************************************* */

static void test_upload_delivered_after_server_eof() {
  test_ctx_t ctx;
  test_setup(&ctx);

  server_eof_while_queued(&ctx);

  send_eagain_count = 0;
  process_events(&ctx);

  assert(server_received_payload(&ctx));

  test_teardown(&ctx);
}

/* ******************************************************* */

static void test_fin_acked_after_server_eof() {
  test_ctx_t ctx;
  test_setup(&ctx);

  uint32_t data_seq = ctx.client_seq;

  server_eof_while_queued(&ctx);

  send_eagain_count = 0;
  process_events(&ctx);

  assert(ctx.last_ack == (data_seq + PAYLOAD_SIZE + 1));

  test_teardown(&ctx);
}

/* ******************************************************* */

static void test_connection_closed_after_server_eof_drain() {
  test_ctx_t ctx;
  test_setup(&ctx);

  server_eof_while_queued(&ctx);

  send_eagain_count = 0;
  process_events(&ctx);

  assert(ctx.num_closed == 1);

  test_teardown(&ctx);
}

/* ******************************************************* */

// recv would keep returning 0 on the socket
static void test_server_eof_not_polled_after_window_update() {
  test_ctx_t ctx;
  test_setup(&ctx);

  server_eof_while_queued(&ctx);

  ctx.server_seq += 1;
  client_send(&ctx, TH_ACK, NULL, 0);

  assert(!zdtun_polls_reads(&ctx));

  test_teardown(&ctx);
}

/* ******************************************************* */

static void test_server_fin_sent_once_while_queued() {
  test_ctx_t ctx;
  test_setup(&ctx);

  server_eof_while_queued(&ctx);

  ctx.server_seq += 1;
  client_send(&ctx, TH_ACK, NULL, 0);

  send_eagain_count = 0;
  process_events(&ctx);

  assert(ctx.num_server_fins == 1);

  test_teardown(&ctx);
}

/* ******************************************************* */

static void test_send_error_after_server_eof_closes() {
  test_ctx_t ctx;
  test_setup(&ctx);

  server_eof_while_queued(&ctx);

  send_eagain_count = 0;
  send_errno = EPIPE;
  process_events(&ctx);

  assert(ctx.num_closed == 1);

  test_teardown(&ctx);
}

/* ******************************************************* */

static void test_upload_sent_while_server_sending() {
  test_ctx_t ctx;
  char received[PAYLOAD_SIZE];
  test_setup(&ctx);

  client_send(&ctx, TH_ACK | TH_PUSH, payload, PAYLOAD_SIZE);
  server_send_payload(&ctx);
  process_events(&ctx);

  assert(ctx.last_ack == ctx.client_seq);
  assert(server_read(&ctx, received, sizeof(received)) == PAYLOAD_SIZE);

  test_teardown(&ctx);
}

/* ******************************************************* */

static void test_close_completed_while_server_sending() {
  test_ctx_t ctx;
  test_setup(&ctx);

  client_send(&ctx, TH_ACK | TH_PUSH, payload, PAYLOAD_SIZE);
  client_send(&ctx, TH_FIN | TH_ACK, NULL, 0);
  server_send_payload(&ctx);
  process_events(&ctx);

  assert(shutdown_calls == 1);
  assert(ctx.last_ack == ctx.client_seq);
  assert(server_received_payload(&ctx));

  test_teardown(&ctx);
}

/* ******************************************************* */

static void test_drain_completed_with_server_eof() {
  test_ctx_t ctx;
  test_setup(&ctx);

  client_send(&ctx, TH_ACK | TH_PUSH, payload, PAYLOAD_SIZE);
  client_send(&ctx, TH_FIN | TH_ACK, NULL, 0);
  assert(__real_shutdown(ctx.server_sock, SHUT_WR) == 0);
  process_events(&ctx);

  assert(ctx.num_closed == 1);
  assert(ctx.last_ack == ctx.client_seq);
  assert(server_received_payload(&ctx));

  test_teardown(&ctx);
}

/* ******************************************************* */

// The socket is both readable and writable, but is closed by the read
static void test_queued_upload_not_sent_after_server_close() {
  test_ctx_t ctx;
  test_setup(&ctx);

  client_send(&ctx, TH_ACK | TH_PUSH, payload, PAYLOAD_SIZE);
  close_server_socket(&ctx);

  assert(ctx.num_server_fins == 1);
  assert(ctx.num_closed == 0);

  test_teardown(&ctx);
}

/* ******************************************************* */

static void test_fin_terminates_when_server_closed() {
  test_ctx_t ctx;
  test_setup(&ctx);

  close_server_socket(&ctx);
  client_send(&ctx, TH_FIN | TH_ACK, NULL, 0);

  assert(ctx.num_closed == 1);

  test_teardown(&ctx);
}

/* ******************************************************* */

static void test_fin_payload_acked_when_server_closed() {
  test_ctx_t ctx;
  test_setup(&ctx);

  uint32_t data_seq = ctx.client_seq;

  close_server_socket(&ctx);
  client_send(&ctx, TH_FIN | TH_ACK | TH_PUSH, payload, PAYLOAD_SIZE);

  assert(ctx.last_ack == (data_seq + PAYLOAD_SIZE + 1));

  test_teardown(&ctx);
}

/* ******************************************************* */

typedef struct {
  const char *name;
  void (*run)();
} test_t;

static const test_t tests[] = {
  {"queued_data_delivered", test_queued_data_delivered},
  {"unpushed_queued_data_delivered", test_unpushed_queued_data_delivered},
  {"fin_payload_delivered", test_fin_payload_delivered},
  {"fin_propagated_to_server", test_fin_propagated_to_server},
  {"shutdown_deferred_while_queued", test_shutdown_deferred_while_queued},
  {"fin_not_acked_while_queued", test_fin_not_acked_while_queued},
  {"partial_send_acks_written_bytes", test_partial_send_acks_written_bytes},
  {"fin_acked_after_drain", test_fin_acked_after_drain},
  {"fin_payload_acked", test_fin_payload_acked},
  {"fin_acked_immediately_when_queue_empty", test_fin_acked_immediately_when_queue_empty},
  {"fin_retransmission_while_queued", test_fin_retransmission_while_queued},
  {"fin_retransmission_after_close", test_fin_retransmission_after_close},
  {"drain_progress_refreshes_idle_timeout", test_drain_progress_refreshes_idle_timeout},
  {"window_update_applied_while_queued", test_window_update_applied_while_queued},
  {"rst_after_fin_while_queued", test_rst_after_fin_while_queued},
  {"server_eof_keeps_connection_while_queued", test_server_eof_keeps_connection_while_queued},
  {"upload_delivered_after_server_eof", test_upload_delivered_after_server_eof},
  {"fin_acked_after_server_eof", test_fin_acked_after_server_eof},
  {"connection_closed_after_server_eof_drain", test_connection_closed_after_server_eof_drain},
  {"server_eof_not_polled_after_window_update", test_server_eof_not_polled_after_window_update},
  {"server_fin_sent_once_while_queued", test_server_fin_sent_once_while_queued},
  {"send_error_after_server_eof_closes", test_send_error_after_server_eof_closes},
  {"upload_sent_while_server_sending", test_upload_sent_while_server_sending},
  {"close_completed_while_server_sending", test_close_completed_while_server_sending},
  {"drain_completed_with_server_eof", test_drain_completed_with_server_eof},
  {"queued_upload_not_sent_after_server_close", test_queued_upload_not_sent_after_server_close},
  {"fin_terminates_when_server_closed", test_fin_terminates_when_server_closed},
  {"fin_payload_acked_when_server_closed", test_fin_payload_acked_when_server_closed},
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
