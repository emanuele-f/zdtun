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
 * Tests the close of a TCP connection, including the half close from either side.
 *
 * The test acts as the client, by crafting the IP packets and reading the
 * zdtun replies, and as the server, via a loopback socket. Since zdtun only
 * writes the client data to the socket from zdtun_handle_fd, a test defines
 * the order of the events by choosing when to call it. The results of send
 * and the clock seen by zdtun are scripted, see the __wrap_ functions.
 */

#include <signal.h>
#include "test_utils.h"

#define PARTIAL_SEND_SIZE 40
#define START_TIME_SEC 1000
#define NUM_EAGAIN_FOREVER 1000000

static int send_eagain_count = 0;
static size_t send_max_bytes = 0;
static int send_errno = 0;
static int shutdown_calls = 0;
static time_t fake_now = START_TIME_SEC;
static uint32_t client_isn = CLIENT_ISN;

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
    ctx->server_next_seq = ctx->server_seq;
  } else if(pkt->tcp->th_flags & TH_ACK)
    ctx->last_ack = ntohl(pkt->tcp->th_ack);

  // server_seq is advanced by the tests to choose what to ACK, server_next_seq follows what
  // was received. A RST is only accepted if its sequence number is exactly the next expected one
  // (RFC 5961 3.2)
  if(!(pkt->tcp->th_flags & TH_SYN) && ctx->syn_ack_received) {
    assert(ntohl(pkt->tcp->th_seq) == ctx->server_next_seq);
    ctx->server_next_seq += pkt->l7_len;
  }

  if(pkt->tcp->th_flags & TH_FIN) {
    ctx->num_server_fins++;
    ctx->server_next_seq += 1;
  }

  if(pkt->tcp->th_flags & TH_RST)
    ctx->num_rsts++;

  ctx->num_replies++;

  return 0;
}

/* ******************************************************* */

static void client_retransmit_fin(test_ctx_t *ctx) {
  ctx->client_seq -= 1;
  client_send(ctx, TH_FIN | TH_ACK, NULL, 0);
}

/* ******************************************************* */

static void client_retransmit_fin_payload(test_ctx_t *ctx) {
  ctx->client_seq -= PAYLOAD_SIZE + 1;
  client_send(ctx, TH_FIN | TH_ACK | TH_PUSH, stream, PAYLOAD_SIZE);
}

/* ******************************************************* */

// Establishes a connection from the client to the server, via zdtun
static void test_setup(test_ctx_t *ctx) {
  test_init(ctx, on_send_client);

  ctx->client_seq = client_isn;
  test_connect(ctx, NULL, 0);

  ctx->num_replies = 0;
}

/* ******************************************************* */

// The server half closes the connection: it stops sending but keeps reading
static void server_eof(test_ctx_t *ctx) {
  assert(__real_shutdown(ctx->server_sock, SHUT_WR) == 0);

  // zdtun reads the server EOF
  process_events(ctx);
}

/* ******************************************************* */

static void server_eof_while_queued(test_ctx_t *ctx) {
  send_eagain_count = NUM_EAGAIN_FOREVER;
  client_send(ctx, TH_ACK | TH_PUSH, stream, PAYLOAD_SIZE);
  client_send(ctx, TH_FIN | TH_ACK, NULL, 0);

  server_eof(ctx);
}

/* ******************************************************* */

// Unlike server_eof_while_queued, the client has not closed
static void server_eof_with_queued_upload(test_ctx_t *ctx) {
  send_eagain_count = NUM_EAGAIN_FOREVER;
  client_send(ctx, TH_ACK | TH_PUSH, stream, PAYLOAD_SIZE);

  server_eof(ctx);
}

/* ******************************************************* */

static void server_send_payload(test_ctx_t *ctx) {
  assert(__real_send(ctx->server_sock, stream, PAYLOAD_SIZE, 0) == PAYLOAD_SIZE);
}

/* ******************************************************* */

static void server_exhausts_client_window(test_ctx_t *ctx) {
  ctx->client_window = PAYLOAD_SIZE;
  client_send(ctx, TH_ACK, NULL, 0);

  server_send_payload(ctx);
  server_send_payload(ctx);
  process_events(ctx);

  assert(!zdtun_polls_reads(ctx));
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

  return(memcmp(received, stream, PAYLOAD_SIZE) == 0);
}

/* ******************************************************* */

static void test_queued_data_delivered() {
  test_ctx_t ctx;
  test_setup(&ctx);

  client_send(&ctx, TH_ACK | TH_PUSH, stream, PAYLOAD_SIZE);
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

  client_send(&ctx, TH_ACK, stream, PAYLOAD_SIZE);
  client_send(&ctx, TH_FIN | TH_ACK, NULL, 0);
  process_events(&ctx);

  assert(server_received_payload(&ctx));

  test_teardown(&ctx);
}

/* ******************************************************* */

static void test_fin_payload_delivered() {
  test_ctx_t ctx;
  test_setup(&ctx);

  client_send(&ctx, TH_FIN | TH_ACK | TH_PUSH, stream, PAYLOAD_SIZE);
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

  client_send(&ctx, TH_ACK | TH_PUSH, stream, PAYLOAD_SIZE);
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
  client_send(&ctx, TH_ACK | TH_PUSH, stream, PAYLOAD_SIZE);
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
  client_send(&ctx, TH_ACK | TH_PUSH, stream, PAYLOAD_SIZE);
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
  client_send(&ctx, TH_ACK | TH_PUSH, stream, PAYLOAD_SIZE);
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

  client_send(&ctx, TH_ACK | TH_PUSH, stream, PAYLOAD_SIZE);
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

  client_send(&ctx, TH_FIN | TH_ACK | TH_PUSH, stream, PAYLOAD_SIZE);
  process_events(&ctx);

  assert(ctx.last_ack == (data_seq + PAYLOAD_SIZE + 1));

  test_teardown(&ctx);
}

/* ******************************************************* */

static void test_fin_acked_immediately_when_queue_empty() {
  test_ctx_t ctx;
  test_setup(&ctx);

  uint32_t data_seq = ctx.client_seq;

  client_send(&ctx, TH_ACK | TH_PUSH, stream, PAYLOAD_SIZE);
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
  client_send(&ctx, TH_ACK | TH_PUSH, stream, PAYLOAD_SIZE);
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
  client_send(&ctx, TH_ACK | TH_PUSH, stream, PAYLOAD_SIZE);
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
  client_send(&ctx, TH_ACK | TH_PUSH, stream, PAYLOAD_SIZE);
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
  client_send(&ctx, TH_ACK | TH_PUSH, stream, PAYLOAD_SIZE);
  client_send(&ctx, TH_FIN | TH_ACK, NULL, 0);
  client_send(&ctx, TH_RST | TH_ACK, NULL, 0);

  assert(ctx.num_closes == 1);
  assert(ctx.num_rsts == 0);
  assert(server_read(&ctx, received, sizeof(received)) == 0);

  test_teardown(&ctx);
}

/* ******************************************************* */

// A RST is never sent in reply to a RST (RFC 9293 3.10.7.4)
static void test_no_rst_reply_to_client_rst() {
  test_ctx_t ctx;
  test_setup(&ctx);

  client_send(&ctx, TH_RST | TH_ACK, NULL, 0);

  assert(ctx.num_closes == 1);
  assert(ctx.num_rsts == 0);

  test_teardown(&ctx);

  assert(ctx.num_rsts == 0);
}

/* ******************************************************* */

static void test_no_rst_reply_to_client_rst_after_server_eof() {
  test_ctx_t ctx;
  test_setup(&ctx);

  server_eof(&ctx);
  client_send(&ctx, TH_RST | TH_ACK, NULL, 0);

  assert(ctx.num_closes == 1);
  assert(ctx.num_rsts == 0);

  test_teardown(&ctx);
}

/* ******************************************************* */

static void test_server_eof_keeps_connection_while_queued() {
  test_ctx_t ctx;
  test_setup(&ctx);

  server_eof_while_queued(&ctx);

  assert(ctx.num_closes == 0);

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

  assert(ctx.num_closes == 1);
  assert(ctx.num_rsts == 0);

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

  // The upload was lost and the client FIN was not ACKed
  assert(ctx.num_closes == 1);
  assert(ctx.num_rsts == 1);

  test_teardown(&ctx);
}

/* ******************************************************* */

static void test_upload_sent_while_server_sending() {
  test_ctx_t ctx;
  char received[PAYLOAD_SIZE];
  test_setup(&ctx);

  client_send(&ctx, TH_ACK | TH_PUSH, stream, PAYLOAD_SIZE);
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

  client_send(&ctx, TH_ACK | TH_PUSH, stream, PAYLOAD_SIZE);
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

  client_send(&ctx, TH_ACK | TH_PUSH, stream, PAYLOAD_SIZE);
  client_send(&ctx, TH_FIN | TH_ACK, NULL, 0);
  assert(__real_shutdown(ctx.server_sock, SHUT_WR) == 0);
  process_events(&ctx);

  assert(ctx.num_closes == 1);
  assert(ctx.last_ack == ctx.client_seq);
  assert(server_received_payload(&ctx));

  test_teardown(&ctx);
}

/* ******************************************************* */

// The socket is both readable and writable: reading the EOF must not drop the upload
static void test_queued_upload_sent_after_server_eof() {
  test_ctx_t ctx;
  test_setup(&ctx);

  client_send(&ctx, TH_ACK | TH_PUSH, stream, PAYLOAD_SIZE);
  server_eof(&ctx);

  assert(ctx.num_server_fins == 1);
  assert(ctx.last_ack == ctx.client_seq);
  assert(ctx.num_closes == 0);
  assert(server_received_stream(&ctx, PAYLOAD_SIZE));

  test_teardown(&ctx);
}

/* ******************************************************* */

// After a server half close, the client can still send data (RFC 9293 3.6)
static void test_upload_delivered_after_server_half_close() {
  test_ctx_t ctx;
  test_setup(&ctx);

  uint32_t data_seq = ctx.client_seq;

  server_eof(&ctx);

  assert(ctx.num_server_fins == 1);
  assert(!zdtun_polls_reads(&ctx));

  client_send(&ctx, TH_ACK | TH_PUSH, stream, PAYLOAD_SIZE);
  process_events(&ctx);

  assert(ctx.last_ack == (data_seq + PAYLOAD_SIZE));
  assert(ctx.num_closes == 0);
  assert(ctx.num_rsts == 0);
  assert(server_received_stream(&ctx, PAYLOAD_SIZE));

  test_teardown(&ctx);
}

/* ******************************************************* */

static void test_fin_propagated_after_server_half_close() {
  test_ctx_t ctx;
  char buf[1];
  test_setup(&ctx);

  server_eof(&ctx);
  client_send(&ctx, TH_FIN | TH_ACK, NULL, 0);

  assert(shutdown_calls == 1);
  assert(ctx.last_ack == ctx.client_seq);
  assert(ctx.num_closes == 1);
  assert(ctx.num_rsts == 0);
  assert(server_read(&ctx, buf, sizeof(buf)) == 0);

  test_teardown(&ctx);
}

/* ******************************************************* */

static void test_fin_terminates_when_server_closed() {
  test_ctx_t ctx;
  test_setup(&ctx);

  close_server_socket(&ctx);
  client_send(&ctx, TH_FIN | TH_ACK, NULL, 0);

  assert(ctx.num_closes == 1);
  assert(ctx.num_rsts == 0);

  test_teardown(&ctx);
}

/* ******************************************************* */

static void test_fin_payload_delivered_after_server_eof() {
  test_ctx_t ctx;
  test_setup(&ctx);

  uint32_t data_seq = ctx.client_seq;

  server_eof(&ctx);
  client_send(&ctx, TH_FIN | TH_ACK | TH_PUSH, stream, PAYLOAD_SIZE);
  process_events(&ctx);

  assert(ctx.last_ack == (data_seq + PAYLOAD_SIZE + 1));
  assert(ctx.num_closes == 1);
  assert(ctx.num_rsts == 0);
  assert(server_received_payload(&ctx));

  test_teardown(&ctx);
}

/* ******************************************************* */

// The queued data is only ACKed once written to the socket
static void test_queued_upload_not_acked_at_server_eof() {
  test_ctx_t ctx;
  test_setup(&ctx);

  uint32_t data_seq = ctx.client_seq;

  server_eof_with_queued_upload(&ctx);

  assert(ctx.num_server_fins == 1);
  assert(ctx.last_ack == data_seq);
  assert(ctx.num_closes == 0);

  send_eagain_count = 0;
  process_events(&ctx);

  assert(ctx.last_ack == ctx.client_seq);
  assert(server_received_stream(&ctx, PAYLOAD_SIZE));

  test_teardown(&ctx);
}

/* ******************************************************* */

static void test_partially_sent_upload_delivered_after_server_eof() {
  test_ctx_t ctx;
  test_setup(&ctx);

  uint32_t data_seq = ctx.client_seq;

  send_max_bytes = PARTIAL_SEND_SIZE;
  client_send(&ctx, TH_ACK | TH_PUSH, stream, PAYLOAD_SIZE);
  process_events(&ctx);

  send_eagain_count = NUM_EAGAIN_FOREVER;
  server_eof(&ctx);

  assert(ctx.last_ack == (data_seq + PARTIAL_SEND_SIZE));

  send_eagain_count = 0;
  send_max_bytes = 0;
  process_events(&ctx);

  assert(ctx.last_ack == ctx.client_seq);
  assert(server_received_stream(&ctx, PAYLOAD_SIZE));

  test_teardown(&ctx);
}

/* ******************************************************* */

static void test_fin_acked_after_server_eof_with_queued_upload() {
  test_ctx_t ctx;
  test_setup(&ctx);

  server_eof_with_queued_upload(&ctx);
  client_send(&ctx, TH_FIN | TH_ACK, NULL, 0);

  assert(ctx.num_closes == 0);

  send_eagain_count = 0;
  process_events(&ctx);

  assert(ctx.last_ack == ctx.client_seq);
  assert(ctx.num_closes == 1);
  assert(ctx.num_rsts == 0);
  assert(server_received_payload(&ctx));

  test_teardown(&ctx);
}

/* ******************************************************* */

static void test_data_queued_after_server_eof_with_queued_upload() {
  test_ctx_t ctx;
  test_setup(&ctx);

  server_eof_with_queued_upload(&ctx);
  client_send(&ctx, TH_ACK | TH_PUSH, stream, PAYLOAD_SIZE);

  send_eagain_count = 0;
  process_events(&ctx);

  assert(ctx.last_ack == ctx.client_seq);
  assert(ctx.num_closes == 0);
  assert(server_received_stream(&ctx, PAYLOAD_SIZE));
  assert(server_received_stream(&ctx, PAYLOAD_SIZE));

  test_teardown(&ctx);
}

/* ******************************************************* */

// The upload cannot be delivered, so the client must be told (RFC 9293 3.6.1)
static void test_rst_on_send_error_after_server_eof() {
  test_ctx_t ctx;
  test_setup(&ctx);

  server_eof(&ctx);

  send_errno = EPIPE;
  client_send(&ctx, TH_ACK | TH_PUSH, stream, PAYLOAD_SIZE);
  process_events(&ctx);

  assert(ctx.num_closes == 1);
  assert(ctx.num_rsts == 1);

  test_teardown(&ctx);
}

/* ******************************************************* */

// The EOF of a fully closed server looks like a half close. The server
// replies to the upload with a RST, which fails the next send
static void test_rst_after_upload_to_closed_server() {
  test_ctx_t ctx;
  test_setup(&ctx);

  // Like PCAPdroid, as the send would raise SIGPIPE
  signal(SIGPIPE, SIG_IGN);

  close_server_socket(&ctx);

  client_send(&ctx, TH_ACK | TH_PUSH, stream, PAYLOAD_SIZE);
  process_events(&ctx);

  assert(ctx.num_closes == 0);

  client_send(&ctx, TH_ACK | TH_PUSH, stream, PAYLOAD_SIZE);
  process_events(&ctx);

  assert(ctx.num_closes == 1);
  assert(ctx.num_rsts == 1);

  test_teardown(&ctx);
}

/* ******************************************************* */

// The server replies to the upload with a RST. No send follows it, so the
// RST must be detected on the client FIN, which must not close gracefully
static void test_rst_after_fin_payload_to_closed_server() {
  test_ctx_t ctx;
  test_setup(&ctx);

  signal(SIGPIPE, SIG_IGN);

  close_server_socket(&ctx);

  client_send(&ctx, TH_FIN | TH_ACK | TH_PUSH, stream, PAYLOAD_SIZE);
  process_events(&ctx);

  assert(ctx.num_closes == 1);
  assert(ctx.close_status == CONN_STATUS_SOCKET_ERROR);
  assert(ctx.num_rsts == 1);

  test_teardown(&ctx);
}

/* ******************************************************* */

static void test_rst_after_fin_following_upload_to_closed_server() {
  test_ctx_t ctx;
  test_setup(&ctx);

  signal(SIGPIPE, SIG_IGN);

  close_server_socket(&ctx);

  client_send(&ctx, TH_ACK | TH_PUSH, stream, PAYLOAD_SIZE);
  process_events(&ctx);

  assert(ctx.num_closes == 0);

  client_send(&ctx, TH_FIN | TH_ACK, NULL, 0);

  assert(ctx.num_closes == 1);
  assert(ctx.close_status == CONN_STATUS_SOCKET_ERROR);
  assert(ctx.num_rsts == 1);

  test_teardown(&ctx);
}

/* ******************************************************* */

static void test_rst_on_idle_timeout_after_server_eof() {
  test_ctx_t ctx;
  test_setup(&ctx);

  server_eof(&ctx);

  fake_now += 61;
  zdtun_purge_expired(ctx.tun);

  assert(zdtun_get_num_connections(ctx.tun) == 0);
  assert(ctx.num_rsts == 1);

  test_teardown(&ctx);
}

/* ******************************************************* */

static void test_window_update_applied_by_fin() {
  test_ctx_t ctx;
  test_setup(&ctx);

  server_exhausts_client_window(&ctx);

  ctx.server_seq += PAYLOAD_SIZE;
  ctx.client_window = CLIENT_WINDOW;
  client_send(&ctx, TH_FIN | TH_ACK, NULL, 0);

  assert(zdtun_polls_reads(&ctx));

  ctx.num_replies = 0;
  process_events(&ctx);

  assert(ctx.num_replies == 1);

  test_teardown(&ctx);
}

/* ******************************************************* */

static void test_window_update_applied_by_fin_retransmission() {
  test_ctx_t ctx;
  test_setup(&ctx);

  server_exhausts_client_window(&ctx);
  client_send(&ctx, TH_FIN | TH_ACK, NULL, 0);

  assert(!zdtun_polls_reads(&ctx));

  ctx.server_seq += PAYLOAD_SIZE;
  ctx.client_window = CLIENT_WINDOW;
  client_retransmit_fin(&ctx);

  assert(zdtun_polls_reads(&ctx));

  ctx.num_replies = 0;
  process_events(&ctx);

  assert(ctx.num_replies == 1);

  test_teardown(&ctx);
}

/* ******************************************************* */

static void test_server_eof_not_polled_after_fin_retransmission() {
  test_ctx_t ctx;
  test_setup(&ctx);

  server_eof_while_queued(&ctx);
  client_retransmit_fin(&ctx);

  assert(!zdtun_polls_reads(&ctx));

  test_teardown(&ctx);
}

/* ******************************************************* */

static void test_fin_payload_retransmission_after_close() {
  test_ctx_t ctx;
  test_setup(&ctx);

  client_send(&ctx, TH_FIN | TH_ACK | TH_PUSH, stream, PAYLOAD_SIZE);
  process_events(&ctx);

  uint32_t fin_ack = ctx.last_ack;

  assert(fin_ack == ctx.client_seq);

  ctx.last_ack = 0;
  client_retransmit_fin_payload(&ctx);

  assert(ctx.last_ack == fin_ack);
  assert(!zdtun_polls_writes(&ctx));

  ctx.last_ack = 0;
  client_retransmit_fin_payload(&ctx);

  assert(ctx.last_ack == fin_ack);
  assert(shutdown_calls == 1);
  assert(ctx.num_closes == 0);
  assert(server_received_payload(&ctx));

  test_teardown(&ctx);
}

/* ******************************************************* */

static void test_fin_payload_retransmission_seq_wrap() {
  client_isn = 0xFFFFFFFF - (PAYLOAD_SIZE / 2);

  test_fin_payload_retransmission_after_close();
}

/* ******************************************************* */

static void test_fin_payload_retransmission_while_queued() {
  test_ctx_t ctx;
  test_setup(&ctx);

  uint32_t data_seq = ctx.client_seq;

  send_max_bytes = PARTIAL_SEND_SIZE;
  client_send(&ctx, TH_FIN | TH_ACK | TH_PUSH, stream, PAYLOAD_SIZE);
  process_events(&ctx);

  client_retransmit_fin_payload(&ctx);

  send_max_bytes = 0;
  process_events(&ctx);

  assert(ctx.last_ack == (data_seq + PAYLOAD_SIZE + 1));
  assert(server_received_payload(&ctx));

  test_teardown(&ctx);
}

/* ******************************************************* */

static void test_non_fin_dup_acked_at_fin_payload_seq() {
  test_ctx_t ctx;
  test_setup(&ctx);

  uint32_t data_seq = ctx.client_seq;
  uint32_t fin_ack = data_seq + PAYLOAD_SIZE + 1;

  client_send(&ctx, TH_FIN | TH_ACK | TH_PUSH, stream, PAYLOAD_SIZE);
  process_events(&ctx);

  int num_replies = ctx.num_replies;

  // an old segment is answered with a duplicate ACK (RFC 9293 3.10.7.4)
  ctx.last_ack = 0;
  ctx.client_seq = data_seq;
  client_send(&ctx, TH_ACK | TH_PUSH, stream, PAYLOAD_SIZE);

  assert(ctx.num_replies == (num_replies + 1));
  assert(ctx.last_ack == fin_ack);

  // a segment without ACK is dropped, like Linux does
  ctx.client_seq = data_seq;
  client_send(&ctx, TH_FIN | TH_PUSH, stream, PAYLOAD_SIZE);

  assert(ctx.num_replies == (num_replies + 1));
  assert(!zdtun_polls_writes(&ctx));
  assert(server_received_payload(&ctx));

  test_teardown(&ctx);
}

/* ******************************************************* */

static void test_old_segment_dup_acked() {
  test_ctx_t ctx;
  test_setup(&ctx);

  uint32_t data_seq = ctx.client_seq;

  client_send(&ctx, TH_ACK | TH_PUSH, stream, PAYLOAD_SIZE);
  process_events(&ctx);

  assert(ctx.last_ack == (data_seq + PAYLOAD_SIZE));

  ctx.num_replies = 0;
  ctx.last_ack = 0;
  ctx.client_seq = data_seq;
  client_send(&ctx, TH_ACK | TH_PUSH, stream, PAYLOAD_SIZE);

  assert(ctx.num_replies == 1);
  assert(ctx.last_ack == (data_seq + PAYLOAD_SIZE));
  assert(server_received_stream(&ctx, PAYLOAD_SIZE));

  test_teardown(&ctx);
}

/* ******************************************************* */

static void test_future_segment_dup_acked() {
  test_ctx_t ctx;
  test_setup(&ctx);

  uint32_t data_seq = ctx.client_seq;

  // the first segment is lost, the second one triggers a duplicate ACK (RFC 5681 4.2)
  ctx.client_seq = data_seq + PAYLOAD_SIZE;
  client_send(&ctx, TH_ACK | TH_PUSH, stream + PAYLOAD_SIZE, PAYLOAD_SIZE);

  assert(ctx.num_replies == 1);
  assert(ctx.last_ack == data_seq);
  assert(!zdtun_polls_writes(&ctx));

  ctx.client_seq = data_seq;
  client_send(&ctx, TH_ACK | TH_PUSH, stream, PAYLOAD_SIZE);
  process_events(&ctx);

  assert(ctx.last_ack == (data_seq + PAYLOAD_SIZE));
  assert(server_received_stream(&ctx, PAYLOAD_SIZE));

  test_teardown(&ctx);
}

/* ******************************************************* */

static void test_old_pure_ack_not_replied() {
  test_ctx_t ctx;
  test_setup(&ctx);

  uint32_t data_seq = ctx.client_seq;

  client_send(&ctx, TH_ACK | TH_PUSH, stream, PAYLOAD_SIZE);
  process_events(&ctx);

  ctx.num_replies = 0;
  ctx.client_seq = data_seq;
  client_send(&ctx, TH_ACK, NULL, 0);

  assert(ctx.num_replies == 0);
  assert(!zdtun_polls_writes(&ctx));

  test_teardown(&ctx);
}

/* ******************************************************* */

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
  {"no_rst_reply_to_client_rst", test_no_rst_reply_to_client_rst},
  {"no_rst_reply_to_client_rst_after_server_eof", test_no_rst_reply_to_client_rst_after_server_eof},
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
  {"queued_upload_sent_after_server_eof", test_queued_upload_sent_after_server_eof},
  {"upload_delivered_after_server_half_close", test_upload_delivered_after_server_half_close},
  {"fin_propagated_after_server_half_close", test_fin_propagated_after_server_half_close},
  {"fin_terminates_when_server_closed", test_fin_terminates_when_server_closed},
  {"fin_payload_delivered_after_server_eof", test_fin_payload_delivered_after_server_eof},
  {"fin_payload_retransmission_after_close", test_fin_payload_retransmission_after_close},
  {"fin_payload_retransmission_seq_wrap", test_fin_payload_retransmission_seq_wrap},
  {"fin_payload_retransmission_while_queued", test_fin_payload_retransmission_while_queued},
  {"non_fin_dup_acked_at_fin_payload_seq", test_non_fin_dup_acked_at_fin_payload_seq},
  {"old_segment_dup_acked", test_old_segment_dup_acked},
  {"future_segment_dup_acked", test_future_segment_dup_acked},
  {"old_pure_ack_not_replied", test_old_pure_ack_not_replied},
  {"queued_upload_not_acked_at_server_eof", test_queued_upload_not_acked_at_server_eof},
  {"partially_sent_upload_delivered_after_server_eof", test_partially_sent_upload_delivered_after_server_eof},
  {"fin_acked_after_server_eof_with_queued_upload", test_fin_acked_after_server_eof_with_queued_upload},
  {"data_queued_after_server_eof_with_queued_upload", test_data_queued_after_server_eof_with_queued_upload},
  {"rst_on_send_error_after_server_eof", test_rst_on_send_error_after_server_eof},
  {"rst_after_upload_to_closed_server", test_rst_after_upload_to_closed_server},
  {"rst_after_fin_payload_to_closed_server", test_rst_after_fin_payload_to_closed_server},
  {"rst_after_fin_following_upload_to_closed_server", test_rst_after_fin_following_upload_to_closed_server},
  {"rst_on_idle_timeout_after_server_eof", test_rst_on_idle_timeout_after_server_eof},
  {"window_update_applied_by_fin", test_window_update_applied_by_fin},
  {"window_update_applied_by_fin_retransmission", test_window_update_applied_by_fin_retransmission},
  {"server_eof_not_polled_after_fin_retransmission", test_server_eof_not_polled_after_fin_retransmission},
};

/* ******************************************************* */

int main(int argc, char **argv) {
  return run_test(argc, argv, tests, sizeof(tests) / sizeof(tests[0]));
}
