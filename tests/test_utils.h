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

#ifndef __ZDTUN_TEST_UTILS_H__
#define __ZDTUN_TEST_UTILS_H__

// the tests must not become no-op on release builds
#undef NDEBUG

#include <assert.h>
#include <sys/select.h>
#include <sys/socket.h>
#include "zdtun.h"
#include "third_party/net_headers.h"

#define CLIENT_IP "10.0.0.2"
#define SERVER_IP "127.0.0.1"
#define CLIENT_PORT 12345
#define CLIENT_ISN 1000
#define CLIENT_WINDOW 65535
#define MAX_TCP_OPTIONS_LEN 40
#define PAYLOAD_SIZE 1000
#define STREAM_SIZE 200000
#define IO_TIMEOUT_SEC 5

typedef struct {
  zdtun_t *tun;
  uint8_t ipver;
  zdtun_ip_t client_ip;
  zdtun_ip_t server_ip;
  int listen_sock;
  int server_sock;
  int zdtun_sock;
  uint16_t server_port;
  uint32_t client_seq;
  uint32_t server_seq;
  uint32_t server_next_seq;
  uint32_t last_ack;
  uint16_t client_window;
  uint16_t syn_ack_window;
  int syn_ack_wscale;
  int num_replies;
  int num_server_fins;
  int max_pkt_len;
  int rx_len;
  int num_rsts;
  int num_closes;
  zdtun_conn_status_t close_status;
  uint8_t syn_ack_received;
  uint8_t syn_ack_acked;
  uint8_t fail_rst;
} test_ctx_t;

typedef struct {
  const char *name;
  void (*run)();
} test_t;

// The data sent by the client and by the server
extern char stream[STREAM_SIZE];

void test_init(test_ctx_t *ctx, int (*send_client)(zdtun_t *tun, zdtun_pkt_t *pkt, const zdtun_conn_t *conn_info));
void test_connect(test_ctx_t *ctx, const uint8_t *syn_opts, int syn_opts_len);
void test_teardown(test_ctx_t *ctx);
int run_test(int argc, char **argv, const test_t *tests, size_t num_tests);

int client_iphdr(test_ctx_t *ctx, char *buf, uint8_t ipproto, int l4_len);
void client_send_opts(test_ctx_t *ctx, uint8_t flags, const uint8_t *opts, int opts_len,
        const char *data, int len);
void client_send(test_ctx_t *ctx, uint8_t flags, const char *data, int len);
void client_ack(test_ctx_t *ctx);

void set_recv_timeout(int sock);
void accept_server_sock(test_ctx_t *ctx);
void close_server_socket(test_ctx_t *ctx);
int server_received_stream(test_ctx_t *ctx, int len);

void process_events(test_ctx_t *ctx);
int zdtun_polls_reads(test_ctx_t *ctx);
int zdtun_polls_writes(test_ctx_t *ctx);

#endif
