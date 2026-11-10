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

#include <signal.h>
#include "test_utils.h"

#define MAX_TCP_HEADERS_LEN (sizeof(struct ipv6_hdr) + sizeof(struct tcphdr))

char stream[STREAM_SIZE];

/* ******************************************************* */

static void on_socket_open(zdtun_t *tun, socket_t sock) {
  test_ctx_t *ctx = (test_ctx_t*) zdtun_userdata(tun);

  ctx->zdtun_sock = sock;
}

/* ******************************************************* */

static void on_connection_close(zdtun_t *tun, const zdtun_conn_t *conn_info) {
  test_ctx_t *ctx = (test_ctx_t*) zdtun_userdata(tun);

  ctx->num_closes++;
  ctx->close_status = zdtun_conn_get_status(conn_info);
}

/* ******************************************************* */

void set_recv_timeout(int sock) {
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
void test_init(test_ctx_t *ctx, int (*send_client)(zdtun_t *tun, zdtun_pkt_t *pkt, const zdtun_conn_t *conn_info)) {
  zdtun_callbacks_t callbacks = {
    .send_client = send_client,
    .on_socket_open = on_socket_open,
    .on_connection_close = on_connection_close,
  };

  memset(ctx, 0, sizeof(*ctx));

  ctx->ipver = 4;
  ctx->client_ip.ip4 = inet_addr(CLIENT_IP);
  ctx->server_ip.ip4 = inet_addr(SERVER_IP);
  ctx->server_sock = -1;
  ctx->client_seq = CLIENT_ISN;
  ctx->client_window = CLIENT_WINDOW;

  for(int i = 0; i < STREAM_SIZE; i++)
    stream[i] = (char) (i % 251);

  open_listen_socket(ctx);

  ctx->tun = zdtun_init(&callbacks, ctx);
  assert(ctx->tun != NULL);
}

/* ******************************************************* */

void accept_server_sock(test_ctx_t *ctx) {
  ctx->server_sock = accept(ctx->listen_sock, NULL, NULL);
  assert(ctx->server_sock >= 0);

  set_recv_timeout(ctx->server_sock);
}

/* ******************************************************* */

// Establishes a connection from the client to the server, via zdtun
void test_connect(test_ctx_t *ctx, const uint8_t *syn_opts, int syn_opts_len) {
  client_send_opts(ctx, TH_SYN, syn_opts, syn_opts_len, NULL, 0);

  // A loopback connect can either complete immediately or be in progress
  while(!ctx->syn_ack_received)
    process_events(ctx);

  accept_server_sock(ctx);
  client_ack(ctx);
}

/* ******************************************************* */

void test_teardown(test_ctx_t *ctx) {
  zdtun_finalize(ctx->tun);

  if(ctx->server_sock >= 0)
    close(ctx->server_sock);

  close(ctx->listen_sock);
}

/* ******************************************************* */

int run_test(int argc, char **argv, const test_t *tests, size_t num_tests) {
  if(argc != 2) {
    fprintf(stderr, "Usage: %s test_name\n", argv[0]);
    return 2;
  }

  // a send on a closed socket must fail with EPIPE, like in the zdtun integrations
  signal(SIGPIPE, SIG_IGN);

  for(size_t i = 0; i < num_tests; i++) {
    if(!strcmp(argv[1], tests[i].name)) {
      tests[i].run();
      return 0;
    }
  }

  fprintf(stderr, "Unknown test: %s\n", argv[1]);
  return 2;
}

/* ******************************************************* */

// Writes the IP header of a client packet, returning its length
int client_iphdr(test_ctx_t *ctx, char *buf, uint8_t ipproto, int l4_len) {
  if(ctx->ipver == 4) {
    struct iphdr *ip = (struct iphdr*) buf;

    memset(ip, 0, sizeof(*ip));
    ip->version = 4;
    ip->ihl = 5;
    ip->tot_len = htons(sizeof(*ip) + l4_len);
    ip->ttl = 64;
    ip->protocol = ipproto;
    ip->saddr = ctx->client_ip.ip4;
    ip->daddr = ctx->server_ip.ip4;

    return sizeof(*ip);
  } else {
    struct ipv6_hdr *ip = (struct ipv6_hdr*) buf;

    memset(ip, 0, sizeof(*ip));
    ip->version = 6;
    ip->payload_len = htons(l4_len);
    ip->nexthdr = ipproto;
    ip->hop_limit = 64;
    ip->saddr = ctx->client_ip.ip6;
    ip->daddr = ctx->server_ip.ip6;

    return sizeof(*ip);
  }
}

/* ******************************************************* */

void client_send_opts(test_ctx_t *ctx, uint8_t flags, const uint8_t *opts, int opts_len,
        const char *data, int len) {
  static char buf[MAX_TCP_HEADERS_LEN + MAX_TCP_OPTIONS_LEN + PAYLOAD_SIZE] __attribute__((aligned(4)));
  int l4_len = sizeof(struct tcphdr) + opts_len + len;

  assert((opts_len % 4) == 0);
  assert(opts_len <= MAX_TCP_OPTIONS_LEN);
  assert(len <= PAYLOAD_SIZE);

  int iphdr_len = client_iphdr(ctx, buf, IPPROTO_TCP, l4_len);
  struct tcphdr *tcp = (struct tcphdr*) (buf + iphdr_len);
  int pkt_len = iphdr_len + l4_len;

  memset(tcp, 0, sizeof(*tcp));

  tcp->th_sport = htons(CLIENT_PORT);
  tcp->th_dport = htons(ctx->server_port);
  tcp->th_seq = htonl(ctx->client_seq);
  tcp->th_ack = htonl(ctx->server_seq);
  tcp->th_off = 5 + (opts_len / 4);
  tcp->th_flags = flags;
  tcp->th_win = htons(ctx->client_window);

  if(opts_len > 0)
    memcpy(buf + iphdr_len + sizeof(struct tcphdr), opts, opts_len);

  if(len > 0)
    memcpy(buf + iphdr_len + sizeof(struct tcphdr) + opts_len, data, len);

  assert(zdtun_easy_forward(ctx->tun, buf, pkt_len) != NULL);

  if((flags & TH_ACK) && ctx->syn_ack_received)
    ctx->syn_ack_acked = 1;

  ctx->client_seq += len + ((flags & (TH_SYN | TH_FIN)) ? 1 : 0);
}

/* ******************************************************* */

void client_send(test_ctx_t *ctx, uint8_t flags, const char *data, int len) {
  client_send_opts(ctx, flags, NULL, 0, data, len);
}

/* ******************************************************* */

void client_ack(test_ctx_t *ctx) {
  client_send(ctx, TH_ACK, NULL, 0);
}

/* ******************************************************* */

void close_server_socket(test_ctx_t *ctx) {
  close(ctx->server_sock);
  ctx->server_sock = -1;

  // zdtun reads the server EOF and closes its own socket
  process_events(ctx);
}

/* ******************************************************* */

// Checks that the server received the first len bytes of the stream
int server_received_stream(test_ctx_t *ctx, int len) {
  char rx[PAYLOAD_SIZE];

  assert(len <= PAYLOAD_SIZE);

  if(recv(ctx->server_sock, rx, len, MSG_WAITALL) != len)
    return 0;

  return(memcmp(rx, stream, len) == 0);
}

/* ******************************************************* */

// Handles a single batch of socket events
void process_events(test_ctx_t *ctx) {
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

static int any_fd_set(const fd_set *fds, int max_fd) {
  for(int fd = 0; fd <= max_fd; fd++) {
    if(FD_ISSET(fd, fds))
      return 1;
  }

  return 0;
}

/* ******************************************************* */

int zdtun_polls_reads(test_ctx_t *ctx) {
  fd_set rd_fds;
  fd_set wr_fds;
  int max_fd = 0;

  zdtun_fds(ctx->tun, &max_fd, &rd_fds, &wr_fds);

  return any_fd_set(&rd_fds, max_fd);
}

/* ******************************************************* */

int zdtun_polls_writes(test_ctx_t *ctx) {
  fd_set rd_fds;
  fd_set wr_fds;
  int max_fd = 0;

  zdtun_fds(ctx->tun, &max_fd, &rd_fds, &wr_fds);

  return any_fd_set(&wr_fds, max_fd);
}
