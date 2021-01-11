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

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include "zdtun.h"
#include "utils.h"

#ifndef WIN32
#include <signal.h>
#endif

#define PACKET_BUFSIZE 65535
#define MAX_PURGE_SECS 3

#define eprintf(...) fprintf(stderr, __VA_ARGS__);

/* ******************************************************* */

static int data_in(zdtun_t *tun, char *pkt_buf, int pkt_size, const zdtun_conn_t *conn_info) {
  socket_t client_sock = *((socket_t *)zdtun_userdata(tun));

  con_send(client_sock, pkt_buf, pkt_size);
  return 0;
}

/* ******************************************************* */

static void print_zdtun_stats(zdtun_t *tun) {
  time_t now = time(NULL);

  struct zdtun_statistics _stats;
  struct zdtun_statistics *stats = &_stats;
  zdtun_get_stats(tun, stats);

  eprintf("**** ZDTUN STATS ****\n");
  eprintf("  tot_icmp_opened: %u\n", stats->num_icmp_opened);
  eprintf("  tot_tcp_opened: %u\n", stats->num_tcp_opened);
  eprintf("  tot_udp_opened: %u\n\n", stats->num_udp_opened);
  eprintf("  num_open_sockets: %u\n", stats->num_open_sockets);
  eprintf("  num_icmp_conn: %u\n", stats->num_icmp_conn);
  eprintf("  num_tcp_conn: %u\n", stats->num_tcp_conn);
  eprintf("  num_udp_conn: %u\n\n", stats->num_udp_conn);
  eprintf("  oldest_icmp_conn: %lu sec ago\n", (stats->oldest_icmp_conn) ? (now - stats->oldest_icmp_conn) : 0);
  eprintf("  oldest_tcp_conn: %lu sec ago\n", (stats->oldest_tcp_conn) ? (now - stats->oldest_tcp_conn) : 0);
  eprintf("  oldest_udp_conn: %lu sec ago\n", (stats->oldest_udp_conn) ? (now - stats->oldest_udp_conn) : 0);
  eprintf("********************\n\n");
}

/* ******************************************************* */

static bool running;

#ifndef WIN32

static void term_handler(int signo) {
  if(running) {
    eprintf("Shutting down...");
    running = false;
  } else {
    eprintf("Leaving now");
    exit(0);
  }
}

#endif

/* ******************************************************* */

int main(int argc, char **argv) {
#ifdef WIN32
  WORD wVersionRequested;
  WSADATA wsaData;

  wVersionRequested = MAKEWORD(2, 2);

  int err = WSAStartup(wVersionRequested, &wsaData);

  err = WSAStartup(wVersionRequested, &wsaData);
  if(err != 0)
    fatal("WSAStartup failed with error: %d\n", err);
#else
  signal(SIGPIPE, SIG_IGN);
#endif

  running = true;

#ifndef WIN32
  signal(SIGINT, term_handler);
#endif

  if(argc != 3)
    fatal("Usage: %s [-l port|ip port]", argv[0]);

  con_mode_info info;
  con_parse_args(argv, &info);

  char *buffer = (char *) malloc(PACKET_BUFSIZE);

  if(!buffer)
    fatal("Cannot allocate packet buffer[%d]", errno);

  zdtun_t *tun;
  socket_t sock;
  zdtun_callbacks_t callbacks = {
    .send_client = data_in,
  };

  while(true) {
    struct sockaddr_in client_addr;
    sock = con_wait_connection(&info, &client_addr);

    char buf1[INET_ADDRSTRLEN];
    log("Client connection: %s", ipv4str(client_addr.sin_addr.s_addr, buf1));

    time_t last_purge = time(NULL);
    tun = zdtun_init(&callbacks, &sock);

    if(!tun)
      exit(1);

    while(running) {
      bool do_purge = false;

      if((time(NULL) - last_purge) >= MAX_PURGE_SECS) {
        do_purge = true;
      } else {
        int max_fd = 0;
        fd_set fdset;
        fd_set wrfds;
  
        zdtun_fds(tun, &max_fd, &fdset, &wrfds);

        FD_SET(sock, &fdset);

#ifndef WIN32
        max_fd = max(max_fd, sock);
#endif

        struct timeval tv = {0};
        tv.tv_sec = 1;

        int ret = select(max_fd + 1, &fdset, &wrfds, NULL, &tv);

        if(!running)
          break;
        else if(ret == SOCKET_ERROR) {
          fatal("Select error[%d]\n", socket_errno);
        } else if (ret > 0) {
          if(FD_ISSET(sock, &fdset)) {
            u_int32_t size = con_recv(sock, buffer, PACKET_BUFSIZE);

            if(!size)
              break;

            debug("Got %u bytes from the client", size);

            if(!zdtun_easy_forward(tun, buffer, size))
              error("zdtun_easy_forward failed");
          } else
            zdtun_handle_fd(tun, &fdset, &wrfds);
        } else {
          do_purge = true;
        }
      }

      if(do_purge) {
        print_zdtun_stats(tun);
        last_purge = time(NULL);
        zdtun_purge_expired(tun, last_purge);
      }
    }

    // no more requests supported
    break;
  }

  free(buffer);
  closesocket(sock);
  ztdun_finalize(tun);
}
