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

#ifndef __ZDTUN_H__
#define __ZDTUN_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <time.h>

/* ********************************* */

/* DEBUG OPTIONS */
//#define SHOW_DEBUG
//#define SHOW_PACKETS_LOG
//#define SHOW_TCP_WINDOW_LOG

/* ********************************* */

#ifdef SHOW_DEBUG
#define debug(...) { log(__VA_ARGS__); }
#else
#define debug(...) {}
#endif

#ifdef SHOW_PACKETS_LOG
#define log_packet(...) { log(__VA_ARGS__); }
#else
#define log_packet(...) {}
#endif

#ifdef SHOW_TCP_WINDOW_LOG
#define log_tcp_window(...) { log(__VA_ARGS__); }
#else
#define log_tcp_window(...) {}
#endif

#ifndef NO_DEBUG

#ifdef ANDROID
#include <android/log.h>
#define log(...) { __android_log_print(ANDROID_LOG_INFO, "zdtun", __VA_ARGS__); }
#define error(...) { __android_log_print(ANDROID_LOG_ERROR, "zdtun", __VA_ARGS__); }
#else
#define log(...) { printf(__VA_ARGS__); fputc('\n', stdout); }
#define error(...) { fprintf(stderr, __VA_ARGS__); fputc('\n', stderr); }
#endif

#else

#ifndef log
#define log(...) {}
#endif
#ifndef error
#define error(...) {}
#endif

#endif

#define fatal(...) { error(__VA_ARGS__); exit(1); }

#define ZDTUN_IP_HEADER_SIZE 20

#ifdef WIN32
#include <stdint.h>
 
typedef uint8_t u_int8_t;
typedef uint16_t u_int16_t;
typedef uint32_t u_int32_t;

typedef unsigned int uint;
typedef int ssize_t;

#else

#define max(a, b) ((a > b) ? (a) : (b))
#define min(a, b) ((a < b) ? (a) : (b))

#endif

#ifdef WIN32

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

typedef SOCKET socket_t;
#define socket_errno (WSAGetLastError())
#define socket_in_progress (WSAEWOULDBLOCK)
#define socket_con_refused (WSAECONNREFUSED)
#define socket_con_reset (WSAECONNRESET)

#else

#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#define socket_errno (errno)
#define socket_in_progress (EINPROGRESS)
#define socket_con_refused (ECONNREFUSED)
#define socket_con_reset (ECONNRESET)
typedef int socket_t;
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#define closesocket close

#endif // WIN32

/* ********************************* */

/* Cisco HDLC */
#ifdef _MSC_VER
/* Windows */
#define PACK_ON   __pragma(pack(push, 1))
#define PACK_OFF  __pragma(pack(pop))
#elif defined(__GNUC__)
/* GNU C */
#define PACK_ON
#define PACK_OFF  __attribute__((packed))
#endif

#define safe_alloc(item, type) do {        \
  item = (type*) calloc(1, sizeof(type));  \
  if(!item)                                \
    fatal("calloc failed at %d", __LINE__) \
} while(0)

typedef struct zdtun_t zdtun_t;

/* ********************************* */
/*             ZDTUN API             */
/* ********************************* */

/*
 * @brief a structure containing zdtun statistics.
 */
typedef struct zdtun_statistics {
  u_int16_t num_icmp_conn;              ///< current number of active ICMP connections
  u_int16_t num_tcp_conn;               ///< current number of active TCP connections
  u_int16_t num_udp_conn;               ///< current number of active UDP connections

  u_int32_t num_icmp_opened;            ///< total number of ICMP connections (since zdtun_init)
  u_int32_t num_tcp_opened;             ///< total number of TCP connections (since zdtun_init)
  u_int32_t num_udp_opened;             ///< total number of UDP connections (since zdtun_init)

  time_t oldest_icmp_conn;              ///< timestamp of the oldest active ICMP connection
  time_t oldest_tcp_conn;               ///< timestamp of the oldest active TCP connection
  time_t oldest_udp_conn;               ///< timestamp of the oldest active UDP connection

  u_int32_t num_open_sockets;           ///< number of opened sockets in zdtun
} zdtun_statistics_t;

// packed - to be used with uthash
typedef PACK_ON struct zdtun_5tuple {
  u_int32_t src_ip;
  u_int32_t dst_ip;

  union {
    u_int16_t src_port;
    u_int16_t echo_id;
  };

  union {
    u_int16_t dst_port;
    u_int16_t echo_seq;
  };

  u_int8_t ipproto;
} PACK_OFF zdtun_5tuple_t;

/*
 * @brief represents a connection in zdtun
 */
typedef struct zdtun_conn zdtun_conn_t;

/*
 * @brief a container for a packet metadata.
 */
typedef struct zdtun_pkt {
  zdtun_5tuple_t tuple;

  u_int16_t pkt_len;
  u_int16_t ip_hdr_len;
  u_int16_t l4_hdr_len;
  u_int16_t l7_len;

  /* Packet buffer */
  char *buf;

  /* L3 pointers */
  union {
    char *l3;
    struct iphdr *ip;
  };

  /* L4 pointers */
  union {
    char *l4;
    struct tcphdr *tcp;
    struct udphdr *udp;
    struct icmphdr *icmp;
  };

  /* L7 pointer */
  char *l7;
} zdtun_pkt_t;

/*
 * @brief A connections iterator.
 * @return 0 to continue iteration, != 0 to abort it.
 */
typedef int (*zdtun_conn_iterator_t)(zdtun_t *tun, const zdtun_conn_t *conn_info, void *userdata);

typedef struct zdtun_callbacks {
  /*
   * @brief (mandatory) Send data to the client.
   *
   * @param tun the zdtun instance the packet comes from
   * @param pkt_buf the buffer pointing to IP header and data
   * @param pkt_size the total size of the IP packet
   * @param conn_info contains information about the connection
   *
   * @return 0 on success
   */
  int (*send_client) (zdtun_t *tun, char *pkt_buf, ssize_t pkt_size, const zdtun_conn_t *conn_info);

  /*
   * @brief A callback to easily account packets exchanged between the pivot and zdtun.
   *
   * @param tun the zdtun instance
   * @param pkt_buf the buffer pointing to IP header and data
   * @param pkt_size the total size of the IP packet
   * @param to_zdtun 1 if the packet is generated from the pivot, false otherwise
   * @param conn_info contains information about the connection
   */
  void (*account_packet) (zdtun_t *tun, const char *pkt_buf, ssize_t pkt_size, uint8_t to_zdtun, const zdtun_conn_t *conn_info);

  /*
   * @brief Called whenever a new socket is opened.
   * @param tun the zdtun instance
   * @param socket the socket which has been opened
   */
  void (*on_socket_open) (zdtun_t *tun, socket_t socket);

  /*
   * @brief Called whenever a socket is being closed.
   * @param tun the zdtun instance
   * @param socket the socket which is being closed
   */
  void (*on_socket_close) (zdtun_t *tun, socket_t socket);

  /*
   * @brief Called whenever a new connection is created.
   *
   * @param tun the zdtun instance
   * @param conn_info information about the connection
   *
   * @return 0 if the connection can be established, 1 to block it
   */
  int (*on_connection_open) (zdtun_t *tun, zdtun_conn_t *conn_info);

  /*
   * @brief Called whenever a connection is closed.
   *
   * @param tun the zdtun instance
   * @param conn_info information about the connection. User provided user_data should be manually freed.
   */
  void (*on_connection_close) (zdtun_t *tun, const zdtun_conn_t *conn_info);
} zdtun_callbacks_t;

/*
 * @brief Inizialize a zdtun instance.
 *
 * @param client_callback the callback to use to send data to the client.
 * @param udata a user data pointer that will be passed to the client_callback.
 *
 * @return a zdtun_t instance on success, NULL on failure.
 */
zdtun_t* zdtun_init(struct zdtun_callbacks *callbacks, void *udata);

void zdtun_destroy_conn(zdtun_t *tun, zdtun_conn_t *conn);

/*
 * @brief Retrieves user data passed in zdtun_init from a zdtun connection.
 *
 * @return (possibly NULL) user data
 */
void* zdtun_userdata(zdtun_t *tun);

/*
 * @brief Finalize a zdtun instance.
 *
 * @param tun the zdtun instance to destroy.
 */
void ztdun_finalize(zdtun_t *tun);

/*
 * @brief Get zdtun file descriptors, suitable for a select.
 *
 * @param tun a zdtun instance.
 * @param max_fd will be filled with the maximum fd number from zdtun.
 * @param rdfd will be filled with zdtun readable file descriptors.
 * @param wrfd will be filled with zdtun writable file descriptors.
 */
void zdtun_fds(zdtun_t *tun, int *max_fd, fd_set *rdfd, fd_set *wrfd);

/*
 * @brief Iterate the active connections
 *
 * @param tun a zdtun instance.
 * @param iterator the iterator to be called.
 * @param userdata some arbitrary data to pass to the iterator.
 *
 * @return 0 if all the connections were iterated, 1 if the iterator aborted the iteration.
 */
int zdtun_iter_connections(zdtun_t *tun, zdtun_conn_iterator_t iterator, void *userdata);

/*
 * @brief handle zdtun ready file descriptors. To be called after a select.
 *
 * @param tun a zdtun instance.
 * @param rd_fds pointer to readable fds as returned by select.
 * @param wr_fds pointer to writable fds as returned by select.
 *
 * @return number of handled file descriptors.
 */
int zdtun_handle_fd(zdtun_t *tun, const fd_set *rd_fds, const fd_set *wr_fds);

/*
 * @brief purge expired connections. To be called periodically.
 *
 * @param tun a zdtun instance.
 */
void zdtun_purge_expired(zdtun_t *tun, time_t now);

/*
 * Get zdtun statisticts.
 *
 * @param tun a zdtun instance.
 * @param stats structure to be filled with zdtun statisticts.
 */
void zdtun_get_stats(zdtun_t *tun, zdtun_statistics_t *stats);

/*
 * Get the number of active connections
 *
 * @param tun a zdtun instance.
 *
 * @return the number of active connections
 */
int zdtun_get_num_connections(zdtun_t *tun);

/*
 * Parse a packet and populate the zdtun_pkt_t structure with its metadata.
 *
 * @param pkt_buf buffer pointing to IP header and data.
 * @param pkt_len total size of the IP packet.
 * @param pinfo pointer to the output structure.
 *
 * @return 0 on success, error code otherwise.
 */
int zdtun_parse_pkt(const char *pkt_buf, uint16_t pkt_len, zdtun_pkt_t *pinfo);

/*
 * Forward a client packet through the pivot.
 *
 * @param tun a zdtun instance.
 * @param pkt_buf buffer pointing to IP header and data.
 * @param pkt_len total size of the IP packet.
 *
 * @return zdtun_conn_t instance on success, NULL on failure.
 */
zdtun_conn_t* zdtun_easy_forward(zdtun_t *tun, const char *pkt_buf, size_t pkt_len);

/*
 * Forward a client packet through the pivot.
 *
 * @param tun a zdtun instance.
 * @param pkt the packet to forward.
 * @param conn the connection, obtained by calling zdtun_lookup.
 *
 * @return 0 on success, errcode otherwise.
 */
int zdtun_forward(zdtun_t *tun, const zdtun_pkt_t *pkt, zdtun_conn_t *conn);

/*
 * Send a client packet containing out of band data through the pivot.
 *
 * This can be used to inject additional data, not present in the
 * original TCP communication, without breaking the original TCP stream.
 * The client won't know anything about this data, only the TCP receiver
 * will.
 *
 * @param tun a zdtun instance.
 * @param pkt the oob data to send.
 * @param conn the connection, obtained by calling zdtun_lookup.
 *
 * @return 0 on success, errcode otherwise.
 */
int zdtun_send_oob(zdtun_t *tun, const zdtun_pkt_t *pkt, zdtun_conn_t *conn);

/*
 * Look up a flow or create it if it's not found.
 *
 * @param tun a zdtun instance.
 * @param tuple the connection 5-tuple.
 * @create 1 if a new connection should be created if not found, 0 otherwise.
 *
 * @return zdtun_conn_t instance on success, NULL on failure.
 */
zdtun_conn_t* zdtun_lookup(zdtun_t *tun, const zdtun_5tuple_t *tuple, uint8_t create);

/* Connection methods */
void* zdtun_conn_get_userdata(const zdtun_conn_t *conn);
void zdtun_conn_set_userdata(zdtun_conn_t *conn, void *userdata);
int zdtun_conn_dnat(zdtun_conn_t *conn, uint32_t dest_ip, uint16_t dest_port);
const zdtun_5tuple_t* zdtun_conn_get_5tuple(const zdtun_conn_t *conn);

#endif
