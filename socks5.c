/* ----------------------------------------------------------------------------
 * Zero Dep Tunnel: VPN library without dependencies
 * ----------------------------------------------------------------------------
 *
 * Copyright (C) 2021 - Emanuele Faranda
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

// See https://en.wikipedia.org/wiki/SOCKS#SOCKS5

PACK_ON
struct socks5_srv_choice {
  uint8_t ver;
  uint8_t cauth;
} PACK_OFF;

PACK_ON
struct socks5_connect_reply {
  uint8_t ver;
  uint8_t status;
  uint8_t rsv;
  uint8_t bndaddr[];
  //uint16_t bndport;
} PACK_OFF;

typedef enum {
  SOCKS5_REQUEST_GRANTED        = 0,
  SOCKS5_GENERAL_FAILURE        = 1,
  SOCKS5_NOT_ALLOWED_BY_RULESET = 2,
  SOCKS5_NETWORK_UNREACHABLE    = 3,
  SOCKS5_HOST_UNREACHABLE       = 4,
  SOCKS5_CONNECTION_REFUSED     = 5,
  SOCKS5_TTL_EXPIRED            = 6,
  SOCKS5_PROTO_ERROR            = 7,
  SOCKS5_ADDRTYPE_UNSUPPORTED   = 8
} socks5_connect_status;

/* ******************************************************* */

int socks5_connect(zdtun_t *tun, zdtun_conn_t *conn) {
  // ver, nauth, no_auth
  uint8_t hello[] = {5, 1, 0};

  if(send(conn->sock, hello, 3, 0) < 0)
    return close_with_socket_error(tun, conn, "SOCKS5_HELLO send");

  //debug("SOCKS5_HELLO sent");

  conn->socks5_status = SOCKS5_HELLO;

  return 0;
}

/* ******************************************************* */

int handle_socks5_reply(zdtun_t *tun, zdtun_conn_t *conn, char *data, int len) {
  if(conn->socks5_status == SOCKS5_HELLO) {
    struct socks5_srv_choice *reply = (struct socks5_srv_choice*) data;

    if((len != 2) || (reply->ver != 5)) {
      close_conn(tun, conn, CONN_STATUS_SOCKS5_ERROR);
      return -1;
    }

    uint8_t req[32], *p;
    int addrsize;

    p = req;
    (*p++) = 5; // ver
    (*p++) = 1; // cmd: TCP/IP connection
    (*p++) = 0; // reserved

    if(conn->tuple.ipver == 4) {
      (*p++) = 1; // IPv4 address
      memcpy(p, &conn->tuple.dst_ip.ip4, 4);
      addrsize = 4;
    } else {
      (*p++) = 4; // IPv6 address
      memcpy(p, &conn->tuple.dst_ip.ip6, 16);
      addrsize = 16;
    }

    memcpy(p+addrsize, &conn->tuple.dst_port, 2);

    if(send(conn->sock, req, 6+addrsize, 0) < 0)
      return close_with_socket_error(tun, conn, "SOCKS5_CONNECTING send");

    //debug("SOCKS5_CONNECTING sent");

    conn->socks5_status = SOCKS5_CONNECTING;
    return 0;
  } else if(conn->socks5_status == SOCKS5_CONNECTING) {
    struct socks5_connect_reply *reply = (struct socks5_connect_reply*) data;

    if((len < 4) || (reply->ver != 5)) {
      close_conn(tun, conn, CONN_STATUS_SOCKS5_ERROR);
      return -1;
    }

    if(reply->status != 0) {
      zdtun_conn_status_t status;
      int rv;

      debug("SOCKS5 connect failed with code %d", reply->status);

      switch(reply->status) {
        case SOCKS5_HOST_UNREACHABLE:
        case SOCKS5_NETWORK_UNREACHABLE:
          status = CONN_STATUS_UNREACHABLE;
          rv = 0;
          break;
        case SOCKS5_CONNECTION_REFUSED:
          status = CONN_STATUS_SOCKET_ERROR;
          rv = 0;
          break;
        default:
          status = CONN_STATUS_SOCKS5_ERROR;
          rv = -1;
      }

      close_conn(tun, conn, status);
      return rv;
    } else {
      uint8_t addrtype = reply->bndaddr[0];
      uint8_t to_skip = 0;

      // DSTADDR
      if(addrtype == 1) // IPv4
        to_skip = 4;
      else if(addrtype == 4) // IPv6
        to_skip = 16;
      else {
        error("invalid SOCKS5 addr type: %d", addrtype);

        close_conn(tun, conn, CONN_STATUS_SOCKS5_ERROR);
        return -1;
      }

      // DSTPORT
      to_skip += 2;

      // some proxies split the BND address and port in different messages,
      // use SOCKS5_SKIP_BND to skip such bytes
      conn->socks5_skip = to_skip;
      conn->socks5_status = SOCKS5_SKIP_BND;

      if(len > 4)
        return handle_socks5_reply(tun, conn, data + 4, len - 4);

      return 0;
    }
  } else if((conn->socks5_status == SOCKS5_SKIP_BND) && (len <= conn->socks5_skip)) {
    conn->socks5_skip -= len;

    if(conn->socks5_skip == 0) {
      //debug("SOCKS5 established");
      conn->socks5_status = SOCKS5_ESTABLISHED;
    }

    return 0;
  } else {
    error("invalid SOCKS5 status: %d", conn->socks5_status);

    close_conn(tun, conn, CONN_STATUS_SOCKS5_ERROR);
    return -1;
  }
}
