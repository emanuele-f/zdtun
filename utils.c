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

#include "zdtun.h"
#include "utils.h"

// NOTE: xor is not safe!
#define ENCODE_KEY "?!?0QAxAW1e.^9KJdma(//n PQe["

/* ******************************************************* */

static socket_t server_init(const char *address, int listen_port) {
  socket_t listen_sock;

  if((listen_sock = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
    fatal("could not create socket[%d]", socket_errno);

  if(setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, (char*)(&(int){ 1 }), sizeof(int)) == SOCKET_ERROR)
    fatal("setsockopt(SO_REUSEADDR) failed[%d]", socket_errno);

  struct sockaddr_in server_address;
  memset(&server_address, 0, sizeof(server_address));
  server_address.sin_family = AF_INET;

  inet_pton(AF_INET, address, &server_address.sin_addr);
  server_address.sin_port = htons(listen_port);

  if ((bind(listen_sock, (struct sockaddr *)&server_address,
            sizeof(server_address))) == SOCKET_ERROR)
    fatal("could not bind the socket [%d]", socket_errno);

  int wait_size = 1;

  if(listen(listen_sock, wait_size) == SOCKET_ERROR)
    fatal("socket listen error [%d]", socket_errno);

  log("Listening on port %d", listen_port);

  return listen_sock;
}

/* ******************************************************* */

static socket_t client_init(const char *server_name, int server_port, struct sockaddr_in *srv_addr) {
  struct sockaddr_in server_address;
  memset(&server_address, 0, sizeof(server_address));
  server_address.sin_family = AF_INET;

  inet_pton(AF_INET, server_name, &server_address.sin_addr);
  server_address.sin_port = htons(server_port);

  socket_t sock;
  if((sock = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
    fatal("could not create socket[%d]", sock);

  if(connect(sock, (struct sockaddr*)&server_address, sizeof(server_address)) == SOCKET_ERROR)
    fatal("could not connect to the server[%d]", socket_errno);

  *srv_addr = server_address;
  return sock;
}

void con_parse_args(char **argv, con_mode_info *info) {
  memset(info, 0, sizeof(*info));

  if(!strcmp(argv[1], "-l")) {
    info->mode = CON_MODE_SERVER;
    info->address = "0.0.0.0";
  } else {
    info->mode = CON_MODE_CLIENT;
    info->address = argv[1];
  }

  info->port = atoi(argv[2]);
}

/* ******************************************************* */

socket_t con_wait_connection(con_mode_info *info, struct sockaddr_in *cli_addr) {
  socket_t sock;
  socklen_t client_address_len = sizeof(*cli_addr);

  if(info->mode == CON_MODE_SERVER) {
    info->socket = server_init(info->address, info->port);

    if((sock = accept(info->socket, (struct sockaddr *)cli_addr,
                    &client_address_len)) == SOCKET_ERROR)
      fatal("socket accept error [%d]", socket_errno);
  } else {
    info->socket = client_init(info->address, info->port, cli_addr);
    sock = info->socket;
  }

  return sock;
}

/* ******************************************************* */

void con_send(socket_t sock, char*data, u_int32_t len) {
  u_int32_t bo_len = htonl(len);

  xor_encdec(data, len, ENCODE_KEY);

  // send the size
  send(sock, (char*)&bo_len, sizeof(bo_len), 0);

  // send data
  send(sock, data, len, 0);
}

u_int32_t con_recv(socket_t sock, char*data, u_int32_t len) {
  u_int32_t size;
  int rv;

  // read the size
  if((rv = recv(sock, (char*)&size, sizeof(size), 0)) == SOCKET_ERROR)
    fatal("recv error1: %d", socket_errno);

  if(rv == 0)
    fatal("peer disconnected");

  size = ntohl(size);

  if(size > len)
    fatal("Packet too big!");

  u_int32_t sofar = 0;

  // read the data
  while(sofar < size) {
    int n = recv(sock, &data[sofar], size - sofar, 0);

    if(n == SOCKET_ERROR)
      fatal("recv error2: %d", socket_errno);

    if(n == 0)
      fatal("peer disconnected");

    sofar += n;
  }

  xor_encdec(data, size, ENCODE_KEY);
  return size;
}

/* ******************************************************* */

char* ipv4str(u_int32_t addr, char *buf) {
  struct in_addr sin = {0};
  sin.s_addr = addr;

  inet_ntop(AF_INET, (char*)&sin, buf, INET_ADDRSTRLEN);
  return buf;
}

/* ******************************************************* */

// from http://minirighi.sourceforge.net/html/tcp_8c-source.html
u_int16_t tcp_checksum(const void *buff, size_t len, u_int32_t src_addr, u_int32_t dest_addr) {
  const uint16_t *buf=buff;
  uint16_t *ip_src=(void *)&src_addr, *ip_dst=(void *)&dest_addr;
  uint32_t sum;
  size_t length=len;

  // Calculate the sum
  sum = 0;
  while (len > 1) {
    sum += *buf++;
    if (sum & 0x80000000)
      sum = (sum & 0xFFFF) + (sum >> 16);
    len -= 2;
  }

  if ( len & 1 )
    // Add the padding if the packet lenght is odd
    sum += *((uint8_t *)buf);

  // Add the pseudo-header
  sum += *(ip_src++);
  sum += *ip_src;
  sum += *(ip_dst++);
  sum += *ip_dst;
  sum += htons(IPPROTO_TCP);
  sum += htons(length);

  // Add the carries
  while (sum >> 16)
    sum = (sum & 0xFFFF) + (sum >> 16);

  // Return the one's complement of sum
  return ( (uint16_t)(~sum)  );
}

/* ******************************************************* */

// from DHCPd
u_int16_t in_cksum(const char *buf, size_t nbytes, u_int32_t sum) {
  u_int16_t i;

  /* Checksum all the pairs of bytes first... */
  for (i = 0; i < (nbytes & ~1U); i += 2) {
    sum += (u_int16_t) ntohs(*((u_int16_t *)(buf + i)));
    /* Add carry. */
    if(sum > 0xFFFF)
      sum -= 0xFFFF;
  }

  /* If there's a single byte left over, checksum it, too.   Network
     byte order is big-endian, so the remaining byte is the high byte. */
  if(i < nbytes) {
    sum += buf [i] << 8;
    /* Add carry. */
    if(sum > 0xFFFF)
      sum -= 0xFFFF;
  }

  return sum;
}

static inline u_int16_t wrapsum(u_int32_t sum) {
  sum = ~sum & 0xFFFF;
  return htons(sum);
}

u_int16_t ip_checksum(const void *buf, size_t hdr_len) {
  return wrapsum(in_cksum(buf, hdr_len, 0));
}

/* ******************************************************* */

// from ntopng
void xor_encdec(char *data, int data_len, char *key) {
  int i, y;

  for(i = 0, y = 0; i < data_len; i++) {
    data[i] ^= key[y++];
    if(key[y] == 0) y = 0;
  }
}
