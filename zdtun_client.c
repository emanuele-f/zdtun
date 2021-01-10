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

#include <netinet/ip.h>
#include <arpa/inet.h>

#include <sys/select.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#include <netinet/udp.h>
#include <netinet/tcp.h>

#include <linux/if.h>
#include <linux/if_tun.h>

#include "zdtun.h"
#include "utils.h"

//#define ENABLE_LOCAL_TEST

#define TUN1_DEV "tun10"

#ifdef ENABLE_LOCAL_TEST
#define TUN1_IP "10.30.10.1" // NOTE: ping 10.30.10.2
#define TUN2_DEV "tun32"
#define TUN2_IP "10.30.11.2"
#define NETMASK "255.255.255.0"
#endif

#define TUN_MTU 1500
#define PACKET_BUFSIZE 65535

/* ******************************************************* */

int tun1_fd, tun2_fd;

socket_t server_sock = 0;
u_int32_t tun_ip_addr = 0;

/* ******************************************************* */

static int open_tun(const char *tun_dev, const char*ip, const char *netmask) {
  struct ifreq ifr;
  char cmd_buf[255];
  int tun_fd;

  tun_fd = open("/dev/net/tun", O_RDWR);

  if(tun_fd < 0)
    fatal("Cannot open TUN device[%d]: %s", errno, strerror(errno));

  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
  strncpy(ifr.ifr_name, tun_dev, IFNAMSIZ);

  int rc = ioctl(tun_fd, TUNSETIFF, (void *)&ifr);

  if(rc < 0)
    fatal("ioctl failed[%d]: %s", rc, strerror(errno));

  // set IPv4 address
  snprintf(cmd_buf, sizeof(cmd_buf), "/sbin/ip addr add %s/%s dev %s", ip, netmask, tun_dev);
  debug("CMD: %s", cmd_buf);
  system(cmd_buf);

  // bring device upaddr add dev %s %s/ netmask %s mtu %d up
  snprintf(cmd_buf, sizeof(cmd_buf), "/sbin/ip link set dev %s mtu %d up", tun_dev, TUN_MTU);
  debug("CMD: %s", cmd_buf);
  system(cmd_buf);

  return tun_fd;
}

/* ******************************************************* */

static void send_server(char *pkt_buf, u_int32_t pkt_size) {
  struct iphdr *ip_header = (struct iphdr*) pkt_buf;

  if(ip_header->version != 4) {
    debug("Ignoring non IPv4 packet: %d", ip_header->version);
    return;
  }

  if(ip_header->saddr != tun_ip_addr) {
    char buf[INET_ADDRSTRLEN];
    debug("Refusing to route packet from %s", ipv4str(ip_header->saddr, buf));
    return;
  }

  switch(ip_header->protocol) {
    case IPPROTO_TCP:
      break;
    case IPPROTO_UDP:
      break;
    case IPPROTO_ICMP:
      break;
    default:
      debug("Ignoring unhandled IP protocol %d", ip_header->protocol);
      return;
  }

#ifdef ENABLE_LOCAL_TEST
  /* Conversion for test: 10.30.10.2 -> 10.30.11.2 */
  ip_header->daddr = htonl((ntohl(ip_header->daddr) | 0x100));
#endif

  con_send(server_sock, pkt_buf, pkt_size);
}

/* ******************************************************* */

static void recv_server(char *buffer) {
  u_int32_t size = con_recv(server_sock, buffer, PACKET_BUFSIZE);

  if(!size)
    exit(1);

  debug("Got %u bytes from the server", size);

#ifdef ENABLE_LOCAL_TEST
  struct iphdr *ip_header = (struct iphdr*) buffer;

  /* Conversion for test: 10.30.11.2 -> 10.30.10.2 */
  ip_header->saddr = htonl((ntohl(ip_header->saddr) & (~0x100)));

  // Fix the checsums
  if(ip_header->protocol == IPPROTO_TCP) {
    struct tcphdr *tcp_header = (struct tcphdr *) &buffer[20];
    tcp_header->check = 0;
    tcp_header->check = tcp_checksum(tcp_header, ntohs(ip_header->tot_len) - ZDTUN_IP_HEADER_SIZE, ip_header->saddr, ip_header->daddr);
  } else if(ip_header->protocol == IPPROTO_UDP) {
    // remove the checsum for now
    struct udphdr *udp_header = (struct udphdr *) &buffer[20];
    udp_header->check = 0;
  }

  ip_header->check = 0;
  ip_header->check = ip_checksum(buffer, ZDTUN_IP_HEADER_SIZE);
#endif

  write(tun1_fd, buffer, size);
}

/* ******************************************************* */

int main(int argc, char **argv) {
  char *pkt_buf;
  int max_fd = 0;

#ifndef ENABLE_LOCAL_TEST
  if(argc != 5)
    fatal("Usage: %s [-l port|ip port] tun_ip tun_netmask", argv[0]);
#else
  if(argc != 3)
    fatal("Usage: %s [-l port|ip port]", argv[0]);
#endif

  con_mode_info info;
  con_parse_args(argv, &info);

#ifndef ENABLE_LOCAL_TEST
  const char *tun_ip = argv[3];
  const char *tun_netmask = argv[4];
#else
  const char *tun_ip = TUN1_IP;
  const char *tun_netmask = NETMASK;
#endif

  pkt_buf = (char *) malloc(PACKET_BUFSIZE);

  if(!pkt_buf)
    fatal("Cannot allocate packet buffer");

  tun1_fd = open_tun(TUN1_DEV, tun_ip, tun_netmask);

  struct sockaddr_in tun_addr;
  inet_pton(AF_INET, tun_ip, &(tun_addr.sin_addr));
  tun_ip_addr = tun_addr.sin_addr.s_addr;

#ifdef ENABLE_LOCAL_TEST
  tun2_fd = open_tun(TUN2_DEV, TUN2_IP, NETMASK);
#endif

  while(1) {
    struct sockaddr_in server_addr;
    server_sock = con_wait_connection(&info, &server_addr);

    char buf1[INET_ADDRSTRLEN];
    log("Server connection: %s", ipv4str(server_addr.sin_addr.s_addr, buf1));

    while(1) {
      fd_set fdset;
      FD_ZERO(&fdset);

      FD_SET(tun1_fd, &fdset);
      FD_SET(server_sock, &fdset);
      max_fd = max(max_fd, tun1_fd);
      max_fd = max(max_fd, server_sock);

      struct timeval tv = {0};
      tv.tv_sec = 1;

      int ret = select(max_fd + 1, &fdset, NULL, NULL, &tv);

      if(ret < 0) {
        fatal("Select error[%d]: %s\n", ret, strerror(errno));
      } else if (ret > 0) {

        if(FD_ISSET(tun1_fd, &fdset)) {
          ssize_t pkt_size = read(tun1_fd, pkt_buf, PACKET_BUFSIZE);

          if(pkt_size < 0) {
            fatal("Error reading packet[%d]: %s", (int)pkt_size, strerror(errno));
          } else if(pkt_size < sizeof(struct iphdr)) {
            error("Packet too small: %lu < %lu", sizeof(struct iphdr), pkt_size);
          } else
            send_server(pkt_buf, pkt_size);
        } else if(FD_ISSET(server_sock, &fdset))
          recv_server(pkt_buf);
      }
    }

    // no more requests supported
    break;
  }
}
