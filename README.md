# zdtun

zdtun (short for "Zero Dependency Tunnel") is a C library which provides an API to integrate VPN like functionalities on existing programs without installing third-party software or drivers on the target device.

This library is used in [PCAPdroid](https://github.com/emanuele-f/PCAPdroid) to capture network packets on Android without root.

The library implements parts of a TCP/IP stack, for example the tracking of sessions and handling of TCP sequence numbers and window size.
However, zdtun *does not* implement any TCP retransmission logic, as this feature is already provided by the TCP sockets used internally.

## Features

zdtun offers the following features:

  - Simple API to integrate into existing programs
  - Supports Windows, Linux and Android
  - Support UDP, TCP, ICMP and IPv4/IPv6
  - Just one header file, no additional dependencies
  - No special interface / promisc mode is used, only standard sockets
  - Generic API to parse TCP/IP packets into a `zdtun_pkt`

## Sample Integration

Here is how to use the zdtun api to integrate its VPN capabilities into an existing program:

```c
#include "zdtun.h"

/* This is called when zdtun needs to send data to the client */
int send_client_callback(zdtun_t *tun, zdtun_pkt_t *pkt, const zdtun_conn_t *conn_info) {
  int cli_socket = *((int*) zdtun_userdata(tun));

  send(cli_socket, pkt->buf, pkt->len, 0);
}

int main() {
  /* A TCP socket connected to the client */
  socket_t cli_socket = ...;
  zdtun_callbacks_t callbacks = {
    .send_client = send_client_callback,
  };
  ...

  // ignore SIGPIPE, which can occur while sending data
  signal(SIGPIPE, SIG_IGN);

  zdtun_t *tun = zdtun_init(&callbacks, &cli_socket);

  while(1) {
    int max_fd = 0;
    fd_set fdset;
    fd_set wrfds;
  
    /* get zdtun own fds */
    zdtun_fds(tun, &max_fd, &fdset, &wrfds);

    /* Add client fd to the readable fds */
    FD_SET(cli_socket, &fdset);
    max_fd = max(max_fd, cli_socket);

    /* Wait for socket events */
    select(max_fd + 1, &fdset, &wrfds, NULL, NULL);

    if(FD_ISSET(cli_socket, &fdset)) {
      /* Got data from the client, forward it to the private network */
      size = recv(cli_socket, buffer, sizeof(buffer), 0);
      zdtun_easy_forward(tun, buffer, size);
    } else {
      /* let zdtun handle it */
      zdtun_handle_fd(tun, &fdset, &wrfds);
    }
  }

  zdtun_finalize(tun);
}
```

See `zdtun_gateway.c` for a complete example.

## Run Local Gateway

The `zdtun_gateway` is a program which routes all the local/internet connections
through zdtun via a TUN device. It can be useful to easily test the zdtun
functionalities locally.


## Motivation

The library was initially developed for Windows, as a way to provide VPN-like feature into an existing program, and later extended for the linux/Android world.

Tunneling traffic through Windows can be tricky:
  - TUN/TAP interfaces require a specific driver
  - RAW sockets cannot enstablish TCP/UDP connections for security reasons
  - Using libpcap-like functionalities requires installing WinPcap

Existing solutions are complex and not appropriate to be integrated as a library
into an existing program.

## See Also

- zdtun used on Android to capture packets: https://github.com/emanuele-f/PCAPdroid
- Reverse tethering on Android devices, employing a similar tecnique: https://github.com/Genymobile/gnirehtet/blob/master/DEVELOP.md
- Android firewall app, employing a similar tecnique: https://github.com/m66b/NetGuard
- RAW sockets for pivoting, no Windows support, no API: https://github.com/0x36/VPNPivot
- https://docs.microsoft.com/en-us/windows/desktop/winsock/maximum-number-of-sockets-supported-2
- http://tangentsoft.net/wskfaq/advanced.html#maxsockets
