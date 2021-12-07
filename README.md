# Zero Dep Tunnel

Zero Dep Tunnel is a C library to integrate VPN like functionalities on existing
programs without installing third-party software or drivers on the target device.

## Motivation

Tunneling traffic through Windows can be tricky:
  - TUN/TAP interfaces require a specific driver
  - RAW sockets cannot enstablish TCP/UDP connections for security reasons
  - Using libpcap-like functionalities requires installing WinPcap

Existing solutions are complex and not appropriate to be integrated as a library
into an existing program.

## Features

Zero Dep Tunnel offers the following features:

  - Tunnel TCP, UDP and ICMP (echo) connections via a pivot host towards a private network
  - Works on both Windows and Linux
  - Easy integration: just a static library, a header file, and no dependencies
  - No special interface / promisc mode is used, only the sockets API
  - Supports running some nmap scans through the tunnel
  - Supports internet traffic tunneling via a default gateway on the pivot host network

## Naming and Assumptions

Some naming conventions:
  - Client host: the host which is willing to reach the remote private network
  - Pivot host: the host which has direct access to the private network
  - Target host: an host which is located into the private pivot host network

Assumptions:
  - Zero Dep Tunnel requires an enstablished TCP-like connection between the client host
    and the pivot host. It won't work on a UDP connection.
  - The client host is a Linux pc with TUN interface support.

## Sample Integration

Here is how to use the zdtun api to integrate its VPN capabilities into an existing program and turn it into a zdtun pivot:

```c
#include "zdtun.h"

/* This is called when zdtun needs to send data to the client */
int send_pivot_callback(zdtun_t *tun, zdtun_pkt_t *pkt, const zdtun_conn_t *conn_info) {
  int cli_socket = *((int*) zdtun_userdata(tun));

  send(cli_socket, pkt->buf, pkt->len, 0);
}

int main() {
  /* A TCP socket connected to the client */
  socket_t cli_socket = ...;
  zdtun_callbacks_t callbacks = {
    .send_client = send_pivot_callback,
  };
  ...

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

See `zdtun_pivot.c` for a complete example.

NOTE: when running the pivot on linux, it's necessary to mask/handle the *SIGPIPE*
signal, which can occur while sending data.

## Build

Cross platform build is provided by cmake.

Preparation:
  - `mkdir Build`
  - `cd Build`
  - `cmake ..` (or `cmake -G "Visual Studio 15 Win64" ..` for a Windows x64 build)

Build the zdtun library and the sample pivot program:
  - on Linux:

    `make zdtun_pivot`

  - on Windows:

    `MSBuild zdtun_pivot.vcxproj /t:Build /p:Configuration=Release`

    `MSBuild zdtun.vcxproj /t:Build /p:Configuration=Release`

  The output is `Release\zdtun_pivot.exe`.

Build the sample client program (Linux only):
  - `make zdtun_client`

See `zdtun.h` for the zdtun API documentation.

## Run Examples

The client and pivot programs provide an example of zdtun integration and usage.
In this example, the client has a public IP `1.2.3.4` and is willing to reach the
`192.168.30.0/24` network, which is located on the pivot host side.
The pivot host is under NAT, so it will be the initiator of the connection.

On the Linux client host, start the listening program:

  `./zdtun_client -l 5050 192.168.30.0 255.255.255.0`

A new tun interface will be created.

On the Windows pivot host, start the connection to the client host:

  `zdtun_server.exe 1.2.3.4 5050`

The client host should be now able to ping and connect to the `192.168.30.0/24`
network.

NOTE: the sample programs are *not* intended to be used in production as they
are not "secure". They just show how to integrate the zdtun API to
communicate over an existing channel. It's your job to provide and secure such
a channel.

## Run Local Gateway

The `zdtun_gateway` is a program which routes all the local/internet connections
through zdtun via a TUN device. It can be useful to easily test the zdtun
functionalities locally.

## How It Works

The pivot host running Zero Dep Tunnel keeps track of the client connections and opens sockets on demand toward the private network.

When the client initiates a connection, the pivot creates a new socket towards
the target host. It proxies subsequent packets from the client to the target and
viceversa by reconstructing network headers which have been stripped by the sockets.

In order to proxy the TCP packets coming from the target host back to the client
host, the pivot keeps track of the TCP sequence/ack numbers and behaves like a
TCP application. Since Zero Dep Tunnel is running (see Assumptions above) on a
reliable transport, there is no need to implement full TCP protocol, but only a
minimal communication.

## See Also

- zdtun used on Android to capture packets: https://github.com/emanuele-f/PCAPdroid
- RAW sockets for pivoting, no Windows support, no API: https://github.com/0x36/VPNPivot
- https://docs.microsoft.com/en-us/windows/desktop/winsock/maximum-number-of-sockets-supported-2
- http://tangentsoft.net/wskfaq/advanced.html#maxsockets
- Reverse tethering on Android devices, employing a similar tecnique: https://github.com/Genymobile/gnirehtet/blob/master/DEVELOP.md
- Proxy-like implementation for an Android firewall: https://github.com/m66b/NetGuard
