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

## Naming an Assumptions

Some naming conventions:
  - Client host: the host which is willing to reach the remote private network
  - Pivot host: the host which has direct access to the private network
  - Target host: an host which is located into the private pivot host network

Assumptions:
  - Zero Dep Tunnel requires an enstablished TCP-like connection between the client host
    and the pivot host. It won't work on a UDP connection.
  - The client host is a Linux pc with TUN interface support.
  - Only one client IP address at a time is using the pivot connection.

The last assumption implies that, if you want to route multiple devices via a single
pivot host connection, you will need to masquerade the client IPs with the client
IP.

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

## How It Works

The pivot host running Zero Dep Tunnel keeps track of the client connections in
a similar way as a NAT device would do.

When the client initiates a connection, the pivot creates a new socket towards
the target host. It proxies subsequent packets from the client to the target and
viceversa by reconstructing network headers which have been stripped by the sockets.

In order to proxy the TCP packets coming from the target host back to the client
host, the pivot keeps track of the TCP sequence/ack numbers and behaves like a
TCP application. Since Zero Dep Tunnel is running (see Assumptions above) on a
reliable transport, there is no need to implement full TCP protocol, but only a
minimal communication.

## See Also

- RAW sockets for pivoting, no Windows support, no API: https://github.com/0x36/VPNPivot

## TODO
  - Solve the error in gateway mode: "Packet too small for TCP" and "Packet too big!"
  - Add maximum number of connections and purge by sorting by timestamp
