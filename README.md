# PacketRelay

A lightweight packet relay server implemented in Rust. It exposes a simple HTTP and WebSocket API that lets a remote client:

- Stream packets sniffed on a server network interface in real time (server -> client).
- Send client‑constructed raw packets to be transmitted on a server’s network interface (client -> server).

This enables bidirectional packet streaming over a single WebSocket connection. Packet capture and injection are powered 
via the pcap Rust crate. Streaming is delivered over WebSockets using Axum.

Note: Client examples are available in the client_examples directory.

## Features

- List available network interfaces on the server.
- Start a WebSocket session tied to a specific interface.
- Server streams captured packets to the client as binary WebSocket frames.
- Client can send binary WebSocket frames that the server transmits on the selected interface.
- Optional capture filter (BPF) provided via a query parameter.

## Build and Run

Requirements:
- Rust (stable)
- libpcap installed on the host
- Appropriate privileges to capture and send packets (root/admin or setcap as appropriate)

Build:
- `cargo build`

Run:
- `cargo run`

The server listens on 0.0.0.0:<PORT> (default 3000). Control logging with RUST_LOG, e.g., RUST_LOG=info.

## Endpoints

- GET /
  - Health check. Returns a simple text response.

- GET /interfaces
  - Returns a JSON array of available interface names. Example response: ["en0", "eth0", "lo0"].

- GET /connections/{iface}
  - Upgrades to a WebSocket connection bound to the specified interface. Optional query parameter filter can be supplied as a libpcap filter expression.
  - Example: ws://server:3000/connections/eth0?filter=tcp port 80

  WebSocket behavior:
  - Server -> Client: Each captured packet is sent as a binary WebSocket frame containing the raw packet bytes.
  - Client -> Server: Any binary WebSocket frame received is treated as a raw packet to transmit on the bound interface.
  - Control frames (e.g., close) are handled; when either side stops, the relay shuts down cleanly.

WebSocket message format:
- Binary frames only; the payload is the raw packet bytes as would be seen on the wire.
- No text protocol is defined; non-binary messages are ignored.

Query parameters:
- filter (optional): A BPF/libpcap filter expression applied to the capture. Examples: "tcp", "port 53", "tcp and port 443".

HTTP Responses / Errors:
- 404 if the requested interface does not exist.
- 500 for internal errors (e.g., capture open failure, invalid filter, etc.).

## Security and Permissions

- Packet capture typically requires elevated privileges. On Linux, consider setcap on the binary (e.g., setcap cap_net_raw,cap_net_admin=eip ./packet-relay). On macOS, run as root or grant appropriate permissions.
- Be careful exposing this service on untrusted networks. There is no authentication or authorization built-in. Consider reverse proxies, firewalling, or adding auth if needed.

## Client Guidance

- Use any WebSocket client capable of sending/receiving binary frames. For packet crafting, tools like Scapy can be used to build raw packets and send as binary payloads.
- See client_examples for reference scripts/snippets.
