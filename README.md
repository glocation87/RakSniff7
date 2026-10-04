# RakSniff7

A command-line packet sniffer for SA-MP and open.mp servers. It sits passively on the wire (or reads a pcap file), decrypts the SA-MP obfuscation layer, tears apart the RakNet 2.52 reliability framing, and prints every RPC and sync packet by name as it flies past.

Built in C. No GUI, no dependencies beyond libpcap/Npcap.

## What it does

- Captures live UDP traffic or reads `.pcap` files
- Strips Ethernet/IP/UDP headers
- Detects and labels SA-MP query packets (`SAMP` protocol)
- Decrypts client-to-server traffic (XOR + substitution table)
- Handles open.mp's optional encryption (4-byte XOR key exchange)
- Parses RakNet offline handshake (open connection, cookie, auth key, etc.)
- Parses the RakNet 2.52 reliability layer (bit-packed frames, compressed fields)
- Reassembles split packets
- Deduplicates retransmissions
- Identifies RPCs by ID and names them (PlayerConnect, ShowDialog, etc.)
- Identifies sync packets (PlayerSync, VehicleSync, AimSync, etc.)

Output is one line per decoded message, color-coded, streamed to stdout in real time.

## Building

You need CMake and a C compiler. On Windows you also need the [Npcap SDK](https://npcap.com/#download) and Npcap installed.

```
cmake -B build -DNPCAP_SDK_DIR=C:/path/to/npcap-sdk
cmake --build build
```

On Linux:
```
sudo apt install libpcap-dev
cmake -B build
cmake --build build
```

## Usage

Read a capture file:
```
omp_packet_viewer -f session.pcap
```

Live capture (needs admin/root):
```
omp_packet_viewer -i eth0 -p 7777
```

Hide the sync spam (they're like 95% of the traffic):
```
omp_packet_viewer -f session.pcap --hide-sync
```

Only watch specific RPCs:
```
omp_packet_viewer -i eth0 --rpc 25,93,86 --hex
```

Filter to one client:
```
omp_packet_viewer -f session.pcap --client 192.168.1.50
```

All options:
```
  -f <file>       pcap file to read
  -i <iface>      network interface for live capture
  -p <port>       server port (default 7777)
  --hide-sync     hide PlayerSync/VehicleSync/etc
  --hex           show hex dump of payloads
  --rpc <ids>     comma-separated RPC IDs to show
  --client <ip>   only this client's traffic
  --no-color      plain output, no ANSI colors
```

## Notes

- The 256-byte substitution table in `src/decrypt.c` needs to match the one in `SAMPRakNet.cpp` from the open.mp source. The current one is a placeholder.
- Only sniff traffic on servers you own or have permission to inspect.
- Live capture requires elevated privileges (Administrator on Windows, root on Linux).
- Get test data by recording a session with Wireshark or `tcpdump -i any udp port 7777 -w session.pcap`, then work against that file first.
