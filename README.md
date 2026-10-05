# Network Packet Sniffer

A command-line Python packet sniffer for Linux. It uses a raw `AF_PACKET`
socket to inspect IPv4 traffic and parses basic IP, TCP, and UDP headers.

## Files

- `packet_sniffer.py` - complete Python source code
- `sample_network_log.txt` - sample output/log for submission proof
- `README.md` - setup and usage instructions

## Requirements

- Linux/Kali Linux
- Python 3
- Root/sudo privileges
- No third-party Python packages are required

## Run

```bash
cd network_packet_sniffer
sudo python3 packet_sniffer.py
```

Optional interface selection:

```bash
sudo python3 packet_sniffer.py -i eth0
```

Optional custom log file:

```bash
sudo python3 packet_sniffer.py -l my_network_log.txt
```

Press `Ctrl+C` to stop. A session summary is appended to the log.

## What the script demonstrates

1. Creates a Linux raw packet socket.
2. Reads Ethernet frames from the socket.
3. Identifies IPv4 frames.
4. Parses source IP, destination IP, protocol, TTL and packet length.
5. Parses TCP/UDP source and destination ports.
6. Calculates transport payload length.
7. Displays a short hexadecimal payload preview.
8. Writes traffic records and protocol statistics to a text log.

## Important note

Only capture traffic on systems/networks you own or are explicitly authorized
to monitor. The sample log contains synthetic/example values and is included
as submission evidence; it is not presented as a real capture from a third
party network.
