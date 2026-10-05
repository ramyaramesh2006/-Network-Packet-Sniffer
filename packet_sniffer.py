#!/usr/bin/env python3
"""
Network Packet Sniffer
----------------------
A small command-line packet sniffer for Linux that reads Ethernet frames
from a raw socket, parses IPv4/TCP/UDP headers, prints summaries, and
writes protocol statistics to a log file.

Run with elevated privileges, for example:
    sudo python3 packet_sniffer.py

Stop with Ctrl+C.
"""

import argparse
import socket
import struct
import time
from collections import Counter


ETH_HEADER_LEN = 14
IP_HEADER_MIN_LEN = 20
ETH_P_IP = 0x0800
IPPROTO_TCP = 6
IPPROTO_UDP = 17


def parse_ipv4_header(data):
    """Return parsed IPv4 header information and header length."""
    if len(data) < IP_HEADER_MIN_LEN:
        return None

    first_byte = data[0]
    version = first_byte >> 4
    ihl = (first_byte & 0x0F) * 4

    if version != 4 or ihl < IP_HEADER_MIN_LEN or len(data) < ihl:
        return None

    total_length, identification, flags_fragment, ttl, protocol, checksum = (
        struct.unpack("!HHHBBH", data[2:12])
    )
    source = socket.inet_ntoa(data[12:16])
    destination = socket.inet_ntoa(data[16:20])

    return {
        "version": version,
        "header_length": ihl,
        "total_length": total_length,
        "identification": identification,
        "ttl": ttl,
        "protocol": protocol,
        "checksum": checksum,
        "source": source,
        "destination": destination,
    }


def parse_transport_header(data, protocol):
    """Parse TCP or UDP ports and return payload length."""
    if protocol == IPPROTO_TCP:
        if len(data) < 20:
            return None

        source_port, destination_port = struct.unpack("!HH", data[:4])
        data_offset = (data[12] >> 4) * 4
        if data_offset < 20 or len(data) < data_offset:
            return None

        payload = data[data_offset:]
        return {
            "protocol": "TCP",
            "source_port": source_port,
            "destination_port": destination_port,
            "payload_length": len(payload),
        }

    if protocol == IPPROTO_UDP:
        if len(data) < 8:
            return None

        source_port, destination_port, udp_length, checksum = struct.unpack(
            "!HHHH", data[:8]
        )
        payload = data[8:]
        return {
            "protocol": "UDP",
            "source_port": source_port,
            "destination_port": destination_port,
            "payload_length": len(payload),
        }

    return None


def payload_preview(packet_payload, limit=24):
    """Return a short hexadecimal payload preview."""
    return packet_payload[:limit].hex(" ") if packet_payload else "-"


def main():
    parser = argparse.ArgumentParser(
        description="IPv4 TCP/UDP command-line packet sniffer"
    )
    parser.add_argument(
        "-i", "--interface",
        help="Interface to listen on (Linux AF_PACKET). Example: eth0 or wlan0"
    )
    parser.add_argument(
        "-l", "--log",
        default="network_log.txt",
        help="Output log file (default: network_log.txt)"
    )
    parser.add_argument(
        "-b", "--buffer",
        type=int,
        default=65535,
        help="Raw socket receive buffer size (default: 65535)"
    )
    args = parser.parse_args()

    protocol_counts = Counter()
    packet_count = 0
    start_time = time.time()

    try:
        # AF_PACKET receives Ethernet frames and is intended for Linux.
        raw_socket = socket.socket(
            socket.AF_PACKET,
            socket.SOCK_RAW,
            socket.ntohs(ETH_P_IP)
        )
        if args.interface:
            raw_socket.bind((args.interface, 0))
    except PermissionError:
        print("Permission denied. Run the script with sudo/root privileges.")
        return 1
    except OSError as exc:
        print(f"Could not create raw packet socket: {exc}")
        print("This version expects a Linux system with AF_PACKET support.")
        return 1

    with open(args.log, "a", encoding="utf-8") as log_file:
        log_file.write("\n=== Packet Sniffer Session ===\n")
        log_file.write(f"Started: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")

        print("Packet sniffer started. Press Ctrl+C to stop.")
        print(f"Logging to: {args.log}")

        try:
            while True:
                raw_data, _ = raw_socket.recvfrom(args.buffer)
                packet_count += 1

                if len(raw_data) < ETH_HEADER_LEN:
                    continue

                ethernet_type = struct.unpack("!H", raw_data[12:14])[0]
                if ethernet_type != ETH_P_IP:
                    continue

                ip_data = raw_data[ETH_HEADER_LEN:]
                ip = parse_ipv4_header(ip_data)
                if not ip:
                    continue

                transport_start = ip["header_length"]
                transport_data = ip_data[transport_start:ip["total_length"]]
                transport = parse_transport_header(
                    transport_data, ip["protocol"]
                )

                protocol_name = {
                    IPPROTO_TCP: "TCP",
                    IPPROTO_UDP: "UDP",
                }.get(ip["protocol"], f"PROTO-{ip['protocol']}")

                protocol_counts[protocol_name] += 1

                timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                if transport:
                    line = (
                        f"{timestamp} | {protocol_name:5} | "
                        f"{ip['source']}:{transport['source_port']} -> "
                        f"{ip['destination']}:{transport['destination_port']} | "
                        f"IP_LEN={ip['total_length']} | "
                        f"PAYLOAD={transport['payload_length']} | "
                        f"PREVIEW={payload_preview(transport_data[
                            20 if protocol_name == 'TCP' else 8:
                        ])}"
                    )
                else:
                    line = (
                        f"{timestamp} | {protocol_name:8} | "
                        f"{ip['source']} -> {ip['destination']} | "
                        f"IP_LEN={ip['total_length']}"
                    )

                print(line)
                log_file.write(line + "\n")
                log_file.flush()

        except KeyboardInterrupt:
            print("\nStopping sniffer...")
        finally:
            elapsed = max(time.time() - start_time, 0.001)
            log_file.write("\n--- Session Statistics ---\n")
            log_file.write(f"Packets observed: {packet_count}\n")
            log_file.write(f"Elapsed seconds: {elapsed:.2f}\n")
            log_file.write(
                f"Average packets/sec: {packet_count / elapsed:.2f}\n"
            )
            for protocol, count in sorted(protocol_counts.items()):
                log_file.write(f"{protocol}: {count}\n")
            log_file.write(
                f"Stopped: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            )

    raw_socket.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
