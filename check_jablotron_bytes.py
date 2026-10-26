#!/usr/bin/env python3
import argparse
import binascii
import sys
from typing import List

PACKET_TYPES = {
    0x30: "PACKET_GET_SYSTEM_INFO",
    0x40: "PACKET_SYSTEM_INFO",
    0x51: "PACKET_SECTIONS_STATES",
    0x55: "PACKET_DEVICE_STATE",
    0x90: "PACKET_DEVICE_INFO",
    0xd8: "PACKET_DEVICES_STATES",
    0x50: "PACKET_PG_OUTPUTS_STATES",
    0x52: "PACKET_COMMAND",
    0x80: "PACKET_UI_CONTROL",
    0x3b: "PACKET_DEVICES_SECTIONS",
    0xd0: "PACKET_PG_OUTPUT_EVENT",
    0x94: "PACKET_DIAGNOSTICS",
    0x96: "PACKET_DIAGNOSTICS_COMMAND",
}

COMMANDS = {
    0x0a: "COMMAND_GET_DEVICE_STATUS",
    0x0e: "COMMAND_GET_SECTIONS_AND_PG_OUTPUTS_STATES",
    0x8a: "COMMAND_RESPONSE_DEVICE_STATUS",
}

UI_CONTROLS = {
    0x01: "UI_CONTROL_AUTHORISATION_END",
    0x03: "UI_CONTROL_AUTHORISATION_CODE",
    0x0d: "UI_CONTROL_MODIFY_SECTION",
    0x23: "UI_CONTROL_TOGGLE_PG_OUTPUT",
}



def bytes_to_int(packet: bytes) -> int:
    return int.from_bytes(packet, byteorder=sys.byteorder)


def bytes_to_binary(packet: bytes) -> str:
    dec = bytes_to_int(packet)
    binary_string = bin(dec)[2:]
    return binary_string.zfill(len(packet) * 8)


def binary_to_int(binary: str) -> int:
    return int(binary, 2)


def get_packets_from_packet(packet: bytes) -> List[bytes]:
    packets = []
    start = 0
    while start < len(packet):
        if packet[start:start + 1] == b"\x00":
            break
        length = bytes_to_int(packet[start + 1:start + 2])
        end = start + length + 2
        packets.append(packet[start:end])
        start = end
    return packets


def format_hex(packet: bytes) -> str:
    return binascii.hexlify(packet).decode("utf-8")


def describe_packet(packet: bytes) -> str:
    packet_type = packet[0]
    return PACKET_TYPES.get(packet_type, f"UNKNOWN(0x{packet_type:02x})")


def format_source(source: int) -> str:
    # JA-107K numbering of "Src" in the event log
    if source >= 267:
        return f"User {source - 267}"
    if source > 26:
        return f"Device {source - 26}"
    if source == 26:
        return "Central unit"
    return f"Source {source}"


def parse_pg_output_event(packet: bytes) -> None:
    # d0 = record of the central unit event log (verified against FLEXILOG.TXT of JA-107K)
    print("  Event packet")
    event_code = packet[2]
    group = packet[6] & 0x0f
    source = (int.from_bytes(packet[3:5], "little") & 0x0fff) >> 2
    channel = (packet[5] << 2) | (packet[4] >> 6)
    print(f"    event code: {event_code} (0x{event_code:02x})")
    if 0x33 <= event_code <= 0x52:
        print(f"    PG {event_code - 0x32 + 32 * group} turned on")
    elif 0x53 <= event_code <= 0x72:
        print(f"    PG {event_code - 0x52 + 32 * group} turned off")
    print(f"    source (Src): {source} => {format_source(source)}")
    print(f"    channel (Chnl): {channel}")
    print(f"    group/section: {group + 1}")
    print(f"    remaining bytes (time?): {format_hex(packet[6:])}")


def parse_command(packet: bytes) -> None:
    if len(packet) < 3:
        print("  Command packet too short")
        return
    command = packet[2]
    payload = packet[3:]
    print(f"  Command packet")
    print(f"    command id: 0x{command:02x} ({COMMANDS.get(command, 'unknown')})")
    print(f"    payload: {format_hex(payload)}")


def parse_device_state(packet: bytes) -> None:
    if len(packet) < 6:
        print("  Device state packet too short")
        return
    device_number_binary = bytes_to_binary(packet[4:6])
    device_number = binary_to_int(device_number_binary[2:10])
    print("  Device state packet")
    print(f"    state byte: 0x{packet[3]:02x}")
    print(f"    device number: {device_number}")
    print(f"    raw device bytes: {format_hex(packet[4:6])} => {device_number_binary}")
    print(f"    payload after device id: {format_hex(packet[6:])}")


def parse_device_info(packet: bytes) -> None:
    if len(packet) < 3:
        print("  Device info packet too short")
        return
    device_number = packet[2]
    print("  Device info packet")
    print(f"    device number: {device_number}")
    print(f"    payload: {format_hex(packet[3:])}")


def parse_devices_states(packet: bytes) -> None:
    if len(packet) < 2:
        print("  Devices states packet too short")
        return
    size = packet[1]
    payload = packet[2:2 + size]
    print("  Devices states packet")
    print(f"    size: {size}")
    print(f"    payload: {format_hex(payload)}")
    print(f"    bits: {bytes_to_binary(payload[::-1])}")


def parse_sections_states(packet: bytes) -> None:
    if len(packet) < 2:
        print("  Sections states packet too short")
        return
    size = packet[1]
    payload = packet[2:2 + size]
    print("  Sections states packet")
    print(f"    size: {size}")
    print(f"    payload: {format_hex(payload)}")


def parse_packet(packet: bytes) -> None:
    print(f"Packet: {format_hex(packet)}")
    print(f"  total bytes: {len(packet)}")
    print(f"  type: {describe_packet(packet)}")
    if packet[0] == 0xd0:
        parse_pg_output_event(packet)
    elif packet[0] == 0x52:
        parse_command(packet)
    elif packet[0] == 0x55:
        parse_device_state(packet)
    elif packet[0] == 0x90:
        parse_device_info(packet)
    elif packet[0] == 0xd8:
        parse_devices_states(packet)
    elif packet[0] == 0x51:
        parse_sections_states(packet)
    else:
        print(f"  raw payload: {format_hex(packet[2:])}")
    print()


def main() -> None:
    parser = argparse.ArgumentParser(description="Decode Jablotron packet bytes from hex strings")
    parser.add_argument("hex", nargs="*", help="Hex strings of Jablotron packets")
    parser.add_argument("-f", "--file", help="Read one hex packet per line from a file")
    args = parser.parse_args()

    hex_strings = args.hex or []
    if args.file:
        with open(args.file, "r", encoding="utf-8") as fp:
            for line in fp:
                text = line.strip()
                if text:
                    hex_strings.append(text)

    if not hex_strings:
        parser.print_help()
        return

    for idx, hex_text in enumerate(hex_strings, start=1):
        try:
            packet_bytes = binascii.unhexlify(hex_text)
        except (binascii.Error, ValueError):
            print(f"[{idx}] invalid hex: {hex_text}")
            continue

        packets = get_packets_from_packet(packet_bytes)
        if len(packets) > 1:
            print(f"[{idx}] stream contains {len(packets)} packet(s)")
        for packet in packets:
            parse_packet(packet)


if __name__ == "__main__":
    main()
