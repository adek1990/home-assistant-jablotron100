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

SOURCE_NAMES = {
    0x3e: "F-Link/Server",
    0x0f: "physical keypad",
}

PG_EVENT_TYPES = {
    0x3c: "PG_OUTPUT_EVENT_USER_ACTIVATION",
    0x3d: "PG_OUTPUT_EVENT_USER_DEACTIVATION",
    0x3e: "PG_OUTPUT_EVENT_ACTIVATED",
    0x3f: "PG_OUTPUT_EVENT_DEACTIVATED",
}

KNOWN_PG_OUTPUT_EVENT_PACKETS = {
    "d008332c043ed024096a": 1,
    "d008342c043e8026696c": 2,
    "d008352c04fe8027a9ec": 3,
    "d008362c04fe702809ed": 4,
    "d008372c04fe002929ed": 5,
    "d008382c043e9029496d": 6,
    "d008392c04fe102a69ed": 7,
    "d0083a2c043e902a896d": 8,
    "d0083b2c043e402bc96d": 9,
    "d0083c2c043e202c096e": 10,
    "d0083d2c043e802c496e": 11,
    "d0083d2c04fe30be08f6": 11,
    "d0083e2c04fec02e09f0": 12,
    "d0083e2c04fed0be28f6": 12,
    "d0083f2c04fe70c0a8f6": 13,
    "d008402c04fe30c1e8f6": 14,
    "d008412c04fe80c108f7": 15,
    "d008422c04fee0c128f7": 16,
    "d008432c04fe40c248f7": 17,
    "d008442c04fe10c5a8f8": 18,
    "d008452c04fe20c6e8f8": 19,
    "d008472c04fec0c628f9": 21,
    "d008482c04fe50c748f9": 22,
    "d008492c04fe90c768f9": 23,
    "d0084a2c04fe80c948fa": 24,
    "d0084b2c04fe70cae8fa": 25,
    "d0084c2c04fe30cb28fb": 26,
    "d0084d2c04fe90cb48fb": 27,
    "d0084e2c04fe20cc68fb": 28,
    "d0084f2c04fea0ccc8fb": 29,
    "d008502c04fe40cde8fb": 30,
    "d008352c043e11cf48fd": 35,
    "d008362c043e81cf88fd": 36,
    "d008372c043e31d0c8fd": 37,
    "d0083b2c04fe81d128fe": 41,
    "d0083c2c04fe91d2a8fe": 42,
    "d0083d2c04fe41d408ff": 43,
    "d0083e2c04fef1d548ff": 44,
    "d0083f2c04fea1d668ff": 45,
    "d008402c04fe21d7a8ff": 46,
    "d008412c04fe61d8c8ff": 47,
    "d008422c04fee1d8e8ff": 48,
    "d008432c04fe71d908c0": 49,
    "d008442c04fee1d928c0": 50,
    "d008452c04fe51da48c0": 51,
    "d008462c04fed1da68c0": 52,
    "d008472c04fed1dce8c0": 53,
    "d0084e2c04fe81dd08c1": 60,
    "d0084f2c04fee1dd28c1": 61,
    "d008502c04fe71de48c1": 62,
    "d008512c04fef1de68c1": 63,
    "d008382c04fe22e3c8c1": 70,
    "d008392c04fec2e4e8c1": 71,
    "d0083a2c04fe42e508c2": 72,
    "d008422c04fe92e7c8c2": 80,
    "d008432c04fe62e8e8c2": 81,
    "d008442c04fec2e808c3": 82,
    "d008452c04fe52e928c3": 83,
    "d0084c2c04fe12ea68c3": 90,
    "d0084d2c04fe82ea88c3": 91,
    "d0084e2c04fee2eaa8c3": 92,
    "d0084f2c04fe92ebc8c3": 93,
    "d008362c04fe93ece8c3": 100,
    "d008372c04fe53ed68c4": 101,
    "d008382c04fee3ed88c4": 102,
    "d008392c04fe53eea8c4": 103,
    "d008402c04fef3eec8c4": 110,
    "d008412c04fe83efe8c4": 111,
    "d008422c04feb30049c5": 112,
    "d0084a2c04fe630189c5": 120,
    "d0084b2c04fee301a9c5": 121,
    "d0084c2c04fe5302c9c5": 122,
    "d0084d2c04fed302e9c5": 123,
    "d0084e2c04fe130309c6": 124,
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


def format_user_number(raw_value: int) -> str:
    candidates = []
    for offset in (44, 104):
        if raw_value >= offset and (raw_value - offset) % 4 == 0:
            candidates.append((offset, (raw_value - offset) // 4))

    if len(candidates) == 1:
        offset, user_no = candidates[0]
        return f"User {user_no} (offset {offset})"
    if len(candidates) > 1:
        preferred = next((c for c in candidates if c[0] == 44), candidates[0])
        alternate = [c for c in candidates if c != preferred]
        offset, user_no = preferred
        if alternate:
            alt_text = ", ".join(f"User {user_no} (offset {offset})" for offset, user_no in alternate)
            return f"User {user_no} (offset {offset}; alt {alt_text})"
        return f"User {user_no} (offset {offset})"
    return f"raw {raw_value}"


def is_pg_activation_packet(packet: bytes) -> bool:
    if len(packet) < 6:
        return False
    if packet[4] != 0x04:
        return False
    source_masked = packet[5] & 0x3f
    return source_masked in (0x3e, 0x0f) and 0x33 <= packet[2] <= 0x52


def parse_pg_output_event(packet: bytes) -> None:
    print("  PG output event packet")
    packet_hex = format_hex(packet)
    print(f"    raw bytes: {packet_hex}")
    print(f"    packet length byte: {packet[1]}")
    event_code = packet[2]
    print(f"    event code: 0x{event_code:02x} ({PG_EVENT_TYPES.get(event_code, 'unknown')})")

    user_raw = packet[3]
    print(f"    raw device/user id: {user_raw} (0x{user_raw:02x})")
    print(f"    decoded user: {format_user_number(user_raw)}")

    print(f"    flag byte #1: 0x{packet[4]:02x}")
    source_raw = packet[5]
    source_masked = source_raw & 0x3f
    source_name = SOURCE_NAMES.get(source_masked, 'unknown')
    extra_flags = []
    if source_raw & 0x80:
        extra_flags.append('0x80')

    known_pg = KNOWN_PG_OUTPUT_EVENT_PACKETS.get(packet_hex)
    if known_pg is not None:
        print(f"    known PG output number: {known_pg}")
    elif is_pg_activation_packet(packet):
        pg_number = event_code - 0x32
        print(f"    inferred PG output number: {pg_number}")
    elif 0x33 <= event_code <= 0x52:
        print("    PG output number: unknown for this event subtype")
    else:
        print("    PG output number: not derivable from this packet")

    print(f"    source byte: 0x{source_raw:02x} (masked 0x{source_masked:02x}) => {source_name}{' [' + ', '.join(extra_flags) + ']' if extra_flags else ''}")
    print(f"    data bytes: {format_hex(packet[6:-1])}")
    print(f"    checksum: 0x{packet[-1]:02x}")


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
