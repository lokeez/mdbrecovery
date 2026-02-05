#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Port of:
# Copyright 2016-2017 Benjamin 'Benno' Falkner
# MIT License
#
# Python port: for educational / recovery purposes

import sys
import struct

MDB_PAGE_SIZE = 4096

MDB_VER_JET3 = 0
MDB_VER_JET4 = 1
MDB_VER_ACCDB2007 = 0x02
MDB_VER_ACCDB2010 = 0x0103

JET3_XOR = bytes([
    0x86, 0xFB, 0xEC, 0x37, 0x5D, 0x44, 0x9C, 0xFA, 0xC6,
    0x5E, 0x28, 0xE6, 0x13, 0xB6, 0x8A, 0x60, 0x54, 0x94
])

JET4_XOR = [
    0x6ABA, 0x37EC, 0xD561, 0xFA9C, 0xCFFA,
    0xE628, 0x272F, 0x608A, 0x0568, 0x367B,
    0xE3C9, 0xB1DF, 0x654B, 0x4313, 0x3EF3,
    0x33B1, 0xF008, 0x5B79, 0x24AE, 0x2A7C
]


def read_mdb_page(filename: str) -> bytes:
    try:
        with open(filename, "rb") as f:
            data = f.read(MDB_PAGE_SIZE)
            if len(data) != MDB_PAGE_SIZE:
                raise IOError("Could not read full MDB page")
            return data
    except OSError as e:
        print(f"ERROR: could not open/read {filename}: {e}")
        sys.exit(1)


def scan_mdb_page(buf: bytes) -> int:
    # Page ID check
    if buf[0] != 0:
        print("ERROR: no valid database")
        return 1

    # Version (little endian int32 at 0x14)
    version = struct.unpack_from("<I", buf, 0x14)[0]

    if version == MDB_VER_JET3:
        print("DB Version: JET 3")
    elif version == MDB_VER_JET4:
        print("DB Version: JET 4")
    elif version == MDB_VER_ACCDB2007:
        print("DB Version: AccessDB 2007")
        print("Password recovery NOT supported (AES)")
        return 1
    elif version == MDB_VER_ACCDB2010:
        print("DB Version: AccessDB 2010")
        print("Password recovery NOT supported (AES)")
        return 1
    else:
        print(f"ERROR: unknown version: {hex(version)}")
        return 1

    # Password extraction
    if version == MDB_VER_JET3:
        pwd = bytearray(buf[0x42:0x42 + 20])
        for i in range(18):
            pwd[i] ^= JET3_XOR[i]

        password = pwd.rstrip(b"\x00").decode(errors="ignore")
        print(f"Password: {password}")

    elif version == MDB_VER_JET4:
        raw = buf[0x42:0x42 + 40]

        pwd4 = list(struct.unpack("<20H", raw))
        magic = struct.unpack_from("<H", buf, 0x66)[0]
        magic ^= JET4_XOR[18]

        out = bytearray()

        for i in range(18):
            val = pwd4[i] ^ JET4_XOR[i]
            if val > 0xFF:
                val ^= magic
            out.append(val & 0xFF)

        password = out.rstrip(b"\x00").decode(errors="ignore")
        print(f"Password: {password}")

    return 0


def main():
    print("MDB Access Tool (Python)")
    if len(sys.argv) < 2:
        print("Usage: python mdb_pass.py <file.mdb>")
        sys.exit(1)

    filename = sys.argv[1]
    print(f"Reading: {filename}")
    page = read_mdb_page(filename)
    scan_mdb_page(page)


if __name__ == "__main__":
    main()
