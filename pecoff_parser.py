import subprocess
import typing

# create winnt.py from winnt.h
args = [
    "clang2py",
    "--comments",
    "--doc",
    "--show-definition-location",
    "--kind",
    "acdefstu",
    "--includes",
    "--output",
    "winnt.py",
    "--verbose",
    "-w",
    "W",
    '--clang-args="-fms-extensions -fms-compatibility -fdelayed-template-parsing --include=C:/PROGRA~2/WI3CF2~1/10/Include/100183~1.0/shared/minwindef.h"',
    "C:/PROGRA~2/WI3CF2~1/10/Include/100183~1.0/um/winnt.h",
]
completed_process = subprocess.run(args=args)
completed_process.check_returncode()
from winnt import (
    IMAGE_DOS_HEADER,
    IMAGE_NT_HEADERS,
    IMAGE_SECTION_HEADER,
    IMAGE_SYMBOL,
    IMAGE_AUX_SYMBOL,
    IMAGE_SYMBOL_EX,
    IMAGE_AUX_SYMBOL_EX,
    IMAGE_FILE_HEADER,
)

import argparse
import pathlib
import sys
import struct
import io
from collections import namedtuple
from enum import Enum

from pecoff_definitions import *


def get_base_type(symbol_table: IMAGE_SYMBOL):
    complex_type, base_type = (symbol_table.Type).to_bytes(2, byteorder="big")
    return IMAGE_SYM_TYPE(base_type)


def get_complex_type(symbol_table: IMAGE_SYMBOL):
    complex_type, base_type = (symbol_table.Type).to_bytes(2, byteorder="big")
    return IMAGE_SYM_DTYPE(complex_type)


def get_sizeof(structure, attr):
    KEY_INDEX = 0
    VALUE_INDEX = 1
    return next(
        ctypes.sizeof(field[VALUE_INDEX])
        for field in structure._fields_
        if field[KEY_INDEX] == attr
    )


def get_bytes(structure, attr):
    KEY_INDEX = 0
    VALUE_INDEX = 1
    return getattr(structure, attr).to_bytes(
        get_sizeof(structure, attr), byteorder=sys.byteorder
    )


def pretty(val):
    # TODO: replace the __str__ method of the class?
    result = list()
    if isinstance(val, IMAGE_DOS_HEADER):
        result.append(str(get_bytes(val, "e_magic")))
    elif isinstance(val, IMAGE_NT_HEADERS):
        result.append(str(get_bytes(val, "Signature")))
        result.append(str(IMAGE_FILE_MACHINE(val.FileHeader.Machine)))
        result.append(str(IMAGE_FILE_CHARACTERISTICS(val.FileHeader.Characteristics)))
        result.append(str(IMAGE(val.OptionalHeader.Magic)))
        result.append(str(IMAGE_SUBSYSTEM(val.OptionalHeader.Subsystem)))
        result.append(
            str(IMAGE_DLLCHARACTERISTICS(val.OptionalHeader.DllCharacteristics))
        )
    elif isinstance(val, IMAGE_SECTION_HEADER):
        result.append(str(IMAGE_SCN(val.Characteristics)))
    elif isinstance(val, IMAGE_SYMBOL):
        result.append(get_base_type(val))
        result.append(get_complex_type(val))

    return result


def get_section_headers(
    input, image_file_header: IMAGE_FILE_HEADER
) -> List[IMAGE_SECTION_HEADER]:
    section_headers = list()
    for sectionHeaderNo in range(0, image_file_header.NumberOfSections):
        section_header = IMAGE_SECTION_HEADER()
        input.readinto(section_header)

        print(pretty(section_header))

        section_headers.append(section_header)
    return section_headers


def get_symbols(input, image_file_header: IMAGE_FILE_HEADER):
    input.seek(image_file_header.PointerToSymbolTable)
    symbols = list()
    for symbolNo in range(0, image_file_header.NumberOfSymbols):
        # TODO: if /bigobj, use _EX versions
        image_symbol = IMAGE_SYMBOL()
        input.readinto(image_symbol)

        print(pretty(image_symbol))

        # TODO: not everyone has aux symbol (@comp.id and @feat.00 seems to be special?)
        image_aux_symbol = IMAGE_AUX_SYMBOL()
        input.readinto(image_aux_symbol)

        print(pretty(image_aux_symbol))

        symbols.append((image_symbol, image_aux_symbol))
    return symbols


def get_section_content(input, section_header: IMAGE_SECTION_HEADER):
    # TODO: read and understand https://stackoverflow.com/questions/45212489/image-section-headers-virtualaddress-and-pointertorawdata-difference
    input.seek(section_header.PointerToRawData)
    # TODO: find out what type it is
    return io.BytesIO(input.read(section_header.SizeOfRawData))


def parse_buffer(input):
    """
    https://docs.microsoft.com/en-us/windows/desktop/Debug/pe-format
    https://en.wikibooks.org/wiki/X86_Disassembly/Windows_Executable_Files    
    http://www.pinvoke.net/default.aspx/Structures.IMAGE_DOS_HEADER
    """
    input.seek(io.SEEK_SET)
    if input.peek(getattr(IMAGE_DOS_HEADER, "e_magic")) == b"MZ":
        # vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv
        # order of statements important
        # vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv
        ms_dos_stub = IMAGE_DOS_HEADER()
        input.readinto(ms_dos_stub)

        print(pretty(ms_dos_stub))

        input.seek(ms_dos_stub.e_lfanew)
        image_nt_headers = IMAGE_NT_HEADERS()
        input.readinto(image_nt_headers)
        assert get_bytes(image_nt_headers, "Signature") == b"PE\x00\x00"

        print(pretty(image_nt_headers))

        section_headers = get_section_headers(input, image_nt_headers.FileHeader)

        section_contents = list()
        for section_header in section_headers:
            section_contents.append(get_section_content(input, section_header))

        symbols = get_symbols(input, image_nt_headers.FileHeader)
    else:
        image_file_header = IMAGE_FILE_HEADER()
        input.readinto(image_file_header)

        print(pretty(image_file_header))

        section_headers = get_section_headers(input, image_file_header)
        symbols = get_symbols(input, image_file_header)
        section_contents = list()
        for section_header in section_headers:
            section_contents.append(get_section_content(input, section_headers))

    # TODO: rest of format
    pass


def parse_input(input):
    if isinstance(input, pathlib.PurePath):
        with input.open("rb") as fp:
            parse_buffer(fp)
    elif isinstance(input, bytes):
        parse_buffer(io.BytesIO(input))


def run(pargs):
    parse_input(pathlib.Path(pargs.file))
    pass


def parse_args(*args):
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    required = parser.add_argument_group("required arguments")
    required.add_argument("--file", help="pe coff file (.exe)", required=True)

    pargs = parser.parse_args(args)
    return pargs


if __name__ == "__main__":
    pargs = parse_args(*sys.argv[1:])
    run(pargs)
