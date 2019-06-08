import subprocess
from typing import *

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
    IMAGE_NT_HEADERS32,
    IMAGE_NT_HEADERS64,
    IMAGE_OPTIONAL_HEADER,
    IMAGE_OPTIONAL_HEADER32,
    IMAGE_OPTIONAL_HEADER64,
    IMAGE_FILE_HEADER,
    IMAGE_SECTION_HEADER,
    IMAGE_SYMBOL,
    IMAGE_AUX_SYMBOL,
    IMAGE_SYMBOL_EX,
    IMAGE_AUX_SYMBOL_EX,
)

import argparse
import pathlib
import sys
import struct
import io
from collections import namedtuple
from enum import Enum, auto

from pecoff_definitions import *


def get_base_type(symbol_table: IMAGE_SYMBOL) -> IMAGE_SYM_TYPE:
    complex_type, base_type = (symbol_table.Type).to_bytes(2, byteorder="big")
    return IMAGE_SYM_TYPE(base_type)


def get_complex_type(symbol_table: IMAGE_SYMBOL) -> IMAGE_SYM_DTYPE:
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
    elif isinstance(val, (IMAGE_NT_HEADERS32, IMAGE_NT_HEADERS64)):
        result.append(str(get_bytes(val, "Signature")))
        result.extend(pretty(val.FileHeader))
        result.extend(pretty(val.OptionalHeader))
    elif isinstance(val, (IMAGE_OPTIONAL_HEADER32, IMAGE_OPTIONAL_HEADER64)):
        result.append(str(IMAGE(val.Magic)))
        result.append(str(IMAGE_SUBSYSTEM(val.Subsystem)))
        result.append(str(IMAGE_DLLCHARACTERISTICS(val.DllCharacteristics)))
    elif isinstance(val, IMAGE_FILE_HEADER):
        result.append(str(IMAGE_FILE_MACHINE(val.Machine)))
        result.append(str(IMAGE_FILE_CHARACTERISTICS(val.Characteristics)))
    elif isinstance(val, IMAGE_SECTION_HEADER):
        result.append(str(IMAGE_SCN(val.Characteristics)))
    elif isinstance(val, IMAGE_SYMBOL):
        result.append(str(IMAGE_SYM_CLASS(val.StorageClass)))
        result.append(get_base_type(val))
        result.append(get_complex_type(val))

    return result


class AuxiliarySymbolType(IntFlag):
    FUNCTION_DEFINITION = auto()
    BEGIN_FUNCTION = auto()
    LINES_IN_FUNCTION = auto()
    END_OF_FUNCTION = auto()
    WEAK_EXTERNAL = auto()
    FILE = auto()
    SECTION_DEFINITIONS = auto()


def get_auxiliary_symbol_type(symbol: IMAGE_SYMBOL, aux_symbol: IMAGE_AUX_SYMBOL):
    if (
        symbol.StorageClass == IMAGE_SYM_CLASS.IMAGE_SYM_CLASS_EXTERNAL
        and symbol.Type == (IMAGE_SYM_DTYPE.IMAGE_SYM_DTYPE_FUNCTION << N_BTSHFT)
        and not (
            symbol.SectionNumber
            in (
                IMAGE_SYM.IMAGE_SYM_UNDEFINED,
                IMAGE_SYM.IMAGE_SYM_ABSOLUTE,
                IMAGE_SYM.IMAGE_SYM_DEBUG,
            )
        )
    ):
        """
        Offset	Size	Field	Description
        0	4	TagIndex	The symbol-table index of the corresponding .bf (begin function) symbol record.
        4	4	TotalSize	The size of the executable code for the function itself. If the function is in its own section, the SizeOfRawData in the section header is greater or equal to this field, depending on alignment considerations.
        8	4	PointerToLinenumber	The file offset of the first COFF line-number entry for the function, or zero if none exists. For more information, see COFF Line Numbers (Deprecated).
        12	4	PointerToNextFunction	The symbol-table index of the record for the next function. If the function is the last in the symbol table, this field is set to zero.
        16	2	Unused	
        """
        return AuxiliarySymbolType.FUNCTION_DEFINITION
    elif symbol.StorageClass == IMAGE_SYM_CLASS.IMAGE_SYM_CLASS_FUNCTION:
        """
        Offset	Size	Field	Description
        0	4	Unused	
        4	2	Linenumber	The actual ordinal line number (1, 2, 3, and so on) within the source file, corresponding to the .bf or .ef record.
        6	6	Unused	
        12	4	PointerToNextFunction ( .bf only)	The symbol-table index of the next .bf symbol record. If the function is the last in the symbol table, this field is set to zero. It is not used for .ef records.
        16	2	Unused	
        """
        if symbol.Name.startswith(b".bf"):
            return AuxiliarySymbolType.BEGIN_FUNCTION
        elif symbol.Name.startswith(b".lf"):
            return AuxiliarySymbolType.LINES_IN_FUNCTION
        elif symbol.Name.startswith(b".ef"):
            return AuxiliarySymbolType.END_OF_FUNCTION
    elif (
        symbol.StorageClass == IMAGE_SYM_CLASS.IMAGE_SYM_CLASS_EXTERNAL
        and symbol.SectionNumber == IMAGE_SYM.IMAGE_SYM_UNDEFINED
        and symbol.Value == 0
    ):
        """
        Offset	Size	Field	Description
        0	4	TagIndex	The symbol-table index of sym2, the symbol to be linked if sym1 is not found.
        4	4	Characteristics	"A value of IMAGE_WEAK_EXTERN_SEARCH_NOLIBRARY indicates that no library search for sym1 should be performed. 
        A value of IMAGE_WEAK_EXTERN_SEARCH_LIBRARY indicates that a library search for sym1 should be performed. 
        A value of IMAGE_WEAK_EXTERN_SEARCH_ALIAS indicates that sym1 is an alias for sym2."
        8	10	Unused	

        Note that the Characteristics field is not defined in WINNT.H; instead, the Total Size field is used.
        """
        return AuxiliarySymbolType.WEAK_EXTERNAL
    elif symbol.StorageClass == IMAGE_SYM_CLASS.IMAGE_SYM_CLASS_FILE:
        """
        Offset	Size	Field	Description
        0	18	File Name	An ANSI string that gives the name of the source file. This is padded with nulls if it is less than the maximum length.
        """
        return AuxiliarySymbolType.FILE
    elif symbol.StorageClass == IMAGE_SYM_CLASS.IMAGE_SYM_CLASS_STATIC:
        """
        NOTE: The symbol.Name names the described section

        Offset	Size	Field	Description
        0	4	Length	The size of section data; the same as SizeOfRawData in the section header.
        4	2	NumberOfRelocations	The number of relocation entries for the section.
        6	2	NumberOfLinenumbers	The number of line-number entries for the section.
        8	4	CheckSum	The checksum for communal data. It is applicable if the IMAGE_SCN_LNK_COMDAT flag is set in the section header. For more information, see COMDAT Sections (Object Only).
        12	2	Number	One-based index into the section table for the associated section. This is used when the COMDAT selection setting is 5.
        14	1	Selection	The COMDAT selection number. This is applicable if the section is a COMDAT section.
        15	3	Unused	
        """
        return AuxiliarySymbolType.SECTION_DEFINITIONS


def seek_get_symbols(
    input, image_file_header: IMAGE_FILE_HEADER
) -> List[
    Union[
        Tuple[IMAGE_SYMBOL, IMAGE_AUX_SYMBOL],
        Tuple[IMAGE_SYMBOL_EX, IMAGE_AUX_SYMBOL_EX],
    ]
]:
    input.seek(image_file_header.PointerToSymbolTable)
    symbols = list()
    for symbolNo in range(0, image_file_header.NumberOfSymbols):
        # TODO: if /bigobj, use _EX versions
        image_symbol = IMAGE_SYMBOL()
        input.readinto(image_symbol)

        print(pretty(image_symbol))

        # TODO: not everyone has aux symbol (@comp.id and @feat.00 seems to be special?)
        image_aux_symbols = list()
        for auxSymbolNo in range(0, image_symbol.NumberOfAuxSymbols):
            image_aux_symbol = IMAGE_AUX_SYMBOL()
            input.readinto(image_aux_symbol)
            print(pretty(image_aux_symbol))

            # TODO: indicate what type it is somehow

            image_aux_symbols.append(image_aux_symbol)

        symbols.append((image_symbol, image_aux_symbols))
    return symbols


def seek_get_section_content(input, section_header: IMAGE_SECTION_HEADER):
    # TODO: read and understand https://stackoverflow.com/questions/45212489/image-section-headers-virtualaddress-and-pointertorawdata-difference
    input.seek(section_header.PointerToRawData)
    # TODO: find out what type it is
    return io.BytesIO(input.read(section_header.SizeOfRawData))


def rva_to_file_offset(relative_virtual_address: int, sections: List[IMAGE_NT_HEADERS]):
    for section in sections:
        virtual_address = section.VirtualAddress
        virtual_size = section.Misc.VirtualSize
        if virtual_address <= relative_virtual_address < virtual_address + virtual_size:
            return (
                relative_virtual_address - virtual_address
            ) + section.PointerToRawData
    return None


def get_relocations(input, section_header: IMAGE_SECTION_HEADER):
    # https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#coff-relocations-object-only
    pass


def get_line_numbers(input, section_header: IMAGE_SECTION_HEADER):
    # https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#coff-line-numbers-deprecated
    pass


def seek_peek_image_dos_header(input):
    """
    Seeks to the beginning of file and peeks if it is a MS-DOS stub.
    """
    input.seek(io.SEEK_SET)
    return input.peek(getattr(IMAGE_DOS_HEADER, "e_magic")) == b"MZ"


def seek_get_image_dos_header(input):
    input.seek(io.SEEK_SET)
    ms_dos_stub = IMAGE_DOS_HEADER()
    input.readinto(ms_dos_stub)
    print(pretty(ms_dos_stub))
    return ms_dos_stub


def seek_get_image_nt_headers(input, ms_dos_stub: IMAGE_DOS_HEADER):
    input.seek(ms_dos_stub.e_lfanew)
    image_nt_headers = IMAGE_NT_HEADERS()
    input.readinto(image_nt_headers)
    print(pretty(image_nt_headers))
    assert get_bytes(image_nt_headers, "Signature") == b"PE\x00\x00"


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


def seek_get_section_headers(
    input,
    ms_dos_stub: IMAGE_DOS_HEADER,
    image_nt_headers: Union[IMAGE_NT_HEADERS, IMAGE_NT_HEADERS32, IMAGE_NT_HEADERS64],
):
    assert image_nt_headers.FileHeader.SizeOfOptionalHeader == ctypes.sizeof(
        image_nt_headers.OptionalHeader
    )
    input.seek(ms_dos_stub.e_lfanew + ctypes.sizeof(image_nt_headers))
    return get_section_headers(input, image_nt_headers.FileHeader)


def parse_buffer(input):
    """
    https://docs.microsoft.com/en-us/windows/desktop/Debug/pe-format
    https://en.wikibooks.org/wiki/X86_Disassembly/Windows_Executable_Files    
    http://www.pinvoke.net/default.aspx/Structures.IMAGE_DOS_HEADER
    """
    if seek_peek_image_dos_header(input):
        ms_dos_stub = seek_get_image_dos_header(input)
        image_nt_headers = seek_get_image_nt_headers(input, ms_dos_stub)
        section_headers = seek_get_section_headers(input, ms_dos_stub, image_nt_headers)

        section_contents = list()
        for section_header in section_headers:
            section_contents.append(seek_get_section_content(input, section_header))

        symbols = seek_get_symbols(input, image_nt_headers.FileHeader)

    else:
        # vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv
        # order of statements important
        # vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv
        image_file_header = IMAGE_FILE_HEADER()
        input.readinto(image_file_header)
        print(pretty(image_file_header))
        section_headers = get_section_headers(input, image_file_header)
        # ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
        # order of statements important
        # ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
        symbols = seek_get_symbols(input, image_file_header)
        section_contents = list()
        for section_header in section_headers:
            section_contents.append(seek_get_section_content(input, section_headers))

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
