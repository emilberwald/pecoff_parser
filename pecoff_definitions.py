import ctypes
from enum import Enum, IntFlag

IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16
IMAGE_SIZEOF_SHORT_NAME = 8
N_BTSHFT = 4
IMAGE_SIZEOF_SYMBOL = 18


class IMAGE_FILE_MACHINE(Enum):
    """https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#machine-types"""

    # The contents of this field are assumed to be applicable to any machine type
    IMAGE_FILE_MACHINE_UNKNOWN = 0x0
    # Matsushita AM33
    IMAGE_FILE_MACHINE_AM33 = 0x1D3
    # x64
    IMAGE_FILE_MACHINE_AMD64 = 0x8664
    # ARM little endian
    IMAGE_FILE_MACHINE_ARM = 0x1C0
    # ARM64 little endian
    IMAGE_FILE_MACHINE_ARM64 = 0xAA64
    # ARM Thumb-2 little endian
    IMAGE_FILE_MACHINE_ARMNT = 0x1C4
    # EFI byte code
    IMAGE_FILE_MACHINE_EBC = 0xEBC
    # Intel 386 or later processors and compatible processors
    IMAGE_FILE_MACHINE_I386 = 0x14C
    # Intel Itanium processor family
    IMAGE_FILE_MACHINE_IA64 = 0x200
    # Mitsubishi M32R little endian
    IMAGE_FILE_MACHINE_M32R = 0x9041
    # MIPS16
    IMAGE_FILE_MACHINE_MIPS16 = 0x266
    # MIPS with FPU
    IMAGE_FILE_MACHINE_MIPSFPU = 0x366
    # MIPS16 with FPU
    IMAGE_FILE_MACHINE_MIPSFPU16 = 0x466
    # Power PC little endian
    IMAGE_FILE_MACHINE_POWERPC = 0x1F0
    # Power PC with floating point support
    IMAGE_FILE_MACHINE_POWERPCFP = 0x1F1
    # MIPS little endian
    IMAGE_FILE_MACHINE_R4000 = 0x166
    # RISC-V 32-bit address space
    IMAGE_FILE_MACHINE_RISCV32 = 0x5032
    # RISC-V 64-bit address space
    IMAGE_FILE_MACHINE_RISCV64 = 0x5064
    # RISC-V 128-bit address space
    IMAGE_FILE_MACHINE_RISCV128 = 0x5128
    # Hitachi SH3
    IMAGE_FILE_MACHINE_SH3 = 0x1A2
    # Hitachi SH3 DSP
    IMAGE_FILE_MACHINE_SH3DSP = 0x1A3
    # Hitachi SH4
    IMAGE_FILE_MACHINE_SH4 = 0x1A6
    # Hitachi SH5
    IMAGE_FILE_MACHINE_SH5 = 0x1A8
    # Thumb
    IMAGE_FILE_MACHINE_THUMB = 0x1C2
    # MIPS little-endian WCE v2
    IMAGE_FILE_MACHINE_WCEMIPSV2 = 0x169


class IMAGE_FILE_CHARACTERISTICS(IntFlag):
    """https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#characteristics"""

    # Image only, Windows CE, and Microsoft Windows NT and later. This indicates that the file does not contain base relocations and must therefore be loaded at its preferred base address. If the base address is not available, the loader reports an error. The default behavior of the linker is to strip base relocations from executable (EXE) files.
    IMAGE_FILE_RELOCS_STRIPPED = 0x0001
    # Image only. This indicates that the image file is valid and can be run. If this flag is not set, it indicates a linker error.
    IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
    # COFF line numbers have been removed. This flag is deprecated and should be zero.
    IMAGE_FILE_LINE_NUMS_STRIPPED = 0x0004
    # COFF symbol table entries for local symbols have been removed. This flag is deprecated and should be zero.
    IMAGE_FILE_LOCAL_SYMS_STRIPPED = 0x0008
    # Obsolete. Aggressively trim working set. This flag is deprecated for Windows 2000 and later and must be zero.
    IMAGE_FILE_AGGRESSIVE_WS_TRIM = 0x0010
    # Application can handle > 2-GB addresses.
    IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020
    # This flag is reserved for future use.
    _7 = 0x0040
    # Little endian: the least significant bit (LSB) precedes the most significant bit (MSB) in memory. This flag is deprecated and should be zero.
    IMAGE_FILE_BYTES_REVERSED_LO = 0x0080
    # Machine is based on a 32-bit-word architecture.
    IMAGE_FILE_32BIT_MACHINE = 0x0100
    # Debugging information is removed from the image file.
    IMAGE_FILE_DEBUG_STRIPPED = 0x0200
    # If the image is on removable media, fully load it and copy it to the swap file.
    IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP = 0x0400
    # If the image is on network media, fully load it and copy it to the swap file.
    IMAGE_FILE_NET_RUN_FROM_SWAP = 0x0800
    # The image file is a system file, not a user program.
    IMAGE_FILE_SYSTEM = 0x1000
    # The image file is a dynamic-link library (DLL). Such files are considered executable files for almost all purposes, although they cannot be directly run.
    IMAGE_FILE_DLL = 0x2000
    # The file should be run only on a uniprocessor machine.
    IMAGE_FILE_UP_SYSTEM_ONLY = 0x4000
    # Big endian: the MSB precedes the LSB in memory. This flag is deprecated and should be zero.
    IMAGE_FILE_BYTES_REVERSED_HI = 0x8000


class IMAGE(Enum):
    """https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-_image_optional_header#members"""

    # 32 bit executable image.
    IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10B
    # 64 bit executable image
    IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20B
    # ROM image
    IMAGE_ROM_OPTIONAL_HDR_MAGIC = 0x107


class IMAGE_SUBSYSTEM(Enum):
    """https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#windows-subsystem"""

    # An unknown subsystem
    IMAGE_SUBSYSTEM_UNKNOWN = 0
    # Device drivers and native Windows processes
    IMAGE_SUBSYSTEM_NATIVE = 1
    # The Windows graphical user interface (GUI) subsystem
    IMAGE_SUBSYSTEM_WINDOWS_GUI = 2
    # The Windows character subsystem
    IMAGE_SUBSYSTEM_WINDOWS_CUI = 3
    # The OS/2 character subsystem
    IMAGE_SUBSYSTEM_OS2_CUI = 5
    # The Posix character subsystem
    IMAGE_SUBSYSTEM_POSIX_CUI = 7
    # Native Win9x driver
    IMAGE_SUBSYSTEM_NATIVE_WINDOWS = 8
    # Windows CE
    IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9
    # An Extensible Firmware Interface (EFI) application
    IMAGE_SUBSYSTEM_EFI_APPLICATION = 10
    # An EFI driver with boot services
    IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11
    # An EFI driver with run-time services
    IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12
    # An EFI ROM image
    IMAGE_SUBSYSTEM_EFI_ROM = 13
    # XBOX
    IMAGE_SUBSYSTEM_XBOX = 14
    # Windows boot application.
    IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION = 16


class IMAGE_DLLCHARACTERISTICS(IntFlag):
    """https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#dll-characteristics"""

    # Reserved, must be zero.
    _IMAGE_LIBRARY_PROCESS_INIT = 0x0001
    # Reserved, must be zero.
    _IMAGE_LIBRARY_PROCESS_TERM = 0x0002
    # Reserved, must be zero.
    _IMAGE_LIBRARY_THREAD_INIT = 0x0004
    # Reserved, must be zero.
    _IMAGE_LIBRARY_THREAD_TERM = 0x0008
    # Image can handle a high entropy 64-bit virtual address space.
    IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020
    # DLL can be relocated at load time.
    IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
    # Code Integrity checks are enforced.
    IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY = 0x0080
    # Image is NX compatible.
    IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100
    # Isolation aware, but do not isolate the image.
    IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200
    # Does not use structured exception (SE) handling. No SE handler may be called in this image.
    IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400
    # Do not bind the image.
    IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800
    # Image must execute in an AppContainer.
    IMAGE_DLLCHARACTERISTICS_APPCONTAINER = 0x1000
    # A WDM driver.
    IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000
    # Image supports Control Flow Guard.
    IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000
    # Terminal Server aware.
    IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000


class IMAGE_SCN(IntFlag):
    """https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#section-flags"""

    # Reserved for future use.
    _IMAGE_SCN_TYPE_REG = 0x00000000
    # Reserved for future use.
    _IMAGE_SCN_TYPE_DSECT = 0x00000001
    IMAGE_SCN_SCALE_INDEX = 0x00000001
    # Reserved for future use.
    _IMAGE_SCN_TYPE_NOLOAD = 0x00000002
    # Reserved for future use.
    _IMAGE_SCN_TYPE_GROUP = 0x00000004
    # The section should not be padded to the next boundary. This flag is obsolete and is replaced by IMAGE_SCN_ALIGN_1BYTES. This is valid only for object files.
    IMAGE_SCN_TYPE_NO_PAD = 0x00000008
    # Reserved for future use.
    _IMAGE_SCN_TYPE_COPY = 0x00000010
    # The section contains executable code.
    # Section contains code.
    IMAGE_SCN_CNT_CODE = 0x00000020
    # The section contains initialized data.
    # Section contains initialized data.
    IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
    # The section contains uninitialized data.
    # Section contains uninitialized data.
    IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
    # Reserved for future use.
    IMAGE_SCN_LNK_OTHER = 0x00000100
    # The section contains comments or other information. The .drectve section has this type. This is valid for object files only.
    # Section contains comments or some other type of information.
    IMAGE_SCN_LNK_INFO = 0x00000200
    # Reserved for future use.
    _IMAGE_SCN_TYPE_OVER = 0x00000400
    # The section will not become part of the image. This is valid only for object files.
    # Section contents will not become part of image.
    IMAGE_SCN_LNK_REMOVE = 0x00000800
    # The section contains COMDAT data. For more information, see COMDAT Sections (Object Only). This is valid only for object files.
    # Section contents comdat.
    IMAGE_SCN_LNK_COMDAT = 0x00001000
    # Reserved.
    _ = 0x00002000
    # Obsolete
    _IMAGE_SCN_MEM_PROTECTED = 0x00004000
    # Reset speculative exceptions handling bits in the TLB entries for this section.
    IMAGE_SCN_NO_DEFER_SPEC_EXC = 0x00004000
    # The section contains data referenced through the global pointer (GP).
    # Section content can be accessed relative to GP
    IMAGE_SCN_GPREL = 0x00008000
    IMAGE_SCN_MEM_FARDATA = 0x00008000
    # Obsolete
    _IMAGE_SCN_MEM_SYSHEAP = 0x00010000
    # Reserved for future use.
    IMAGE_SCN_MEM_PURGEABLE = 0x00020000
    # Reserved for future use.
    IMAGE_SCN_MEM_16BIT = 0x00020000
    # Reserved for future use.
    IMAGE_SCN_MEM_LOCKED = 0x00040000
    # Reserved for future use.
    IMAGE_SCN_MEM_PRELOAD = 0x00080000
    # Align data on a 1-byte boundary. Valid only for object files.
    IMAGE_SCN_ALIGN_1BYTES = 0x00100000
    # Align data on a 2-byte boundary. Valid only for object files.
    IMAGE_SCN_ALIGN_2BYTES = 0x00200000
    # Align data on a 4-byte boundary. Valid only for object files.
    IMAGE_SCN_ALIGN_4BYTES = 0x00300000
    # Align data on an 8-byte boundary. Valid only for object files.
    IMAGE_SCN_ALIGN_8BYTES = 0x00400000
    # Align data on a 16-byte boundary. Valid only for object files.
    # Default alignment if no others are specified.
    IMAGE_SCN_ALIGN_16BYTES = 0x00500000
    # Align data on a 32-byte boundary. Valid only for object files.
    IMAGE_SCN_ALIGN_32BYTES = 0x00600000
    # Align data on a 64-byte boundary. Valid only for object files.
    IMAGE_SCN_ALIGN_64BYTES = 0x00700000
    # Align data on a 128-byte boundary. Valid only for object files.
    IMAGE_SCN_ALIGN_128BYTES = 0x00800000
    # Align data on a 256-byte boundary. Valid only for object files.
    IMAGE_SCN_ALIGN_256BYTES = 0x00900000
    # Align data on a 512-byte boundary. Valid only for object files.
    IMAGE_SCN_ALIGN_512BYTES = 0x00A00000
    # Align data on a 1024-byte boundary. Valid only for object files.
    IMAGE_SCN_ALIGN_1024BYTES = 0x00B00000
    # Align data on a 2048-byte boundary. Valid only for object files.
    IMAGE_SCN_ALIGN_2048BYTES = 0x00C00000
    # Align data on a 4096-byte boundary. Valid only for object files.
    IMAGE_SCN_ALIGN_4096BYTES = 0x00D00000
    # Align data on an 8192-byte boundary. Valid only for object files.
    IMAGE_SCN_ALIGN_8192BYTES = 0x00E00000
    # Unused
    IMAGE_SCN_ALIGN_MASK = 0x00F00000
    # The section contains extended relocations.
    # Section contains extended relocations.
    IMAGE_SCN_LNK_NRELOC_OVFL = 0x01000000
    # The section can be discarded as needed.
    # Section can be discarded.
    IMAGE_SCN_MEM_DISCARDABLE = 0x02000000
    # The section cannot be cached.
    # Section is not cachable.
    IMAGE_SCN_MEM_NOT_CACHED = 0x04000000
    # The section is not pageable.
    # Section is not pageable.
    IMAGE_SCN_MEM_NOT_PAGED = 0x08000000
    # The section can be shared in memory.
    # Section is shareable.
    IMAGE_SCN_MEM_SHARED = 0x10000000
    # The section can be executed as code.
    # Section is executable.
    IMAGE_SCN_MEM_EXECUTE = 0x20000000
    # The section can be read.
    # Section is readable.
    IMAGE_SCN_MEM_READ = 0x40000000
    # The section can be written to.
    # Section is writeable.
    IMAGE_SCN_MEM_WRITE = 0x80000000


class IMAGE_REL_AMD64(Enum):
    """https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#x64-processors"""

    # The relocation is ignored.
    IMAGE_REL_AMD64_ABSOLUTE = 0x0000
    # The 64-bit VA of the relocation target.
    IMAGE_REL_AMD64_ADDR64 = 0x0001
    # The 32-bit VA of the relocation target.
    IMAGE_REL_AMD64_ADDR32 = 0x0002
    # The 32-bit address without an image base (RVA).
    IMAGE_REL_AMD64_ADDR32NB = 0x0003
    # The 32-bit relative address from the byte following the relocation.
    IMAGE_REL_AMD64_REL32 = 0x0004
    # The 32-bit address relative to byte distance 1 from the relocation.
    IMAGE_REL_AMD64_REL32_1 = 0x0005
    # The 32-bit address relative to byte distance 2 from the relocation.
    IMAGE_REL_AMD64_REL32_2 = 0x0006
    # The 32-bit address relative to byte distance 3 from the relocation.
    IMAGE_REL_AMD64_REL32_3 = 0x0007
    # The 32-bit address relative to byte distance 4 from the relocation.
    IMAGE_REL_AMD64_REL32_4 = 0x0008
    # The 32-bit address relative to byte distance 5 from the relocation.
    IMAGE_REL_AMD64_REL32_5 = 0x0009
    # The 16-bit section index of the section that contains the target. This is used to support debugging information.
    IMAGE_REL_AMD64_SECTION = 0x000A
    # The 32-bit offset of the target from the beginning of its section. This is used to support debugging information and static thread local storage.
    IMAGE_REL_AMD64_SECREL = 0x000B
    # A 7-bit unsigned offset from the base of the section that contains the target.
    IMAGE_REL_AMD64_SECREL7 = 0x000C
    # CLR tokens.
    IMAGE_REL_AMD64_TOKEN = 0x000D
    # A 32-bit signed span-dependent value emitted into the object.
    IMAGE_REL_AMD64_SREL32 = 0x000E
    # A pair that must immediately follow every span-dependent value.
    IMAGE_REL_AMD64_PAIR = 0x000F
    # A 32-bit signed span-dependent value that is applied at link time.
    IMAGE_REL_AMD64_SSPAN32 = 0x0010


class IMAGE_REL_ARM(Enum):
    """https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#arm-processors"""

    # The relocation is ignored.
    IMAGE_REL_ARM_ABSOLUTE = 0x0000
    # The 32-bit VA of the target.
    IMAGE_REL_ARM_ADDR32 = 0x0001
    # The 32-bit RVA of the target.
    IMAGE_REL_ARM_ADDR32NB = 0x0002
    # The 24-bit relative displacement to the target.
    IMAGE_REL_ARM_BRANCH24 = 0x0003
    # The reference to a subroutine call. The reference consists of two 16-bit instructions with 11-bit offsets.
    IMAGE_REL_ARM_BRANCH11 = 0x0004
    # The 32-bit relative address from the byte following the relocation.
    IMAGE_REL_ARM_REL32 = 0x000A
    # The 16-bit section index of the section that contains the target. This is used to support debugging information.
    IMAGE_REL_ARM_SECTION = 0x000E
    # The 32-bit offset of the target from the beginning of its section. This is used to support debugging information and static thread local storage.
    IMAGE_REL_ARM_SECREL = 0x000F
    # The 32-bit VA of the target. This relocation is applied using a MOVW instruction for the low 16 bits followed by a MOVT for the high 16 bits.
    IMAGE_REL_ARM_MOV32 = 0x0010
    # The 32-bit VA of the target. This relocation is applied using a MOVW instruction for the low 16 bits followed by a MOVT for the high 16 bits.
    IMAGE_REL_THUMB_MOV32 = 0x0011
    # The instruction is fixed up with the 21-bit relative displacement to the 2-byte aligned target. The least significant bit of the displacement is always zero and is not stored. This relocation corresponds to a Thumb-2 32-bit conditional B instruction.
    IMAGE_REL_THUMB_BRANCH20 = 0x0012
    # Unused
    _12 = 0x0013
    # The instruction is fixed up with the 25-bit relative displacement to the 2-byte aligned target. The least significant bit of the displacement is zero and is not stored.This relocation corresponds to a Thumb-2 B instruction.
    IMAGE_REL_THUMB_BRANCH24 = 0x0014
    # The instruction is fixed up with the 25-bit relative displacement to the 4-byte aligned target. The low 2 bits of the displacement are zero and are not stored.
    # This relocation corresponds to a Thumb-2 BLX instruction.
    IMAGE_REL_THUMB_BLX23 = 0x0015
    # The relocation is valid only when it immediately follows a ARM_REFHI or THUMB_REFHI. Its SymbolTableIndex contains a displacement and not an index into the symbol table.
    IMAGE_REL_ARM_PAIR = 0x0016


class IMAGE_REL_ARM64(Enum):
    """https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#arm64-processors"""

    # The relocation is ignored.
    IMAGE_REL_ARM64_ABSOLUTE = 0x0000
    # The 32-bit VA of the target.
    IMAGE_REL_ARM64_ADDR32 = 0x0001
    # The 32-bit RVA of the target.
    IMAGE_REL_ARM64_ADDR32NB = 0x0002
    # The 26-bit relative displacement to the target, for B and BL instructions.
    IMAGE_REL_ARM64_BRANCH26 = 0x0003
    # The page base of the target, for ADRP instruction.
    IMAGE_REL_ARM64_PAGEBASE_REL21 = 0x0004
    # The 12-bit relative displacement to the target, for instruction ADR
    IMAGE_REL_ARM64_REL21 = 0x0005
    # The 12-bit page offset of the target, for instructions ADD/ADDS (immediate) with zero shift.
    IMAGE_REL_ARM64_PAGEOFFSET_12A = 0x0006
    # The 12-bit page offset of the target, for instruction LDR (indexed, unsigned immediate).
    IMAGE_REL_ARM64_PAGEOFFSET_12L = 0x0007
    # The 32-bit offset of the target from the beginning of its section. This is used to support debugging information and static thread local storage.
    IMAGE_REL_ARM64_SECREL = 0x0008
    # Bit 0:11 of section offset of the target, for instructions ADD/ADDS (immediate) with zero shift.
    IMAGE_REL_ARM64_SECREL_LOW12A = 0x0009
    # Bit 12:23 of section offset of the target, for instructions ADD/ADDS (immediate) with zero shift.
    IMAGE_REL_ARM64_SECREL_HIGH12A = 0x000A
    # Bit 0:11 of section offset of the target, for instruction LDR (indexed, unsigned immediate).
    IMAGE_REL_ARM64_SECREL_LOW12L = 0x000B
    # CLR token.
    IMAGE_REL_ARM64_TOKEN = 0x000C
    # The 16-bit section index of the section that contains the target. This is used to support debugging information.
    IMAGE_REL_ARM64_SECTION = 0x000D
    # The 64-bit VA of the relocation target.
    IMAGE_REL_ARM64_ADDR64 = 0x000E
    # The 19-bit offset to the relocation target, for conditional B instruction.
    IMAGE_REL_ARM64_BRANCH19 = 0x000F
    # The 14-bit offset to the relocation target, for instructions TBZ and TBNZ.
    IMAGE_REL_ARM64_BRANCH14 = 0x0010
    # The 32-bit relative address from the byte following the relocation.
    IMAGE_REL_ARM64_REL32 = 0x0011


class IMAGE_REL_SH(Enum):
    """https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#hitachi-superh-processors"""

    # The relocation is ignored.
    IMAGE_REL_SH3_ABSOLUTE = 0x0000
    # A reference to the 16-bit location that contains the VA of the target symbol.
    IMAGE_REL_SH3_DIRECT16 = 0x0001
    # The 32-bit VA of the target symbol.
    IMAGE_REL_SH3_DIRECT32 = 0x0002
    # A reference to the 8-bit location that contains the VA of the target symbol.
    IMAGE_REL_SH3_DIRECT8 = 0x0003
    # A reference to the 8-bit instruction that contains the effective 16-bit VA of the target symbol.
    IMAGE_REL_SH3_DIRECT8_WORD = 0x0004
    # A reference to the 8-bit instruction that contains the effective 32-bit VA of the target symbol.
    IMAGE_REL_SH3_DIRECT8_LONG = 0x0005
    # A reference to the 8-bit location whose low 4 bits contain the VA of the target symbol.
    IMAGE_REL_SH3_DIRECT4 = 0x0006
    # A reference to the 8-bit instruction whose low 4 bits contain the effective 16-bit VA of the target symbol.
    IMAGE_REL_SH3_DIRECT4_WORD = 0x0007
    # A reference to the 8-bit instruction whose low 4 bits contain the effective 32-bit VA of the target symbol.
    IMAGE_REL_SH3_DIRECT4_LONG = 0x0008
    # A reference to the 8-bit instruction that contains the effective 16-bit relative offset of the target symbol.
    IMAGE_REL_SH3_PCREL8_WORD = 0x0009
    # A reference to the 8-bit instruction that contains the effective 32-bit relative offset of the target symbol.
    IMAGE_REL_SH3_PCREL8_LONG = 0x000A
    # A reference to the 16-bit instruction whose low 12 bits contain the effective 16-bit relative offset of the target symbol.
    IMAGE_REL_SH3_PCREL12_WORD = 0x000B
    # A reference to a 32-bit location that is the VA of the section that contains the target symbol.
    IMAGE_REL_SH3_STARTOF_SECTION = 0x000C
    # A reference to the 32-bit location that is the size of the section that contains the target symbol.
    IMAGE_REL_SH3_SIZEOF_SECTION = 0x000D
    # The 16-bit section index of the section that contains the target. This is used to support debugging information.
    IMAGE_REL_SH3_SECTION = 0x000E
    # The 32-bit offset of the target from the beginning of its section. This is used to support debugging information and static thread local storage.
    IMAGE_REL_SH3_SECREL = 0x000F
    # The 32-bit RVA of the target symbol.
    IMAGE_REL_SH3_DIRECT32_NB = 0x0010
    # GP relative.
    IMAGE_REL_SH3_GPREL4_LONG = 0x0011
    # CLR token.
    IMAGE_REL_SH3_TOKEN = 0x0012
    # The offset from the current instruction in longwords. If the NOMODE bit is not set, insert the inverse of the low bit at bit 32 to select PTA or PTB.
    IMAGE_REL_SHM_PCRELPT = 0x0013
    # The low 16 bits of the 32-bit address.
    IMAGE_REL_SHM_REFLO = 0x0014
    # The high 16 bits of the 32-bit address.
    IMAGE_REL_SHM_REFHALF = 0x0015
    # The low 16 bits of the relative address.
    IMAGE_REL_SHM_RELLO = 0x0016
    # The high 16 bits of the relative address.
    IMAGE_REL_SHM_RELHALF = 0x0017
    # The relocation is valid only when it immediately follows a REFHALF, RELHALF, or RELLO relocation. The SymbolTableIndex field of the relocation contains a displacement and not an index into the symbol table.
    IMAGE_REL_SHM_PAIR = 0x0018
    # The relocation ignores section mode.
    IMAGE_REL_SHM_NOMODE = 0x8000


class IMAGE_REL_PPC(Enum):
    """https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#ibm-powerpc-processors"""

    # The relocation is ignored.
    IMAGE_REL_PPC_ABSOLUTE = 0x0000
    # The 64-bit VA of the target.
    IMAGE_REL_PPC_ADDR64 = 0x0001
    # The 32-bit VA of the target.
    IMAGE_REL_PPC_ADDR32 = 0x0002
    # The low 24 bits of the VA of the target. This is valid only when the target symbol is absolute and can be sign-extended to its original value.
    IMAGE_REL_PPC_ADDR24 = 0x0003
    # The low 16 bits of the target's VA.
    IMAGE_REL_PPC_ADDR16 = 0x0004
    # The low 14 bits of the target's VA. This is valid only when the target symbol is absolute and can be sign-extended to its original value.
    IMAGE_REL_PPC_ADDR14 = 0x0005
    # A 24-bit PC-relative offset to the symbol's location.
    IMAGE_REL_PPC_REL24 = 0x0006
    # A 14-bit PC-relative offset to the symbol's location.
    IMAGE_REL_PPC_REL14 = 0x0007
    # The 32-bit RVA of the target.
    IMAGE_REL_PPC_ADDR32NB = 0x000A
    # The 32-bit offset of the target from the beginning of its section. This is used to support debugging information and static thread local storage.
    IMAGE_REL_PPC_SECREL = 0x000B
    # The 16-bit section index of the section that contains the target. This is used to support debugging information.
    IMAGE_REL_PPC_SECTION = 0x000C
    # The 16-bit offset of the target from the beginning of its section. This is used to support debugging information and static thread local storage.
    IMAGE_REL_PPC_SECREL16 = 0x000F
    # The high 16 bits of the target's 32-bit VA. This is used for the first instruction in a two-instruction sequence that loads a full address. This relocation must be immediately followed by a PAIR relocation whose SymbolTableIndex contains a signed 16-bit displacement that is added to the upper 16 bits that was taken from the location that is being relocated.
    IMAGE_REL_PPC_REFHI = 0x0010
    # The low 16 bits of the target's VA.
    IMAGE_REL_PPC_REFLO = 0x0011
    # A relocation that is valid only when it immediately follows a REFHI or SECRELHI relocation. Its SymbolTableIndex contains a displacement and not an index into the symbol table.
    IMAGE_REL_PPC_PAIR = 0x0012
    # The low 16 bits of the 32-bit offset of the target from the beginning of its section.
    IMAGE_REL_PPC_SECRELLO = 0x0013
    # The 16-bit signed displacement of the target relative to the GP register.
    IMAGE_REL_PPC_GPREL = 0x0015
    # The CLR token.
    IMAGE_REL_PPC_TOKEN = 0x0016


class IMAGE_REL_I386(Enum):
    """https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#intel-386-processors"""

    # The relocation is ignored.
    IMAGE_REL_I386_ABSOLUTE = 0x0000
    # Not supported.
    IMAGE_REL_I386_DIR16 = 0x0001
    # Not supported.
    IMAGE_REL_I386_REL16 = 0x0002
    # The target's 32-bit VA.
    IMAGE_REL_I386_DIR32 = 0x0006
    # The target's 32-bit RVA.
    IMAGE_REL_I386_DIR32NB = 0x0007
    # Not supported.
    IMAGE_REL_I386_SEG12 = 0x0009
    # The 16-bit section index of the section that contains the target. This is used to support debugging information.
    IMAGE_REL_I386_SECTION = 0x000A
    # The 32-bit offset of the target from the beginning of its section. This is used to support debugging information and static thread local storage.
    IMAGE_REL_I386_SECREL = 0x000B
    # The CLR token.
    IMAGE_REL_I386_TOKEN = 0x000C
    # A 7-bit offset from the base of the section that contains the target.
    IMAGE_REL_I386_SECREL7 = 0x000D
    # The 32-bit relative displacement to the target. This supports the x86 relative branch and call instructions.
    IMAGE_REL_I386_REL32 = 0x0014


class IMAGE_REL_IA64(Enum):
    """https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#intel-itanium-processor-family-ipf"""

    # The relocation is ignored.
    IMAGE_REL_IA64_ABSOLUTE = 0x0000
    # The instruction relocation can be followed by an ADDEND relocation whose value is added to the target address before it is inserted into the specified slot in the IMM14 bundle. The relocation target must be absolute or the image must be fixed.
    IMAGE_REL_IA64_IMM14 = 0x0001
    # The instruction relocation can be followed by an ADDEND relocation whose value is added to the target address before it is inserted into the specified slot in the IMM22 bundle. The relocation target must be absolute or the image must be fixed.
    IMAGE_REL_IA64_IMM22 = 0x0002
    # The slot number of this relocation must be one (1). The relocation can be followed by an ADDEND relocation whose value is added to the target address before it is stored in all three slots of the IMM64 bundle.
    IMAGE_REL_IA64_IMM64 = 0x0003
    # The target's 32-bit VA. This is supported only for /LARGEADDRESSAWARE:NO images.
    IMAGE_REL_IA64_DIR32 = 0x0004
    # The target's 64-bit VA.
    IMAGE_REL_IA64_DIR64 = 0x0005
    # The instruction is fixed up with the 25-bit relative displacement to the 16-bit aligned target. The low 4 bits of the displacement are zero and are not stored.
    IMAGE_REL_IA64_PCREL21B = 0x0006
    # The instruction is fixed up with the 25-bit relative displacement to the 16-bit aligned target. The low 4 bits of the displacement, which are zero, are not stored.
    IMAGE_REL_IA64_PCREL21M = 0x0007
    # The LSBs of this relocation's offset must contain the slot number whereas the rest is the bundle address. The bundle is fixed up with the 25-bit relative displacement to the 16-bit aligned target. The low 4 bits of the displacement are zero and are not stored.
    IMAGE_REL_IA64_PCREL21F = 0x0008
    # The instruction relocation can be followed by an ADDEND relocation whose value is added to the target address and then a 22-bit GP-relative offset that is calculated and applied to the GPREL22 bundle.
    IMAGE_REL_IA64_GPREL22 = 0x0009
    # The instruction is fixed up with the 22-bit GP-relative offset to the target symbol's literal table entry. The linker creates this literal table entry based on this relocation and the ADDEND relocation that might follow.
    IMAGE_REL_IA64_LTOFF22 = 0x000A
    # The 16-bit section index of the section contains the target. This is used to support debugging information.
    IMAGE_REL_IA64_SECTION = 0x000B
    # The instruction is fixed up with the 22-bit offset of the target from the beginning of its section. This relocation can be followed immediately by an ADDEND relocation, whose Value field contains the 32-bit unsigned offset of the target from the beginning of the section.
    IMAGE_REL_IA64_SECREL22 = 0x000C
    # The slot number for this relocation must be one (1). The instruction is fixed up with the 64-bit offset of the target from the beginning of its section. This relocation can be followed immediately by an ADDEND relocation whose Value field contains the 32-bit unsigned offset of the target from the beginning of the section.
    IMAGE_REL_IA64_SECREL64I = 0x000D
    # The address of data to be fixed up with the 32-bit offset of the target from the beginning of its section.
    IMAGE_REL_IA64_SECREL32 = 0x000E
    # The target's 32-bit RVA.
    IMAGE_REL_IA64_DIR32NB = 0x0010
    # This is applied to a signed 14-bit immediate that contains the difference between two relocatable targets. This is a declarative field for the linker that indicates that the compiler has already emitted this value.
    IMAGE_REL_IA64_SREL14 = 0x0011
    # This is applied to a signed 22-bit immediate that contains the difference between two relocatable targets. This is a declarative field for the linker that indicates that the compiler has already emitted this value.
    IMAGE_REL_IA64_SREL22 = 0x0012
    # This is applied to a signed 32-bit immediate that contains the difference between two relocatable values. This is a declarative field for the linker that indicates that the compiler has already emitted this value.
    IMAGE_REL_IA64_SREL32 = 0x0013
    # This is applied to an unsigned 32-bit immediate that contains the difference between two relocatable values. This is a declarative field for the linker that indicates that the compiler has already emitted this value.
    IMAGE_REL_IA64_UREL32 = 0x0014
    # A 60-bit PC-relative fixup that always stays as a BRL instruction of an MLX bundle.
    IMAGE_REL_IA64_PCREL60X = 0x0015
    # A 60-bit PC-relative fixup. If the target displacement fits in a signed 25-bit field, convert the entire bundle to an MBB bundle with NOP.B in slot 1 and a 25-bit BR instruction (with the 4 lowest bits all zero and dropped) in slot 2.
    IMAGE_REL_IA64_PCREL60B = 0x0016
    # A 60-bit PC-relative fixup. If the target displacement fits in a signed 25-bit field, convert the entire bundle to an MFB bundle with NOP.F in slot 1 and a 25-bit (4 lowest bits all zero and dropped) BR instruction in slot 2.
    IMAGE_REL_IA64_PCREL60F = 0x0017
    # A 60-bit PC-relative fixup. If the target displacement fits in a signed 25-bit field, convert the entire bundle to an MIB bundle with NOP.I in slot 1 and a 25-bit (4 lowest bits all zero and dropped) BR instruction in slot 2.
    IMAGE_REL_IA64_PCREL60I = 0x0018
    # A 60-bit PC-relative fixup. If the target displacement fits in a signed 25-bit field, convert the entire bundle to an MMB bundle with NOP.M in slot 1 and a 25-bit (4 lowest bits all zero and dropped) BR instruction in slot 2.
    IMAGE_REL_IA64_PCREL60M = 0x0019
    # A 64-bit GP-relative fixup.
    IMAGE_REL_IA64_IMMGPREL64 = 0x001A
    # A CLR token.
    IMAGE_REL_IA64_TOKEN = 0x001B
    # A 32-bit GP-relative fixup.
    IMAGE_REL_IA64_GPREL32 = 0x001C
    # The relocation is valid only when it immediately follows one of the following relocations: IMM14, IMM22, IMM64, GPREL22, LTOFF22, LTOFF64, SECREL22, SECREL64I, or SECREL32. Its value contains the addend to apply to instructions within a bundle, not for data.
    IMAGE_REL_IA64_ADDEND = 0x001F


class IMAGE_REL_MIPS(Enum):
    """https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#mips-processors"""

    # The relocation is ignored.
    IMAGE_REL_MIPS_ABSOLUTE = 0x0000
    # The high 16 bits of the target's 32-bit VA.
    IMAGE_REL_MIPS_REFHALF = 0x0001
    # The target's 32-bit VA.
    IMAGE_REL_MIPS_REFWORD = 0x0002
    # The low 26 bits of the target's VA. This supports the MIPS J and JAL instructions.
    IMAGE_REL_MIPS_JMPADDR = 0x0003
    # The high 16 bits of the target's 32-bit VA. This is used for the first instruction in a two-instruction sequence that loads a full address. This relocation must be immediately followed by a PAIR relocation whose SymbolTableIndex contains a signed 16-bit displacement that is added to the upper 16 bits that are taken from the location that is being relocated.
    IMAGE_REL_MIPS_REFHI = 0x0004
    # The low 16 bits of the target's VA.
    IMAGE_REL_MIPS_REFLO = 0x0005
    # A 16-bit signed displacement of the target relative to the GP register.
    IMAGE_REL_MIPS_GPREL = 0x0006
    # The same as IMAGE_REL_MIPS_GPREL.
    IMAGE_REL_MIPS_LITERAL = 0x0007
    # The 16-bit section index of the section contains the target. This is used to support debugging information.
    IMAGE_REL_MIPS_SECTION = 0x000A
    # The 32-bit offset of the target from the beginning of its section. This is used to support debugging information and static thread local storage.
    IMAGE_REL_MIPS_SECREL = 0x000B
    # The low 16 bits of the 32-bit offset of the target from the beginning of its section.
    IMAGE_REL_MIPS_SECRELLO = 0x000C
    # The high 16 bits of the 32-bit offset of the target from the beginning of its section. An IMAGE_REL_MIPS_PAIR relocation must immediately follow this one. The SymbolTableIndex of the PAIR relocation contains a signed 16-bit displacement that is added to the upper 16 bits that are taken from the location that is being relocated.
    IMAGE_REL_MIPS_SECRELHI = 0x000D
    # The low 26 bits of the target's VA. This supports the MIPS16 JAL instruction.
    IMAGE_REL_MIPS_JMPADDR16 = 0x0010
    # The target's 32-bit RVA.
    IMAGE_REL_MIPS_REFWORDNB = 0x0022
    # The relocation is valid only when it immediately follows a REFHI or SECRELHI relocation. Its SymbolTableIndex contains a displacement and not an index into the symbol table.
    IMAGE_REL_MIPS_PAIR = 0x0025


class IMAGE_REL_M32R(Enum):
    """https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#mitsubishi-m32r"""

    # The relocation is ignored.
    MAGE_REL_M32R_ABSOLUTE = 0x0000
    # The target's 32-bit VA.
    IMAGE_REL_M32R_ADDR32 = 0x0001
    # The target's 32-bit RVA.
    IMAGE_REL_M32R_ADDR32NB = 0x0002
    # The target's 24-bit VA.
    IMAGE_REL_M32R_ADDR24 = 0x0003
    # The target's 16-bit offset from the GP register.
    IMAGE_REL_M32R_GPREL16 = 0x0004
    # The target's 24-bit offset from the program counter (PC), shifted left by 2 bits and sign-extended
    IMAGE_REL_M32R_PCREL24 = 0x0005
    # The target's 16-bit offset from the PC, shifted left by 2 bits and sign-extended
    IMAGE_REL_M32R_PCREL16 = 0x0006
    # The target's 8-bit offset from the PC, shifted left by 2 bits and sign-extended
    IMAGE_REL_M32R_PCREL8 = 0x0007
    # The 16 MSBs of the target VA.
    IMAGE_REL_M32R_REFHALF = 0x0008
    # The 16 MSBs of the target VA, adjusted for LSB sign extension. This is used for the first instruction in a two-instruction sequence that loads a full 32-bit address. This relocation must be immediately followed by a PAIR relocation whose SymbolTableIndex contains a signed 16-bit displacement that is added to the upper 16 bits that are taken from the location that is being relocated.
    IMAGE_REL_M32R_REFHI = 0x0009
    # The 16 LSBs of the target VA.
    IMAGE_REL_M32R_REFLO = 0x000A
    # The relocation must follow the REFHI relocation. Its SymbolTableIndex contains a displacement and not an index into the symbol table.
    IMAGE_REL_M32R_PAIR = 0x000B
    # The 16-bit section index of the section that contains the target. This is used to support debugging information.
    IMAGE_REL_M32R_SECTION = 0x000C
    # The 32-bit offset of the target from the beginning of its section. This is used to support debugging information and static thread local storage.
    IMAGE_REL_M32R_SECREL = 0x000D
    # The CLR token.
    IMAGE_REL_M32R_TOKEN = 0x000E


class IMAGE_SYM(Enum):
    r"""
    https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#section-number-values
    %PROGRAMFILES(x86)%\Windows Kits\10\Include\10.0.18362.0\um\winnt.h
    """

    # The symbol record is not yet assigned a section. A value of zero indicates that a reference to an external symbol is defined elsewhere. A value of non-zero is a common symbol with a size that is specified by the value.
    # Symbol is undefined or is common.
    IMAGE_SYM_UNDEFINED = 0
    # The symbol has an absolute (non-relocatable) value and is not an address.
    # Symbol is an absolute value.
    IMAGE_SYM_ABSOLUTE = -1
    # The symbol provides general type or debugging information but does not correspond to a section. Microsoft tools use this setting along with .file records (storage class FILE).
    # Symbol is a special debug item.
    IMAGE_SYM_DEBUG = -2
    # Values 0xFF00-0xFFFF are special
    IMAGE_SYM_SECTION_MAX = 0xFEFF
    # (In COFF files compiled with Visual Studio's /bigobj switch, there can be more than 0x7FFF sections)
    IMAGE_SYM_SECTION_MAX_EX = 0x7FFFFFFF


class IMAGE_SYM_TYPE(Enum):
    r"""
    https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#type-representation
    %PROGRAMFILES(x86)%\Windows Kits\10\Include\10.0.18362.0\um\winnt.h
    """

    # No type information or unknown base type. Microsoft tools use this setting
    IMAGE_SYM_TYPE_NULL = 0x0000
    # No valid type; used with void pointers and functions
    IMAGE_SYM_TYPE_VOID = 0x0001
    # A character (signed byte)
    # type character.
    IMAGE_SYM_TYPE_CHAR = 0x0002
    # A 2-byte signed integer
    # type short integer.
    IMAGE_SYM_TYPE_SHORT = 0x0003
    # A natural integer type (normally 4 bytes in Windows)
    IMAGE_SYM_TYPE_INT = 0x0004
    # A 4-byte signed integer
    IMAGE_SYM_TYPE_LONG = 0x0005
    # A 4-byte floating-point number
    IMAGE_SYM_TYPE_FLOAT = 0x0006
    # An 8-byte floating-point number
    IMAGE_SYM_TYPE_DOUBLE = 0x0007
    # A structure
    IMAGE_SYM_TYPE_STRUCT = 0x0008
    # A union
    IMAGE_SYM_TYPE_UNION = 0x0009
    # An enumerated type
    # enumeration.
    IMAGE_SYM_TYPE_ENUM = 0x000A
    # A member of enumeration (a specific value)
    # member of enumeration.
    IMAGE_SYM_TYPE_MOE = 0x000B
    # A byte; unsigned 1-byte integer
    IMAGE_SYM_TYPE_BYTE = 0x000C
    # A word; unsigned 2-byte integer
    IMAGE_SYM_TYPE_WORD = 0x000D
    # An unsigned integer of natural size (normally, 4 bytes)
    IMAGE_SYM_TYPE_UINT = 0x000E
    # An unsigned 4-byte integer
    IMAGE_SYM_TYPE_DWORD = 0x000F
    IMAGE_SYM_TYPE_PCODE = 0x8000


class IMAGE_SYM_DTYPE(Enum):
    r"""
    https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#type-representation
    %PROGRAMFILES(x86)%\Windows Kits\10\Include\10.0.18362.0\um\winnt.h
    """

    # No derived type; the symbol is a simple scalar variable.
    # no derived type.
    IMAGE_SYM_DTYPE_NULL = 0
    # The symbol is a pointer to base type.
    # pointer.
    IMAGE_SYM_DTYPE_POINTER = 1
    # The symbol is a function that returns a base type.
    # function.
    IMAGE_SYM_DTYPE_FUNCTION = 2
    # The symbol is an array of base type.
    # array.
    IMAGE_SYM_DTYPE_ARRAY = 3


class IMAGE_SYM_CLASS(Enum):
    r"""
    https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#storage-class
    %PROGRAMFILES(x86)%\Windows Kits\10\Include\10.0.18362.0\um\winnt.h
    """

    # A special symbol that represents the end of function, for debugging purposes.
    IMAGE_SYM_CLASS_END_OF_FUNCTION = 0xFF  # (unsigned char)-1
    # No assigned storage class.
    IMAGE_SYM_CLASS_NULL = 0x0000
    # The automatic (stack) variable. The Value field specifies the stack frame offset.
    IMAGE_SYM_CLASS_AUTOMATIC = 0x0001
    # A value that Microsoft tools use for external symbols. The Value field indicates the size if the section number is IMAGE_SYM_UNDEFINED (0). If the section number is not zero, then the Value field specifies the offset within the section.
    IMAGE_SYM_CLASS_EXTERNAL = 0x0002
    # The offset of the symbol within the section. If the Value field is zero, then the symbol represents a section name.
    IMAGE_SYM_CLASS_STATIC = 0x0003
    # A register variable. The Value field specifies the register number.
    IMAGE_SYM_CLASS_REGISTER = 0x0004
    # A symbol that is defined externally.
    IMAGE_SYM_CLASS_EXTERNAL_DEF = 0x0005
    # A code label that is defined within the module. The Value field specifies the offset of the symbol within the section.
    IMAGE_SYM_CLASS_LABEL = 0x0006
    # A reference to a code label that is not defined.
    IMAGE_SYM_CLASS_UNDEFINED_LABEL = 0x0007
    # The structure member. The Value field specifies the n th member.
    IMAGE_SYM_CLASS_MEMBER_OF_STRUCT = 0x0008
    # A formal argument (parameter) of a function. The Value field specifies the n th argument.
    IMAGE_SYM_CLASS_ARGUMENT = 0x0009
    # The structure tag-name entry.
    IMAGE_SYM_CLASS_STRUCT_TAG = 0x000A
    # A union member. The Value field specifies the n th member.
    IMAGE_SYM_CLASS_MEMBER_OF_UNION = 0x000B
    # The Union tag-name entry.
    IMAGE_SYM_CLASS_UNION_TAG = 0x000C
    # A Typedef entry.
    IMAGE_SYM_CLASS_TYPE_DEFINITION = 0x000D
    # A static data declaration.
    IMAGE_SYM_CLASS_UNDEFINED_STATIC = 0x000E
    # An enumerated type tagname entry.
    IMAGE_SYM_CLASS_ENUM_TAG = 0x000F
    # A member of an enumeration. The Value field specifies the n th member.
    IMAGE_SYM_CLASS_MEMBER_OF_ENUM = 0x0010
    # A register parameter.
    IMAGE_SYM_CLASS_REGISTER_PARAM = 0x0011
    # A bit-field reference. The Value field specifies the n th bit in the bit field.
    IMAGE_SYM_CLASS_BIT_FIELD = 0x0012
    IMAGE_SYM_CLASS_FAR_EXTERNAL = 0x0044
    # A .bb (beginning of block) or .eb (end of block) record. The Value field is the relocatable address of the code location.
    IMAGE_SYM_CLASS_BLOCK = 0x0064
    # A value that Microsoft tools use for symbol records that define the extent of a function: begin function (.bf ), end function ( .ef ), and lines in function ( .lf ). For .lf records, the Value field gives the number of source lines in the function. For .ef records, the Value field gives the size of the function code.
    IMAGE_SYM_CLASS_FUNCTION = 0x0065
    # An end-of-structure entry.
    IMAGE_SYM_CLASS_END_OF_STRUCT = 0x0066
    # A value that Microsoft tools, as well as traditional COFF format, use for the source-file symbol record. The symbol is followed by auxiliary records that name the file.
    IMAGE_SYM_CLASS_FILE = 0x0067
    # A definition of a section (Microsoft tools use STATIC storage class instead).
    IMAGE_SYM_CLASS_SECTION = 0x0068
    # A weak external. For more information, see Auxiliary Format 3: Weak Externals.
    IMAGE_SYM_CLASS_WEAK_EXTERNAL = 0x0069
    # A CLR token symbol. The name is an ASCII string that consists of the hexadecimal value of the token. For more information, see CLR Token Definition (Object Only).
    IMAGE_SYM_CLASS_CLR_TOKEN = 0x006B


class IMAGE_COMDAT(Enum):
    """https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#comdat-sections-object-only"""

    # If this symbol is already defined, the linker issues a "multiply defined symbol" error.
    IMAGE_COMDAT_SELECT_NODUPLICATES = 1
    # Any section that defines the same COMDAT symbol can be linked; the rest are removed.
    IMAGE_COMDAT_SELECT_ANY = 2
    # The linker chooses an arbitrary section among the definitions for this symbol. If all definitions are not the same size, a "multiply defined symbol" error is issued.
    IMAGE_COMDAT_SELECT_SAME_SIZE = 3
    # The linker chooses an arbitrary section among the definitions for this symbol. If all definitions do not match exactly, a "multiply defined symbol" error is issued.
    IMAGE_COMDAT_SELECT_EXACT_MATCH = 4
    # The section is linked if a certain other COMDAT section is linked. This other section is indicated by the Number field of the auxiliary symbol record for the section definition. This setting is useful for definitions that have components in multiple sections (for example, code in one and data in another), but where all must be linked or discarded as a set. The other section with which this section is associated must be a COMDAT section; it cannot be another associative COMDAT section (that is, the other section cannot have IMAGE_COMDAT_SELECT_ASSOCIATIVE set).
    IMAGE_COMDAT_SELECT_ASSOCIATIVE = 5
    # The linker chooses the largest definition from among all of the definitions for this symbol. If multiple definitions have this size, the choice between them is arbitrary.
    IMAGE_COMDAT_SELECT_LARGEST = 6


class WIN_CERT_REVISION(Enum):
    """https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#the-attribute-certificate-table-image-only"""

    # Version 1, legacy version of the Win_Certificate structure. It is supported only for purposes of verifying legacy Authenticode signatures
    WIN_CERT_REVISION_1_0 = 0x0100
    # Version 2 is the current version of the Win_Certificate structure.
    WIN_CERT_REVISION_2_0 = 0x0200


class WIN_CERT_TYPE(Enum):
    """https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#the-attribute-certificate-table-image-only"""

    # bCertificate contains an X.509 Certificate
    # Not Supported
    WIN_CERT_TYPE_X509 = 0x0001
    # bCertificate contains a PKCS#7 SignedData structure
    WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002
    # Reserved
    WIN_CERT_TYPE_RESERVED_1 = 0x0003
    # Terminal Server Protocol Stack Certificate signing
    # Not Supported
    WIN_CERT_TYPE_TS_STACK_SIGNED = 0x0004


class IMAGE_DEBUG_TYPE(Enum):
    """https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#debug-type"""

    # An unknown value that is ignored by all tools.
    IMAGE_DEBUG_TYPE_UNKNOWN = 0
    # The COFF debug information (line numbers, symbol table, and string table). This type of debug information is also pointed to by fields in the file headers.
    IMAGE_DEBUG_TYPE_COFF = 1
    # The Visual C++ debug information.
    IMAGE_DEBUG_TYPE_CODEVIEW = 2
    # The frame pointer omission (FPO) information. This information tells the debugger how to interpret nonstandard stack frames, which use the EBP register for a purpose other than as a frame pointer.
    IMAGE_DEBUG_TYPE_FPO = 3
    # The location of DBG file.
    IMAGE_DEBUG_TYPE_MISC = 4
    # A copy of .pdata section.
    IMAGE_DEBUG_TYPE_EXCEPTION = 5
    # Reserved.
    IMAGE_DEBUG_TYPE_FIXUP = 6
    # The mapping from an RVA in image to an RVA in source image.
    IMAGE_DEBUG_TYPE_OMAP_TO_SRC = 7
    # The mapping from an RVA in source image to an RVA in image.
    IMAGE_DEBUG_TYPE_OMAP_FROM_SRC = 8
    # Reserved for Borland.
    IMAGE_DEBUG_TYPE_BORLAND = 9
    # Reserved.
    IMAGE_DEBUG_TYPE_RESERVED10 = 10
    # Reserved.
    IMAGE_DEBUG_TYPE_CLSID = 11
    # PE determinism or reproducibility.
    IMAGE_DEBUG_TYPE_REPRO = 16
    # Extended DLL characteristics bits.
    IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS = 20


class IMAGE_DIRECTORY_ENTRY(Enum):
    IMAGE_DIRECTORY_ENTRY_EXPORT = 0  # Export Directory
    IMAGE_DIRECTORY_ENTRY_IMPORT = 1  # Import Directory
    IMAGE_DIRECTORY_ENTRY_RESOURCE = 2  # Resource Directory
    IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3  # Exception Directory
    IMAGE_DIRECTORY_ENTRY_SECURITY = 4  # Security Directory
    IMAGE_DIRECTORY_ENTRY_BASERELOC = 5  # Base Relocation Table
    IMAGE_DIRECTORY_ENTRY_DEBUG = 6  # Debug Directory
    _IMAGE_DIRECTORY_ENTRY_COPYRIGHT = 7  # (X86 usage)
    IMAGE_DIRECTORY_ENTRY_ARCHITECTURE = 7  # Architecture Specific Data
    IMAGE_DIRECTORY_ENTRY_GLOBALPTR = 8  # RVA of GP
    IMAGE_DIRECTORY_ENTRY_TLS = 9  # TLS Directory
    IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10  # Load Configuration Directory
    IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT = 11  # Bound Import Directory in headers
    IMAGE_DIRECTORY_ENTRY_IAT = 12  # Import Address Table
    IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT = 13  # Delay Load Import Descriptors
    IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14  # COM Runtime descriptor


class IMAGE_DLLCHARACTERISTICS_EX(Enum):
    """https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#extended-dll-characteristics"""

    # Image is CET compatible.
    IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT = 0x0001


class IMAGE_REL_BASED(Enum):
    """https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#base-relocation-types"""

    # The base relocation is skipped. This type can be used to pad a block.
    IMAGE_REL_BASED_ABSOLUTE = 0
    # The base relocation adds the high 16 bits of the difference to the 16-bit field at offset. The 16-bit field represents the high value of a 32-bit word.
    IMAGE_REL_BASED_HIGH = 1
    # The base relocation adds the low 16 bits of the difference to the 16-bit field at offset. The 16-bit field represents the low half of a 32-bit word.
    IMAGE_REL_BASED_LOW = 2
    # The base relocation applies all 32 bits of the difference to the 32-bit field at offset.
    IMAGE_REL_BASED_HIGHLOW = 3
    # The base relocation adds the high 16 bits of the difference to the 16-bit field at offset. The 16-bit field represents the high value of a 32-bit word. The low 16 bits of the 32-bit value are stored in the 16-bit word that follows this base relocation. This means that this base relocation occupies two slots.
    IMAGE_REL_BASED_HIGHADJ = 4
    # The relocation interpretation is dependent on the machine type.
    # When the machine type is MIPS, the base relocation applies to a MIPS jump instruction.
    IMAGE_REL_BASED_MIPS_JMPADDR = 5
    # This relocation is meaningful only when the machine type is ARM or Thumb. The base relocation applies the 32-bit address of a symbol across a consecutive MOVW/MOVT instruction pair.
    IMAGE_REL_BASED_ARM_MOV32 = 5
    # This relocation is only meaningful when the machine type is RISC-V. The base relocation applies to the high 20 bits of a 32-bit absolute address.
    IMAGE_REL_BASED_RISCV_HIGH20 = 5
    # Reserved, must be zero.
    _9 = 6
    # This relocation is meaningful only when the machine type is Thumb. The base relocation applies the 32-bit address of a symbol to a consecutive MOVW/MOVT instruction pair.
    IMAGE_REL_BASED_THUMB_MOV32 = 7
    # This relocation is only meaningful when the machine type is RISC-V. The base relocation applies to the low 12 bits of a 32-bit absolute address formed in RISC-V I-type instruction format.
    IMAGE_REL_BASED_RISCV_LOW12I = 7
    # This relocation is only meaningful when the machine type is RISC-V. The base relocation applies to the low 12 bits of a 32-bit absolute address formed in RISC-V S-type instruction format.
    IMAGE_REL_BASED_RISCV_LOW12S = 8
    # The relocation is only meaningful when the machine type is MIPS. The base relocation applies to a MIPS16 jump instruction.
    IMAGE_REL_BASED_MIPS_JMPADDR16 = 9
    # The base relocation applies the difference to the 64-bit field at offset.
    IMAGE_REL_BASED_DIR64 = 10


class DLL(Enum):
    """https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#tls-callback-functions"""

    # A new process has started, including the first thread.
    DLL_PROCESS_ATTACH = 1
    # A new thread has been created. This notification sent for all but the first thread.
    DLL_THREAD_ATTACH = 2
    # A thread is about to be terminated. This notification sent for all but the first thread.
    DLL_THREAD_DETACH = 3
    # A process is about to terminate, including the original thread.
    DLL_PROCESS_DETACH = 0


class IMAGE_GUARD(Enum):
    """https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#load-configuration-layout"""

    # Module performs control flow integrity checks using system-supplied support.
    IMAGE_GUARD_CF_INSTRUMENTED = 0x00000100
    # Module performs control flow and write integrity checks.
    IMAGE_GUARD_CFW_INSTRUMENTED = 0x00000200
    # Module contains valid control flow target metadata.
    IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT = 0x00000400
    # Module does not make use of the /GS security cookie.
    IMAGE_GUARD_SECURITY_COOKIE_UNUSED = 0x00000800
    # Module supports read only delay load IAT.
    IMAGE_GUARD_PROTECT_DELAYLOAD_IAT = 0x00001000
    # Delayload import table in its own .didat section (with nothing else in it) that can be freely reprotected.
    IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION = 0x00002000
    # Module contains suppressed export information. This also infers that the address taken IAT table is also present in the load config.
    IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT = 0x00004000
    # Module enables suppression of exports.
    IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION = 0x00008000
    # Module contains longjmp target information.
    IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT = 0x00010000
    # Mask for the subfield that contains the stride of Control Flow Guard function table entries (that is, the additional count of bytes per table entry).
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK = 0xF0000000
    # Additionally, the Windows SDK winnt.h header defines this macro for the amount of bits to right-shift the GuardFlags value to right-justify the Control Flow Guard function table stride:
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT = 28


class IMPORT_TYPE(Enum):
    """https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#import-type"""

    # Executable code.
    IMPORT_CODE = 0
    # Data.
    IMPORT_DATA = 1
    # Specified as CONST in the .def file.
    IMPORT_CONST = 2


class IMPORT_NAME_TYPE(Enum):
    """https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#import-name-type"""

    # The import is by ordinal. This indicates that the value in the Ordinal/Hint field of the import header is the import's ordinal. If this constant is not specified, then the Ordinal/Hint field should always be interpreted as the import's hint.
    IMPORT_ORDINAL = 0
    # The import name is identical to the public symbol name.
    IMPORT_NAME = 1
    # The import name is the public symbol name, but skipping the leading ?, @, or optionally _.
    IMPORT_NAME_NOPREFIX = 2
    # The import name is the public symbol name, but skipping the leading ?, @, or optionally _, and truncating at the first @.
    IMPORT_NAME_UNDECORATE = 3
