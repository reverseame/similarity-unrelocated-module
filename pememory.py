import math
import re
import string
import struct
import sys
import time

import volatility.debug as debug
from collections import Counter
from hashlib import sha1
from hashlib import sha256
from hashlib import sha512
from hashlib import md5


#Constants
PAGE_SIZE = 0x1000

# This will set a maximum length of a string to be retrieved from the file.
# It's there to prevent loading massive amounts of data from memory mapped
# files. Strings longer than 1MB should be rather rare.
MAX_STRING_LENGTH = 0x100000 # 2^20

# Limit maximum length for specific string types separately
MAX_IMPORT_NAME_LENGTH = 0x200
MAX_DLL_LENGTH = 0x200
MAX_SYMBOL_NAME_LENGTH = 0x200

DEBUG = True

# Marks for bytes
UNKW_BYTE = 0
DOS_HEADER_BYTE = 'DOS Header' if DEBUG else 1
DOS_SEGMENT_BYTE = 'DOS Segment' if DEBUG else 2
NT_HEADER_BYTE = 'N' if DEBUG else 3
FILE_HEADER_BYTE = 'F' if DEBUG else 4
OPTIONAL_HEADER_BYTE = 'O' if DEBUG else 5
DATA_DIRECTORY_BYTE = 'A' if DEBUG else 6
SECTION_HEADER_BYTE = 'Section header' if DEBUG else 7
EXPORT_DIRECTORY_BYTE = 'Export Directory bytes' if DEBUG else 8
IMPORT_DIRECTORY_BYTE = 'Import directory bytes' if DEBUG else 9
RESOURCE_DIRECTORY_BYTE = 'Resource directory' if DEBUG else 10
RESOURCE_DIRECTORY_BYTE_ToDo = 'R_ToDo' if DEBUG else 11
EXCEPTION_DIRECTORY_BYTE = 'Runtime Function' if DEBUG else 12
EXCEPTION_DIRECTORY_BYTE_CODE = 'XC' if DEBUG else 13
EXCEPTION_DIRECTORY_BYTE_PAD = 'XP' if DEBUG else 14
SECURITY_DIRECTORY_BYTE = 'Signature' if DEBUG else 15
BASERELOC_DIRECTORY_BYTE = 'Base Relocation' if DEBUG else 16
DEBUG_DIRECTORY_BYTE = 'Debug Directory' if DEBUG else 17
COPYRIGHT_DIRECTORY_BYTE = 'Copyright' if DEBUG else 18
GLOBALPTR_DIRECTORY_BYTE = 'G' if DEBUG else 19
TLS_DIRECTORY_BYTE = 'TLS directory' if DEBUG else 20
LOAD_CONFIG_DIRECTORY_BYTE = 'Load Config Directory' if DEBUG else 1
BOUND_IMPORT_DIRECTORY_BYTE = 'Bound Import Directory' if DEBUG else 1
IAT_DIRECTORY_BYTE = 'IAT directory' if DEBUG else 21
DELAY_IMPORT_DIRECTORY_BYTE = 'Delay Import Directory' if DEBUG else 22
COM_DESCRIPTOR_DIRECTORY_BYTE = 'COM Descriptor' if DEBUG else 23
NULL_PAGE = 'Null' if DEBUG else 24
EXCEPTION_DIRECTORY_UNWIND = 'EXCEPTION_DIRECTORY_unwind head' if DEBUG else 25
EXCEPTION_DIRECTORY_UNWIND_DATA = 'EXCEPTION_DIRECTORY_unwind data' if DEBUG else 26
IMPORT_DIRECTORY_BYTE_original_THUNK = 'Import Data by original thunk' if DEBUG else 27
IMPORT_DIRECTORY_BYTE_name = 'Import directory name' if DEBUG else 28
IMPORT_DIRECTORY_BYTE_IMPORT_NAME = 'Import directory import by name structure' if DEBUG else 29
DELAY_IMPORT_IAT_BYTE = 'Delay Import IAT' if DEBUG else 30
DELAY_IMPORT_INT_BYTE = 'Delay Import INT' if DEBUG else 31
END_PAGE_PADDING = 'End page padding' if DEBUG else 32
INSTRUCTION_BYTE = 'Bytes of a instruction' if DEBUG else 33
JUMPED_BYTE = 'Bytes jumped between instructions' if DEBUG else 34
PRE_TABLE = 'Pre-table find by pattern' if DEBUG else 35
TABLE = 'Table inside code section' if DEBUG else 36
STRING_ASCII = 'Ascii string inside code section' if DEBUG else 37
STRING_UNICODE = 'Unicode string inside code section' if DEBUG else 38


IMAGE_DOS_SIGNATURE             = 'MZ'
IMAGE_DOSZM_SIGNATURE           = 'ZM'
IMAGE_NE_SIGNATURE              = 'NE'
IMAGE_LE_SIGNATURE              = 'LE'
IMAGE_LX_SIGNATURE              = 'LX'
IMAGE_TE_SIGNATURE              = 'TE' # Terse Executables have a 'VZ' signature

IMAGE_NT_SIGNATURE              = 'PE\0\0'
IMAGE_NUMBEROF_DIRECTORY_ENTRIES= 16
IMAGE_ORDINAL_FLAG              = 0x80000000
IMAGE_ORDINAL_FLAG64            = 0x8000000000000000
OPTIONAL_HEADER_MAGIC_PE        = 0x10b
OPTIONAL_HEADER_MAGIC_PE_PLUS   = 0x20b

UNW_FLAG_EHANDLER  = 0x01
UNW_FLAG_UHANDLER  = 0x02
UNW_FLAG_CHAININFO = 0x04

directory_entry_types = [
    ('IMAGE_DIRECTORY_ENTRY_EXPORT',        0),
    ('IMAGE_DIRECTORY_ENTRY_IMPORT',        1),
    ('IMAGE_DIRECTORY_ENTRY_RESOURCE',      2),
    ('IMAGE_DIRECTORY_ENTRY_EXCEPTION',     3),
    ('IMAGE_DIRECTORY_ENTRY_SECURITY',      4),
    ('IMAGE_DIRECTORY_ENTRY_BASERELOC',     5),
    ('IMAGE_DIRECTORY_ENTRY_DEBUG',         6),
    ('IMAGE_DIRECTORY_ENTRY_COPYRIGHT',     7),
    ('IMAGE_DIRECTORY_ENTRY_GLOBALPTR',     8),
    ('IMAGE_DIRECTORY_ENTRY_TLS',           9),
    ('IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG',   10),
    ('IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT',  11),
    ('IMAGE_DIRECTORY_ENTRY_IAT',           12),
    ('IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT',  13),
    ('IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR',14),
    ('IMAGE_DIRECTORY_ENTRY_RESERVED',      15)]

DIRECTORY_ENTRY = dict(
    [(e[1], e[0]) for e in directory_entry_types]+directory_entry_types)

image_characteristics = [
    ('IMAGE_FILE_RELOCS_STRIPPED',          0x0001),
    ('IMAGE_FILE_EXECUTABLE_IMAGE',         0x0002),
    ('IMAGE_FILE_LINE_NUMS_STRIPPED',       0x0004),
    ('IMAGE_FILE_LOCAL_SYMS_STRIPPED',      0x0008),
    ('IMAGE_FILE_AGGRESIVE_WS_TRIM',        0x0010),
    ('IMAGE_FILE_LARGE_ADDRESS_AWARE',      0x0020),
    ('IMAGE_FILE_16BIT_MACHINE',            0x0040),
    ('IMAGE_FILE_BYTES_REVERSED_LO',        0x0080),
    ('IMAGE_FILE_32BIT_MACHINE',            0x0100),
    ('IMAGE_FILE_DEBUG_STRIPPED',           0x0200),
    ('IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP',  0x0400),
    ('IMAGE_FILE_NET_RUN_FROM_SWAP',        0x0800),
    ('IMAGE_FILE_SYSTEM',                   0x1000),
    ('IMAGE_FILE_DLL',                      0x2000),
    ('IMAGE_FILE_UP_SYSTEM_ONLY',           0x4000),
    ('IMAGE_FILE_BYTES_REVERSED_HI',        0x8000) ]

IMAGE_CHARACTERISTICS = dict([(e[1], e[0]) for e in
    image_characteristics]+image_characteristics)


section_characteristics = [
    ('IMAGE_SCN_TYPE_REG',                  0x00000000), # reserved
    ('IMAGE_SCN_TYPE_DSECT',                0x00000001), # reserved
    ('IMAGE_SCN_TYPE_NOLOAD',               0x00000002), # reserved
    ('IMAGE_SCN_TYPE_GROUP',                0x00000004), # reserved
    ('IMAGE_SCN_TYPE_NO_PAD',               0x00000008), # reserved
    ('IMAGE_SCN_TYPE_COPY',                 0x00000010), # reserved

    ('IMAGE_SCN_CNT_CODE',                  0x00000020),
    ('IMAGE_SCN_CNT_INITIALIZED_DATA',      0x00000040),
    ('IMAGE_SCN_CNT_UNINITIALIZED_DATA',    0x00000080),

    ('IMAGE_SCN_LNK_OTHER',                 0x00000100),
    ('IMAGE_SCN_LNK_INFO',                  0x00000200),
    ('IMAGE_SCN_LNK_OVER',                  0x00000400), # reserved
    ('IMAGE_SCN_LNK_REMOVE',                0x00000800),
    ('IMAGE_SCN_LNK_COMDAT',                0x00001000),

    ('IMAGE_SCN_MEM_PROTECTED',             0x00004000), # obsolete
    ('IMAGE_SCN_NO_DEFER_SPEC_EXC',         0x00004000),
    ('IMAGE_SCN_GPREL',                     0x00008000),
    ('IMAGE_SCN_MEM_FARDATA',               0x00008000),
    ('IMAGE_SCN_MEM_SYSHEAP',               0x00010000), # obsolete
    ('IMAGE_SCN_MEM_PURGEABLE',             0x00020000),
    ('IMAGE_SCN_MEM_16BIT',                 0x00020000),
    ('IMAGE_SCN_MEM_LOCKED',                0x00040000),
    ('IMAGE_SCN_MEM_PRELOAD',               0x00080000),

    ('IMAGE_SCN_ALIGN_1BYTES',              0x00100000),
    ('IMAGE_SCN_ALIGN_2BYTES',              0x00200000),
    ('IMAGE_SCN_ALIGN_4BYTES',              0x00300000),
    ('IMAGE_SCN_ALIGN_8BYTES',              0x00400000),
    ('IMAGE_SCN_ALIGN_16BYTES',             0x00500000), # default alignment
    ('IMAGE_SCN_ALIGN_32BYTES',             0x00600000),
    ('IMAGE_SCN_ALIGN_64BYTES',             0x00700000),
    ('IMAGE_SCN_ALIGN_128BYTES',            0x00800000),
    ('IMAGE_SCN_ALIGN_256BYTES',            0x00900000),
    ('IMAGE_SCN_ALIGN_512BYTES',            0x00A00000),
    ('IMAGE_SCN_ALIGN_1024BYTES',           0x00B00000),
    ('IMAGE_SCN_ALIGN_2048BYTES',           0x00C00000),
    ('IMAGE_SCN_ALIGN_4096BYTES',           0x00D00000),
    ('IMAGE_SCN_ALIGN_8192BYTES',           0x00E00000),
    ('IMAGE_SCN_ALIGN_MASK',                0x00F00000),

    ('IMAGE_SCN_LNK_NRELOC_OVFL',           0x01000000),
    ('IMAGE_SCN_MEM_DISCARDABLE',           0x02000000),
    ('IMAGE_SCN_MEM_NOT_CACHED',            0x04000000),
    ('IMAGE_SCN_MEM_NOT_PAGED',             0x08000000),
    ('IMAGE_SCN_MEM_SHARED',                0x10000000),
    ('IMAGE_SCN_MEM_EXECUTE',               0x20000000),
    ('IMAGE_SCN_MEM_READ',                  0x40000000),
    ('IMAGE_SCN_MEM_WRITE',                 0x80000000) ]

SECTION_CHARACTERISTICS = dict([(e[1], e[0]) for e in
    section_characteristics]+section_characteristics)


debug_types = [
    ('IMAGE_DEBUG_TYPE_UNKNOWN',        0),
    ('IMAGE_DEBUG_TYPE_COFF',           1),
    ('IMAGE_DEBUG_TYPE_CODEVIEW',       2),
    ('IMAGE_DEBUG_TYPE_FPO',            3),
    ('IMAGE_DEBUG_TYPE_MISC',           4),
    ('IMAGE_DEBUG_TYPE_EXCEPTION',      5),
    ('IMAGE_DEBUG_TYPE_FIXUP',          6),
    ('IMAGE_DEBUG_TYPE_OMAP_TO_SRC',    7),
    ('IMAGE_DEBUG_TYPE_OMAP_FROM_SRC',  8),
    ('IMAGE_DEBUG_TYPE_BORLAND',        9),
    ('IMAGE_DEBUG_TYPE_RESERVED10',     10),
    ('IMAGE_DEBUG_TYPE_CLSID',          11),
    ('IMAGE_DEBUG_TYPE_VC_FEATURE',     12),
    ('IMAGE_DEBUG_TYPE_POGO',           13),
    ('IMAGE_DEBUG_TYPE_ILTCG',          14),
    ('IMAGE_DEBUG_TYPE_MPX',            15) ]

DEBUG_TYPE = dict([(e[1], e[0]) for e in debug_types]+debug_types)


subsystem_types = [
    ('IMAGE_SUBSYSTEM_UNKNOWN',                   0),
    ('IMAGE_SUBSYSTEM_NATIVE',                    1),
    ('IMAGE_SUBSYSTEM_WINDOWS_GUI',               2),
    ('IMAGE_SUBSYSTEM_WINDOWS_CUI',               3),
    ('IMAGE_SUBSYSTEM_OS2_CUI',                   5),
    ('IMAGE_SUBSYSTEM_POSIX_CUI',                 7),
    ('IMAGE_SUBSYSTEM_NATIVE_WINDOWS',            8),
    ('IMAGE_SUBSYSTEM_WINDOWS_CE_GUI',            9),
    ('IMAGE_SUBSYSTEM_EFI_APPLICATION',          10),
    ('IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER',  11),
    ('IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER',       12),
    ('IMAGE_SUBSYSTEM_EFI_ROM',                  13),
    ('IMAGE_SUBSYSTEM_XBOX',                     14),
    ('IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION', 16)]

SUBSYSTEM_TYPE = dict([(e[1], e[0]) for e in subsystem_types]+subsystem_types)


machine_types = [
    ('IMAGE_FILE_MACHINE_UNKNOWN',  0),
    ('IMAGE_FILE_MACHINE_I386',     0x014c),
    ('IMAGE_FILE_MACHINE_R3000',    0x0162),
    ('IMAGE_FILE_MACHINE_R4000',    0x0166),
    ('IMAGE_FILE_MACHINE_R10000',   0x0168),
    ('IMAGE_FILE_MACHINE_WCEMIPSV2',0x0169),
    ('IMAGE_FILE_MACHINE_ALPHA',    0x0184),
    ('IMAGE_FILE_MACHINE_SH3',      0x01a2),
    ('IMAGE_FILE_MACHINE_SH3DSP',   0x01a3),
    ('IMAGE_FILE_MACHINE_SH3E',     0x01a4),
    ('IMAGE_FILE_MACHINE_SH4',      0x01a6),
    ('IMAGE_FILE_MACHINE_SH5',      0x01a8),
    ('IMAGE_FILE_MACHINE_ARM',      0x01c0),
    ('IMAGE_FILE_MACHINE_THUMB',    0x01c2),
    ('IMAGE_FILE_MACHINE_ARMNT',    0x01c4),
    ('IMAGE_FILE_MACHINE_AM33',     0x01d3),
    ('IMAGE_FILE_MACHINE_POWERPC',  0x01f0),
    ('IMAGE_FILE_MACHINE_POWERPCFP',0x01f1),
    ('IMAGE_FILE_MACHINE_IA64',     0x0200),
    ('IMAGE_FILE_MACHINE_MIPS16',   0x0266),
    ('IMAGE_FILE_MACHINE_ALPHA64',  0x0284),
    ('IMAGE_FILE_MACHINE_AXP64',    0x0284), # same
    ('IMAGE_FILE_MACHINE_MIPSFPU',  0x0366),
    ('IMAGE_FILE_MACHINE_MIPSFPU16',0x0466),
    ('IMAGE_FILE_MACHINE_TRICORE',  0x0520),
    ('IMAGE_FILE_MACHINE_CEF',      0x0cef),
    ('IMAGE_FILE_MACHINE_EBC',      0x0ebc),
    ('IMAGE_FILE_MACHINE_AMD64',    0x8664),
    ('IMAGE_FILE_MACHINE_M32R',     0x9041),
    ('IMAGE_FILE_MACHINE_CEE',      0xc0ee),
 ]

MACHINE_TYPE = dict([(e[1], e[0]) for e in machine_types]+machine_types)


relocation_types = [
    ('IMAGE_REL_BASED_ABSOLUTE',        0),
    ('IMAGE_REL_BASED_HIGH',            1),
    ('IMAGE_REL_BASED_LOW',             2),
    ('IMAGE_REL_BASED_HIGHLOW',         3),
    ('IMAGE_REL_BASED_HIGHADJ',         4),
    ('IMAGE_REL_BASED_MIPS_JMPADDR',    5),
    ('IMAGE_REL_BASED_SECTION',         6),
    ('IMAGE_REL_BASED_REL',             7),
    ('IMAGE_REL_BASED_MIPS_JMPADDR16',  9),
    ('IMAGE_REL_BASED_IA64_IMM64',      9),
    ('IMAGE_REL_BASED_DIR64',           10),
    ('IMAGE_REL_BASED_HIGH3ADJ',        11)]

RELOCATION_TYPE = dict(
    [(e[1], e[0]) for e in relocation_types]+relocation_types)


dll_characteristics = [
    ('IMAGE_LIBRARY_PROCESS_INIT',                     0x0001), # reserved
    ('IMAGE_LIBRARY_PROCESS_TERM',                     0x0002), # reserved
    ('IMAGE_LIBRARY_THREAD_INIT',                      0x0004), # reserved
    ('IMAGE_LIBRARY_THREAD_TERM',                      0x0008), # reserved
    ('IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA',       0x0020),
    ('IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE',          0x0040),
    ('IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY',       0x0080),
    ('IMAGE_DLLCHARACTERISTICS_NX_COMPAT',             0x0100),
    ('IMAGE_DLLCHARACTERISTICS_NO_ISOLATION',          0x0200),
    ('IMAGE_DLLCHARACTERISTICS_NO_SEH',                0x0400),
    ('IMAGE_DLLCHARACTERISTICS_NO_BIND',               0x0800),
    ('IMAGE_DLLCHARACTERISTICS_APPCONTAINER',          0x1000),
    ('IMAGE_DLLCHARACTERISTICS_WDM_DRIVER',            0x2000),
    ('IMAGE_DLLCHARACTERISTICS_GUARD_CF',              0x4000),
    ('IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE', 0x8000) ]

DLL_CHARACTERISTICS = dict(
    [(e[1], e[0]) for e in dll_characteristics]+dll_characteristics)

# Resource level
resource_level = ['ROOT', 'type', 'name/ID', 'language']
# Resource types
resource_type = [
    ('RT_CURSOR',          1),
    ('RT_BITMAP',          2),
    ('RT_ICON',            3),
    ('RT_MENU',            4),
    ('RT_DIALOG',          5),
    ('RT_STRING',          6),
    ('RT_FONTDIR',         7),
    ('RT_FONT',            8),
    ('RT_ACCELERATOR',     9),
    ('RT_RCDATA',          10),
    ('RT_MESSAGETABLE',    11),
    ('RT_GROUP_CURSOR',    12),
    ('RT_GROUP_ICON',      14),
    ('RT_VERSION',         16),
    ('RT_DLGINCLUDE',      17),
    ('RT_PLUGPLAY',        19),
    ('RT_VXD',             20),
    ('RT_ANICURSOR',       21),
    ('RT_ANIICON',         22),
    ('RT_HTML',            23),
    ('RT_MANIFEST',        24) ]

RESOURCE_TYPE = dict([(e[1], e[0]) for e in resource_type]+resource_type)


# Language definitions
lang = [
 ('LANG_NEUTRAL',       0x00),
 ('LANG_INVARIANT',     0x7f),
 ('LANG_AFRIKAANS',     0x36),
 ('LANG_ALBANIAN',      0x1c),
 ('LANG_ARABIC',        0x01),
 ('LANG_ARMENIAN',      0x2b),
 ('LANG_ASSAMESE',      0x4d),
 ('LANG_AZERI',         0x2c),
 ('LANG_BASQUE',        0x2d),
 ('LANG_BELARUSIAN',    0x23),
 ('LANG_BENGALI',       0x45),
 ('LANG_BULGARIAN',     0x02),
 ('LANG_CATALAN',       0x03),
 ('LANG_CHINESE',       0x04),
 ('LANG_CROATIAN',      0x1a),
 ('LANG_CZECH',         0x05),
 ('LANG_DANISH',        0x06),
 ('LANG_DIVEHI',        0x65),
 ('LANG_DUTCH',         0x13),
 ('LANG_ENGLISH',       0x09),
 ('LANG_ESTONIAN',      0x25),
 ('LANG_FAEROESE',      0x38),
 ('LANG_FARSI',         0x29),
 ('LANG_FINNISH',       0x0b),
 ('LANG_FRENCH',        0x0c),
 ('LANG_GALICIAN',      0x56),
 ('LANG_GEORGIAN',      0x37),
 ('LANG_GERMAN',        0x07),
 ('LANG_GREEK',         0x08),
 ('LANG_GUJARATI',      0x47),
 ('LANG_HEBREW',        0x0d),
 ('LANG_HINDI',         0x39),
 ('LANG_HUNGARIAN',     0x0e),
 ('LANG_ICELANDIC',     0x0f),
 ('LANG_INDONESIAN',    0x21),
 ('LANG_ITALIAN',       0x10),
 ('LANG_JAPANESE',      0x11),
 ('LANG_KANNADA',       0x4b),
 ('LANG_KASHMIRI',      0x60),
 ('LANG_KAZAK',         0x3f),
 ('LANG_KONKANI',       0x57),
 ('LANG_KOREAN',        0x12),
 ('LANG_KYRGYZ',        0x40),
 ('LANG_LATVIAN',       0x26),
 ('LANG_LITHUANIAN',    0x27),
 ('LANG_MACEDONIAN',    0x2f),
 ('LANG_MALAY',         0x3e),
 ('LANG_MALAYALAM',     0x4c),
 ('LANG_MANIPURI',      0x58),
 ('LANG_MARATHI',       0x4e),
 ('LANG_MONGOLIAN',     0x50),
 ('LANG_NEPALI',        0x61),
 ('LANG_NORWEGIAN',     0x14),
 ('LANG_ORIYA',         0x48),
 ('LANG_POLISH',        0x15),
 ('LANG_PORTUGUESE',    0x16),
 ('LANG_PUNJABI',       0x46),
 ('LANG_ROMANIAN',      0x18),
 ('LANG_RUSSIAN',       0x19),
 ('LANG_SANSKRIT',      0x4f),
 ('LANG_SERBIAN',       0x1a),
 ('LANG_SINDHI',        0x59),
 ('LANG_SLOVAK',        0x1b),
 ('LANG_SLOVENIAN',     0x24),
 ('LANG_SPANISH',       0x0a),
 ('LANG_SWAHILI',       0x41),
 ('LANG_SWEDISH',       0x1d),
 ('LANG_SYRIAC',        0x5a),
 ('LANG_TAMIL',         0x49),
 ('LANG_TATAR',         0x44),
 ('LANG_TELUGU',        0x4a),
 ('LANG_THAI',          0x1e),
 ('LANG_TURKISH',       0x1f),
 ('LANG_UKRAINIAN',     0x22),
 ('LANG_URDU',          0x20),
 ('LANG_UZBEK',         0x43),
 ('LANG_VIETNAMESE',    0x2a),
 ('LANG_GAELIC',        0x3c),
 ('LANG_MALTESE',       0x3a),
 ('LANG_MAORI',         0x28),
 ('LANG_RHAETO_ROMANCE',0x17),
 ('LANG_SAAMI',         0x3b),
 ('LANG_SORBIAN',       0x2e),
 ('LANG_SUTU',          0x30),
 ('LANG_TSONGA',        0x31),
 ('LANG_TSWANA',        0x32),
 ('LANG_VENDA',         0x33),
 ('LANG_XHOSA',         0x34),
 ('LANG_ZULU',          0x35),
 ('LANG_ESPERANTO',     0x8f),
 ('LANG_WALON',         0x90),
 ('LANG_CORNISH',       0x91),
 ('LANG_WELSH',         0x92),
 ('LANG_BRETON',        0x93) ]

LANG = dict(lang+[(e[1], e[0]) for e in lang])



FILE_ALIGNMENT_HARDCODED_VALUE = 0x200
FileAlignment_Warning = False # We only want to print the warning once
SectionAlignment_Warning = False # We only want to print the warning once


def retrieve_flags(flag_dict, flag_filter):
    """Read the flags from a dictionary and return them in a usable form.

    Will return a list of (flag, value) for all flags in "flag_dict"
    matching the filter "flag_filter".
    """

    return [(f[0], f[1]) for f in list(flag_dict.items()) if
            isinstance(f[0], (str, bytes)) and f[0].startswith(flag_filter)]


def set_flags(obj, flag_field, flags):
    """Will process the flags and set attributes in the object accordingly.

    The object "obj" will gain attributes named after the flags provided in
    "flags" and valued True/False, matching the results of applying each
    flag value from "flags" to flag_field.
    """
    for flag in flags:
        if flag[1] & flag_field:
            #setattr(obj, flag[0], True)
            obj.__dict__[flag[0]] = True
        else:
            #setattr(obj, flag[0], False)
            obj.__dict__[flag[0]] = False



STRUCT_SIZEOF_TYPES = {
    'x': 1, 'c': 1, 'b': 1, 'B': 1,
    'h': 2, 'H': 2,
    'i': 4, 'I': 4, 'l': 4, 'L': 4, 'f': 4,
    'q': 8, 'Q': 8, 'd': 8,
    's': 1}

# IMAGE_LOAD_CONFIG_DIRECTORY constants
IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK = 0xf0000000
IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT = 28


class PeMemory(object):
    """A Portable Executable on memory representation.

        This class provides access to most of the information in a memory PE.

        It expects to be supplied PE data to process and an optional argument
        'fast_load' (False by default) which controls whether to load all the
        directories information, which can be quite time consuming.

        The data must be availabel in a buffer:

        pe = pememory.PeMemory(module_dll_data)

        The "fast_load" can be set to a default by setting its value in the
        module itself by means, for instance, of a "pefile.fast_load = True".
        That will make all the subsequent instances not to load the
        whole PE structure. The "full_load" method can be used to parse
        the missing data at a later stage.

        Basic headers information will be available in the attributes:

        DOS_HEADER
        NT_HEADERS
        FILE_HEADER
        OPTIONAL_HEADER

        All of them will contain among their attributes the members of the
        corresponding structures as defined in WINNT.H

        The raw data corresponding to the header (from the beginning of the
        file up to the start of the first section) will be available in the
        instance's attribute 'header' as a string.

        The sections will be available as a list in the 'sections' attribute.
        Each entry will contain as attributes all the structure's members.

        Directory entries will be available as attributes (if they exist):
        (no other entries are processed at this point)

        DIRECTORY_ENTRY_EXPORT (ExportDirData instance)
        DIRECTORY_ENTRY_IMPORT (list of ImportDescData instances)
        DIRECTORY_ENTRY_RESOURCE (ResourceDirData instance)
        DIRECTORY_ENTRY_EXCEPTION (Array of function table entries, .pdata)
        DIRECTORY_ENTRY_CERTIFICATE
        DIRECTORY_ENTRY_BASERELOC (list of BaseRelocationData instances)
        DIRECTORY_ENTRY_DEBUG (list of DebugData instances)
        DIRECTORY_ENTRY_ARCHITECTURE
        DIRECTORY_ENTRY_GLOBAL_PTR
        DIRECTORY_ENTRY_TLS
        DIRECTORY_ENTRY_LOAD_CONFIG_TABLE
        DIRECTORY_ENTRY_BOUND_IMPORT (list of BoundImportData instances)
        DIRECTORY_ENTRY_IAT
        DIRECTORY_ENTRY_DELAY_IMPORT_DESCRIPTOR
        DIRECTORY_ENTRY_CLR_NET


        The following dictionary attributes provide ways of mapping different
        constants. They will accept the numeric value and return the string
        representation and the opposite, feed in the string and get the
        numeric constant:

        DIRECTORY_ENTRY
        IMAGE_CHARACTERISTICS
        SECTION_CHARACTERISTICS
        DEBUG_TYPE
        SUBSYSTEM_TYPE
        MACHINE_TYPE
        RELOCATION_TYPE
        RESOURCE_TYPE
        LANG
        SUBLANG
        """

    # Common structures
    __IMAGE_THUNK_DATA_format__ = ('IMAGE_THUNK_DATA',
                                   ('I,ForwarderString,Function,Ordinal,AddressOfData',))

    __IMAGE_THUNK_DATA64_format__ = ('IMAGE_THUNK_DATA',
                                     ('Q,ForwarderString,Function,Ordinal,AddressOfData',))

    __ADDRESS_ELEMENT_format__ = ('ADDRESS_ELEMENT',
                                  ('I,Address',))

    __ADDRESS_ELEMENT64_format__ = ('ADDRESS_ELEMENT',
                                  ('Q,Address',))

    __ADDRESS_format__ = ('ADDRESS',
                          ('I,Address',))

    __ORDINAL_format__ = ('ORDINAL',
                          ('H,Ordinal',))
    #
    # Format specifications for PE structures.
    #

    __IMAGE_DOS_HEADER_format__ = ('IMAGE_DOS_HEADER',
                                   ('2s,e_magic',
                                    'H,e_cblp',
                                    'H,e_cp',
                                    'H,e_crlc',
                                    'H,e_cparhdr',
                                    'H,e_minalloc',
                                    'H,e_maxalloc',
                                    'H,e_ss',
                                    'H,e_sp',
                                    'H,e_csum',
                                    'H,e_ip',
                                    'H,e_cs',
                                    'H,e_lfarlc',
                                    'H,e_ovno',
                                    '8s,e_res',
                                    'H,e_oemid',
                                    'H,e_oeminfo',
                                    '20s,e_res2',
                                    'I,e_lfanew'))

    __IMAGE_NT_HEADERS_format__ = ('IMAGE_NT_HEADERS', ('4s,Signature',))

    __IMAGE_FILE_HEADER_format__ = ('IMAGE_FILE_HEADER',
                                    ('H,Machine',
                                     'H,NumberOfSections',
                                     'I,TimeDateStamp',
                                     'I,PointerToSymbolTable',
                                     'I,NumberOfSymbols',
                                     'H,SizeOfOptionalHeader',
                                     'H,Characteristics'))

    __IMAGE_OPTIONAL_HEADER_format__ = ('IMAGE_OPTIONAL_HEADER',
                                        ('H,Magic',
                                         'B,MajorLinkerVersion',
                                         'B,MinorLinkerVersion',
                                         'I,SizeOfCode',
                                         'I,SizeOfInitializedData',
                                         'I,SizeOfUninitializedData',
                                         'I,AddressOfEntryPoint',
                                         'I,BaseOfCode',
                                         'I,BaseOfData',
                                         'I,ImageBase',
                                         'I,SectionAlignment',
                                         'I,FileAlignment',
                                         'H,MajorOperatingSystemVersion',
                                         'H,MinorOperatingSystemVersion',
                                         'H,MajorImageVersion',
                                         'H,MinorImageVersion',
                                         'H,MajorSubsystemVersion',
                                         'H,MinorSubsystemVersion',
                                         'I,Reserved1', 'I,SizeOfImage',
                                         'I,SizeOfHeaders',
                                         'I,CheckSum', 'H,Subsystem',
                                         'H,DllCharacteristics',
                                         'I,SizeOfStackReserve',
                                         'I,SizeOfStackCommit',
                                         'I,SizeOfHeapReserve',
                                         'I,SizeOfHeapCommit',
                                         'I,LoaderFlags',
                                         'I,NumberOfRvaAndSizes'))

    __IMAGE_OPTIONAL_HEADER64_format__ = ('IMAGE_OPTIONAL_HEADER64',
                                          ('H,Magic',
                                           'B,MajorLinkerVersion',
                                           'B,MinorLinkerVersion',
                                           'I,SizeOfCode',
                                           'I,SizeOfInitializedData',
                                           'I,SizeOfUninitializedData',
                                           'I,AddressOfEntryPoint',
                                           'I,BaseOfCode',
                                           'Q,ImageBase',
                                           'I,SectionAlignment',
                                           'I,FileAlignment',
                                           'H,MajorOperatingSystemVersion',
                                           'H,MinorOperatingSystemVersion',
                                           'H,MajorImageVersion',
                                           'H,MinorImageVersion',
                                           'H,MajorSubsystemVersion',
                                           'H,MinorSubsystemVersion',
                                           'I,Reserved1',
                                           'I,SizeOfImage',
                                           'I,SizeOfHeaders',
                                           'I,CheckSum', 'H,Subsystem',
                                           'H,DllCharacteristics',
                                           'Q,SizeOfStackReserve',
                                           'Q,SizeOfStackCommit',
                                           'Q,SizeOfHeapReserve',
                                           'Q,SizeOfHeapCommit',
                                           'I,LoaderFlags',
                                           'I,NumberOfRvaAndSizes'))

    __IMAGE_DATA_DIRECTORY_format__ = ('IMAGE_DATA_DIRECTORY',
                                       ('I,VirtualAddress',
                                        'I,Size'))

    __IMAGE_EXPORT_DIRECTORY_format__ = ('IMAGE_EXPORT_DIRECTORY',
                                         ('I,Characteristics',
                                          'I,TimeDateStamp',
                                          'H,MajorVersion',
                                          'H,MinorVersion',
                                          'I,Name',
                                          'I,Base',
                                          'I,NumberOfFunctions',
                                          'I,NumberOfNames',
                                          'I,AddressOfFunctions',
                                          'I,AddressOfNames',
                                          'I,AddressOfNameOrdinals'))

    __EXPORT_ADDRESS_TABLE_EXPORT_format__ = ('EXPORT_ADDRESS_TABLE_EXPORT',
                                              ('I,Export',))

    __EXPORT_ADDRESS_TABLE_FORWARDER_format__ = ('EXPORT_ADDRESS_TABLE_FORWARDER',
                                                 ('I,Forwarder',))

    __IMAGE_IMPORT_DESCRIPTOR_format__ = ('IMAGE_IMPORT_DESCRIPTOR',
                                          ('I,OriginalFirstThunk,Characteristics',
                                           'I,TimeDateStamp',
                                           'I,ForwarderChain',
                                           'I,Name',
                                           'I,FirstThunk'))

    '''__IMAGE_IMPORT_LOOKUP_TABLE_format__ = ('IMAGE_IMPORT_LOOKUP_TABLE',
                                            ('I,ImportLookup',))

    __IMAGE_IMPORT_LOOKUP_TABLE64_format__ = ('IMAGE_IMPORT_LOOKUP_TABLE64',
                                              ('Q,ImportLookup'))'''

    __IMAGE_IMPORT_BY_NAME_format__ = ('IMAGE_IMPORT_BY_NAME_format',
                                       ('H,Hint',))

    __IMAGE_RESOURCE_DIRECTORY_format__ = ('IMAGE_RESOURCE_DIRECTORY',
                                           ('I,Characteristics',
                                            'I,TimeDateStamp',
                                            'H,MajorVersion',
                                            'H,MinorVersion',
                                            'H,NumberOfNamedEntries',
                                            'H,NumberOfIdEntries'))

    __IMAGE_RESOURCE_DIRECTORY_ENTRY_format__ = ('TypeID',
                                                 ('I,NameID',
                                                  'I,OffsetToData'))

    __IMAGE_RESOURCE_DATA_ENTRY_format__ = ('IMAGE_RESOURCE_DATA_ENTRY',
                                            ('I,OffsetToData',
                                             'I,Size',
                                             'I,CodePage',
                                             'I,Reserved'))

    __RT_STRING_format__ = ('RT_STRING',
                            ('H,length',))

    __VS_VERSIONINFO_format_1__ = ('VS_VERSIONINFO_1',
                                 ('H,wLength',
                                  'H,wValueLength',
                                  'H,wType',
                                  's,szKey'))

    __VS_FIXEDFILEINFO_format__ = ('VS_FIXEDFILEINFO',
                                   ('I,dwSignature',
                                    'I,dwStrucVersion',
                                    'I,dwFileVersionMS',
                                    'I,dwFileVersionLS',
                                    'I,dwProductVersionMS',
                                    'I,dwProductVersionLS',
                                    'I,dwFileFlagsMask',
                                    'I,dwFileFlags',
                                    'I,dwFileOS',
                                    'I,dwFileType',
                                    'I,dwFileSubtype',
                                    'I,dwFileDateMS',
                                    'I,dwFileDateLS'))

    __VS_VERSIONINFO_format_2__ = ('VS_VERSIONINFO_2',
                                   's,Padding2')

    __StringFileInfo_format__ = ('StringFileInfo',
                                 ('H,Length',
                                  'H,ValueLength',
                                  'H,Type',
                                  's,szKey'))

    __StringTable_format__ = ('StringTable',
                              ('H,Length',
                               'H,ValueLength',
                               'H,Type',
                               's,szKey'))

    __String_format__ = ('String',
                         ('H,Length',
                          'H,ValueLength',
                          'H,Type',
                          's,szKey',
                          's,Value'))

    __VarFileInfo_format__ = ('VarFileInfo',
                              ('H,Length',
                               'H,ValueLength',
                               'H,Type',
                               's,szKey'))

    __Var_format__ = ('Var',
                      ('H,Length',
                       'H,ValueLength',
                       'H,Type',
                       's,szKey',
                       's,Value'))

    __GRPICONDIR_format__ = ('GRPICONDIR',
                             ('H,idReserved',
                              'H,idType',
                              'H,idCount'))

    __GRPICONDIRENTRY_format__ = ('GRPICONDIRENTRY',
                                  ('B,bWidth',
                                   'B,bHeight',
                                   'B,bColorCount',
                                   'B,bReserved',
                                   'H,wPlanes',
                                   'H,wBitCount',
                                   'I,dwByteInRes',
                                   'H,nId'))

    __RT_MANIFEST_format__ = ('RT_MANIFEST', 's,manifest')

    __RUNTIME_FUNCTION_format__ = ('RUNTIME_FUNCTION',
                                   ('I,FunctionStart',
                                    'I,FunctionEnd',
                                    'I,UnwindInfo'))

    __UNWIND_INFO_format_1__ = ('UNWIND_INFO',
                                ('B,Version_Flags',
                                 'B,SizeOfProlog',
                                 'B,CountOfUnwindCode',
                                 'B,FrameRegister_Offset'))

    __UNWIND_CODE_format__ = ('UNWIND_CODE',
                              ('B,CodeOffset',
                               'B,UnwindOpOpinfo_FrameOffset'))

    __UNWIND_INFO_format_2__ = ('UNWIND_INFO_2',
                                ('I,ExceptionHandler,FunctionEntry',
                                 'I'))

    __WIN_CERTIFICATE_format__ = ('WIN_CERTIFICATE',
                                  ('I,dwLength',
                                   'H,wRevision',
                                   'H,wCertificationType',)
                                  )

    __IMAGE_BASE_RELOCATION_format__ = ('IMAGE_BASE_RELOCATION',
                                        ('I,VirtualAddress',
                                         'I,SizeOfBlock'))

    __IMAGE_TYPEOFFSET_format__ = ('IMAGE_TYPEOFFSET',
                                   ('H,TypeOffset',))

    __IMAGE_DEBUG_DIRECTORY_format__ = ('IMAGE_DEBUG_DIRECTORY',
                                        ('I,Characteristics',
                                         'I,TimeDateStamp',
                                         'H,MajorVersion',
                                         'H,MinorVersion',
                                         'I,Type',
                                         'I,SizeOfData',
                                         'I,AddressOfRawData',
                                         'I,PointerToRawData'))

    __COPYRIGHT_format__ = ('Copyright', 's,String')

    __IMAGE_TLS_DIRECTORY_format__ = ('IMAGE_TLS_DIRECTORY',
                                      ('I,StartAddressOfRawData',
                                       'I,EndAddressOfRawData',
                                       'I,AddressOfIndex',
                                       'I,AddressOfCallBacks',
                                       'I,SizeOfZeroFill',
                                       'I,Characteristics'))

    __IMAGE_TLS_DIRECTORY64_format__ = ('IMAGE_TLS_DIRECTORY',
                                        ('Q,StartAddressOfRawData',
                                         'Q,EndAddressOfRawData',
                                         'Q,AddressOfIndex',
                                         'Q,AddressOfCallBacks',
                                         'I,SizeOfZeroFill',
                                         'I,Characteristics'))

    __IMAGE_TLS_CALLBACK_format__ = ('IMAGE_TLS_CALLBACK', ('I,Callback',))

    __IMAGE_TLS_CALLBACK64_format__ = ('IMAGE_TLS_CALLBACK', ('Q,Callback',))

    __IMAGE_LOAD_CONFIG_DIRECTORY_format__ = ('IMAGE_LOAD_CONFIG_DIRECTORY',
                                              ('I,Size',
                                               'I,TimeDateStamp',
                                               'H,MajorVersion',
                                               'H,MinorVersion',
                                               'I,GlobalFlagsClear',
                                               'I,GlobalFlagsSet',
                                               'I,CriticalSectionDefaultTimeout',))

    __IMAGE_LOAD_CONFIG_CODE_INTEGRITY_format__ = ('IMAGE_LOAD_CONFIG_CODE_INTEGRITY',
                                              ('H,Flag',
                                               'H,Catalog',
                                               'I,CatalogOffset',
                                               'I,Reserved',))


    '''typedef https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/km/ntimage.h
    struct
    _IMAGE_LOAD_CONFIG_CODE_INTEGRITY
    {
        USHORT
    Flags; // Flags
    to
    indicate if CI
    information is available, etc.
        USHORT
    Catalog; // 0xFFFF
    means
    not available
    ULONG
    CatalogOffset;
    ULONG
    Reserved; // Additional
    bitmask
    to
    be
    defined
    later
    }'''

    '''I,DeCommitFreeBlockThreshold',
                                               'I,DeCommitTotalFreeThreshold',
                                               'I,LockPrefixTable',
                                               'I,MaximumAllocationSize',
                                               'I,VirtualMemoryThreshold',
                                               'I,ProcessHeapFlags',
                                               'I,ProcessAffinityMask',
                                               'H,CSDVersion',
                                               'H,Reserved1',
                                               'I,EditList',
                                               'I,SecurityCookie',
                                               'I,SEHandlerTable',
                                               'I,SEHandlerCount',
                                               'I,GuardCFCheckFunctionPointer',
                                               'I,Reserved2',
                                               'I,GuardCFFunctionTable',
                                               'I,GuardCFFunctionCount',
                                               'I,GuardFlags'))'''

    __IMAGE_LOAD_CONFIG_DIRECTORY64_format__ = ('IMAGE_LOAD_CONFIG_DIRECTORY',
                                                ('I,Size',
                                                 'I,TimeDateStamp',
                                                 'H,MajorVersion',
                                                 'H,MinorVersion',
                                                 'I,GlobalFlagsClear',
                                                 'I,GlobalFlagsSet',
                                                 'I,CriticalSectionDefaultTimeout',
                                                 'Q,DeCommitFreeBlockThreshold',
                                                 'Q,DeCommitTotalFreeThreshold',
                                                 'Q,LockPrefixTable',
                                                 'Q,MaximumAllocationSize',
                                                 'Q,VirtualMemoryThreshold',
                                                 'Q,ProcessAffinityMask',
                                                 'I,ProcessHeapFlags',
                                                 'H,CSDVersion',
                                                 'H,Reserved1',
                                                 'Q,EditList',
                                                 'Q,SecurityCookie',
                                                 'Q,SEHandlerTable',
                                                 'Q,SEHandlerCount',
                                                 'Q,GuardCFCheckFunctionPointer',
                                                 'Q,Reserved2',
                                                 'Q,GuardCFFunctionTable',
                                                 'Q,GuardCFFunctionCount',
                                                 'I,GuardFlags'))

    __HandlerTable_format__ = ('HandlerTable', 'I,Handler')

    __IMAGE_BOUND_IMPORT_DESCRIPTOR_format__ = ('IMAGE_BOUND_IMPORT_DESCRIPTOR',
                                                ('I,TimeDateStamp',
                                                 'H,OffsetModuleName',
                                                 'H,NumberOfModuleForwarderRefs'))

    __IMAGE_DELAY_IMPORT_DESCRIPTOR_format__ = ('IMAGE_DELAY_IMPORT_DESCRIPTOR',
                                                ('I,grAttrs',
                                                 'I,szName',
                                                 'I,phmod',
                                                 'I,pIAT',
                                                 'I,pINT',
                                                 'I,pBoundIAT',
                                                 'I,pUnloadIAT',
                                                 'I,dwTimeStamp'))

    __IMAGE_COR20_HEADER_format__ = ('IMAGE_COR20_HEADER',
                                     ('I,cb',
                                      'H,MajorRuntimeVersion',
                                      'H,MinorRuntimeVersion',
                                      'I,MetaDataVirtualAddress',
                                      'I,MetaDataSize',
                                      'I,Flags',
                                      'I,EtryPointToken,EtryPointRVA',
                                      'I,ResourcesVirtualAddress',
                                      'I,ResourcesSize',
                                      'I,StrongNameSignatureVirtualAddress',
                                      'I,StrongNameSignaturesize',
                                      'I,CodeManagerTableVirtualAddress',
                                      'I,CodeManagerTableSize',
                                      'I,VTableFixupsVirtualAddress',
                                      'I,VTableFixupsSize',
                                      'I,ExportAddressTableJumpsVirtualAddress',
                                      'I,ExportAddressTableJumpsSize',
                                      'I,ManagedNativeHeaderVirtualAddress',
                                      'I,ManagedNativeHeaderSize'))

    __METADATAHDR_format__ = ('METADATAHDR',
                              ('I,Signature',
                               'H,MajorVersion',
                               'H,MinorVersion',
                               'I,Reserved',
                               'I,VersionLength'))

    __METADATAHDR2_format__ = ('METADATAHDR2',
                               ('H,Flags',
                               'H,Streams'))

    __METADATASTRAMHDR_format__ = ('METADATASTRAMHDR',
                                   ('I,offset',
                                    'I,size'))

    __METADATATABLESHDR_format__ = ('METADATATABLESHDR',
                                    ('I,Reserved1',
                                     'B,MajorVersion',
                                     'B,MinorVersion',
                                     'H,HeapOffsetSizes',
                                     'B,Reserved2',
                                     'Q,MaskValid',
                                     'Q,MaskStored',
                                     'I,NumRows'))

    __MODULETABLE_format__ = ('MODULETABLE',
                              ('H,Generator',
                               'H,Name',
                               'H,Mvid',
                               'H,EncId',
                               'H,EncBaseId'))

    __TYPEEREFTABLE_format__ = ('TYPEEREFTABLE',
                                ('I,Flags',
                                 'H,Name',
                                 'H,Namespace',
                                 'H,Extends',
                                 'H,FieldList',
                                 'H,MethodList'))

    __METHODDEFTABLE_format__ = ('METHODDEFTABLE',
                                 ('I,RVA',
                                  'H,ImplFlags',
                                  'H,Flags',
                                  'H,Name',
                                  'H,Signature',
                                  'H,ParamList'))

    __MEMBERREFTABLE_format__ = ('MEMBERREFTABLE',
                                 ('H.Class',
                                  'H,Name',
                                  'H,Signature'))

    __CUSTOMATTRIBUTETABLE_format__ = ('CUSTOMATTRIBUTETABLE',
                                       ('H,Parent',
                                        'H,Type',
                                        'H,Value'))

    __ASSEMBLYTABLE_format__ = ('ASSEMBLYTABLE',
                                ('I,HashAlgId',
                                 'H,MajorVersion',
                                 'H,MinorVersion',
                                 'H,BuildVersion',
                                 'H,RevisonNumber',
                                 'I,Flags',
                                 'H,PublicKey',
                                 'H,Name',
                                 'H,Culture'))

    __ASSEMBYREFTABLE_format__ = ('ASSEMBLYREFTABLE',
                                  ('H,MajorVersion',
                                   'H,MinorVersion',
                                   'H,BuildNumber',
                                   'H,RevisonNumber',
                                   'I,Flags',
                                   'H,PublickKeyOrTocken',
                                   'H,Name',
                                   'H,Culture',
                                   'H,HashValue'))

    __IMAGE_SECTION_HEADER_format__ = ('IMAGE_SECTION_HEADER',
                                       ('8s,Name',
                                        'I,VirtualSize',
                                        'I,VirtualAddress',
                                        'I,SizeOfRawData',
                                        'I,PointerToRawData',
                                        'I,PointerToRelocations',
                                        'I,PointerToLinenumbers',
                                        'H,NumberOfRelocations',
                                        'H,NumberOfLinenumbers',
                                        'I,Characteristics'))

    __IMAGE_BASE_RELOCATION_ENTRY_format__ = ('IMAGE_BASE_RELOCATION_ENTRY', ('H,Data',))

    __IMAGE_BOUND_FORWARDER_REF_format__ = ('IMAGE_BOUND_FORWARDER_REF',
                                            ('I,TimeDateStamp',
                                             'H,OffsetModuleName',
                                             'H,Reserved'))

    def __init__(self, data, base_address, valid_pages):

        self.sections = []
        self.__warnings = []
        self.__data__ = data
        self.__size__ = len(data)
        self.__visited__ = [UNKW_BYTE] * self.__size__
        self.__valid_pages__ = valid_pages

        if data is None:
            raise ValueError('Must supply data')

        self.__base_address__ = base_address

        # This list will keep track of all the structures created.
        # That will allow for an easy iteration through the list
        # in order to save the modifications made
        #self.__structures__ = []

        try:
            self.__parse__()
        except:
            self.close()
            raise

    # Deal with __visited__ structure
    def set_visited(self, pointer, size, tag, force=False):
        for index in range(pointer, pointer+size):
            if self.__visited__[index] == UNKW_BYTE or self.__visited__[index] == tag or force:
                self.__visited__[index] = tag
            else:
                # ToDelete: Duplication error
                if self.__visited__[index] == NULL_PAGE or tag==JUMPED_BYTE:
                    raise PeMemError(self.__visited__[index], 'Visiting space previously visited', pointer)

                else:
                    raise PeMemError(self.__visited__[index], 'Visiting space previously visited', pointer)

    def valid_pages(self):
        for page_offset in range(0, self.__size__, PAGE_SIZE):
            if not self.__valid_pages__[page_offset/PAGE_SIZE]:
                self.set_visited(page_offset, PAGE_SIZE, NULL_PAGE)

    def __unpack_data__(self, format, data, offset, byte_mark, force=False):
        """Apply structure format to raw data.

        Returns and unpacked structure object if successful, None otherwise.
        """

        structure = Structure(format, offset=offset)
        try:
            structure.__unpack__(data)
            self.set_visited(offset, structure.sizeof(), byte_mark, force)
        except PEFormatError as err:
            self.__warnings.append(
                'Corrupt header "{0}" at file offset {1}. Exception: {2}'.format(
                    format[0], offset, err))
            return None

        # self.__structures__.append(structure)

        return structure

    def __unpack_section__(self, format, data, offset, byte_mark):
        """Apply structure format to raw data.

        Returns and unpacked structure object if successful, None otherwise.
        """

        structure = SectionStructure(format, offset=offset)

        try:
            structure.__unpack__(data)
            self.set_visited(offset, structure.sizeof(), byte_mark)
        except PEFormatError as err:
            self.__warnings.append(
                'Corrupt header "{0}" at file offset {1}. Exception: {2}'.format(
                    format[0], offset, err))
            return None
        # self.__structures__.append(structure)
        return structure

    @staticmethod
    def all_zero(page):
        for byte in page:
            if ord(byte) != 0:
                return False
        return True

    def close(self):
        del self.__data__
        del self.__visited__

    '''def dump_section(self, section_name):
        if section_name == 'header': 
            return self.__data__[0:self.sections[0].VirtualAddress]
        else:
            for section in self.sections:
                if section.Name == section_name:
                    return section.data
            return None'''

    def __parse__(self):
        """Parse a Portable Executable file.

        Loads a PE, parsing all its structures and making them available
        through the instance's attributes.
        """

        self.valid_pages()

        if len(self.__data__[:64]) != 64:
            raise PEFormatError('Unable to read the DOS Header, possibly a truncated file.')

        self.DOS_HEADER = self.__unpack_data__(
            self.__IMAGE_DOS_HEADER_format__,
            self.__data__[:64], 0, DOS_HEADER_BYTE)

        if self.DOS_HEADER.e_magic == IMAGE_DOSZM_SIGNATURE:
            raise PEFormatError('Probably a ZM Executable (not a PE file).')
        if not self.DOS_HEADER or self.DOS_HEADER.e_magic != IMAGE_DOS_SIGNATURE:
            raise PEFormatError('DOS Header magic not found.')

        # OC Patch:
        # Check for sane value in e_lfanew
        #
        if self.DOS_HEADER.e_lfanew > len(self.__data__):
            raise PEFormatError('Invalid e_lfanew value, probably not a PE file')

        self.DOS_SEGMENT = self.__data__[64:self.DOS_HEADER.e_lfanew]
        self.set_visited(64, self.DOS_HEADER.e_lfanew-64, DOS_SEGMENT_BYTE)



        nt_header_offset = self.DOS_HEADER.e_lfanew

        self.NT_HEADERS = self.__unpack_data__(
            self.__IMAGE_NT_HEADERS_format__,
            self.__data__[nt_header_offset:nt_header_offset + 4],
            nt_header_offset, NT_HEADER_BYTE)

        # We better check the signature right here, before the file screws
        # around with sections:
        # OC Patch:
        # Some malware will cause the Signature value to not exist at all
        if not self.NT_HEADERS or not self.NT_HEADERS.Signature:
            raise PEFormatError('NT Headers not found.')

        if self.NT_HEADERS.Signature[:2] == IMAGE_NE_SIGNATURE:
            raise PEFormatError('Invalid NT Headers signature. Probably a NE file')
        if self.NT_HEADERS.Signature[:2] == IMAGE_LE_SIGNATURE:
            raise PEFormatError('Invalid NT Headers signature. Probably a LE file')
        if self.NT_HEADERS.Signature[:2] == IMAGE_LX_SIGNATURE:
            raise PEFormatError('Invalid NT Headers signature. Probably a LX file')
        if self.NT_HEADERS.Signature[:2] == IMAGE_TE_SIGNATURE:
            raise PEFormatError('Invalid NT Headers signature. Probably a TE file')
        if self.NT_HEADERS.Signature != IMAGE_NT_SIGNATURE:
            raise PEFormatError('Invalid NT Headers signature.')

        file_header_offset = nt_header_offset + 4
        self.NT_HEADERS.FILE_HEADER = self.__unpack_data__(
            self.__IMAGE_FILE_HEADER_format__,
            self.__data__[file_header_offset:file_header_offset+20],
            file_header_offset, FILE_HEADER_BYTE)

        if not self.NT_HEADERS.FILE_HEADER:
            raise PEFormatError('File Header missing')

        '''# Set the image's flags according the the Characteristics member
        image_flags = retrieve_flags(IMAGE_CHARACTERISTICS, 'IMAGE_FILE_')
        set_flags(self.NT_HEADERS.FILE_HEADER, self.NT_HEADERS.FILE_HEADER.Characteristics, image_flags)'''

        optional_header_offset = file_header_offset + self.NT_HEADERS.FILE_HEADER.sizeof()

        self.NT_HEADERS.OPTIONAL_HEADER = self.__unpack_data__(
            self.__IMAGE_OPTIONAL_HEADER_format__,
            # Read up to 256 bytes to allow creating a copy of too much data
            self.__data__[optional_header_offset:optional_header_offset + 0x60],
            optional_header_offset, OPTIONAL_HEADER_BYTE)

        if self.NT_HEADERS.OPTIONAL_HEADER.Magic == OPTIONAL_HEADER_MAGIC_PE_PLUS:
            self.NT_HEADERS.OPTIONAL_HEADER = self.__unpack_data__(
                self.__IMAGE_OPTIONAL_HEADER64_format__,
                # Read up to 256 bytes to allow creating a copy of too much data
                self.__data__[optional_header_offset:optional_header_offset + 0x70],
                optional_header_offset, OPTIONAL_HEADER_BYTE, True)

        # Note: location of sections can be controlled from PE header:

        data_directories_offset = optional_header_offset + self.NT_HEADERS.OPTIONAL_HEADER.sizeof()
        self.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY = []
        for directory_index in range(self.NT_HEADERS.OPTIONAL_HEADER.NumberOfRvaAndSizes):

            data_directory_offset = data_directories_offset + directory_index * 8
            dir_entry = self.__unpack_data__(
                self.__IMAGE_DATA_DIRECTORY_format__, self.__data__[data_directory_offset:data_directory_offset + 8],
                data_directory_offset, DATA_DIRECTORY_BYTE)

            if dir_entry is None:
                break
            try:
                dir_entry.name = DIRECTORY_ENTRY[directory_index]
            except (KeyError, AttributeError):
                pass

            self.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY.append(dir_entry)
        del directory_index, dir_entry, data_directory_offset

        # The NumberOfRvaAndSizes is sanitized to stay within
        # reasonable limits so can be casted to an int
        #
        if self.NT_HEADERS.OPTIONAL_HEADER.NumberOfRvaAndSizes > 0x10:
            self.__warnings.append('Suspicious NumberOfRvaAndSizes in the Optional Header. '
                                   'Normal values are never larger than 0x10, the value is: 0x%x'
                                   .format(self.NT_HEADERS.OPTIONAL_HEADER.NumberOfRvaAndSizes))

        section_headers_offset = data_directories_offset + 8 * self.NT_HEADERS.OPTIONAL_HEADER.NumberOfRvaAndSizes

        end_section_headers_offset = self.parse_sections(section_headers_offset)

        VirtualAddressPointers = [s.VirtualAddress for s in self.sections]
        del s

        if len(VirtualAddressPointers) > 0:
            lowest_section_offset = min(VirtualAddressPointers)
        else:
            lowest_section_offset = None
        del VirtualAddressPointers


        # Check whether the entry point lies within a section
        #
        if self.NT_HEADERS.OPTIONAL_HEADER.AddressOfEntryPoint is not None:

            # Check whether the entry point lies within the file
            #
            if self.NT_HEADERS.OPTIONAL_HEADER.AddressOfEntryPoint > len(self.__data__):
                self.__warnings.append(
                    'Possibly corrupt file. AddressOfEntryPoint lies outside the file. '
                    'AddressOfEntryPoint: 0x%x' %
                    self.NT_HEADERS.OPTIONAL_HEADER.AddressOfEntryPoint)

        else:

            self.__warnings.append(
                'AddressOfEntryPoint lies outside the sections\' boundaries. '
                'AddressOfEntryPoint: 0x%x' %
                self.NT_HEADERS.OPTIONAL_HEADER.AddressOfEntryPoint)

        self.parse_data_directories()
        return True

    def parse_sections(self, offset):
        """Fetch the PE sections.

        The sections will be readily available in the "sections" attribute.
        Its attributes will contain all the section information plus "data"
        a buffer containing the section's data.

        The "Characteristics" member will be processed and attributes
        representing the section characteristics (with the 'IMAGE_SCN_'
        string trimmed from the constant's names) will be added to the
        section instance.

        Refer to the SectionStructure class for additional info.
        """

        self.sections = []
        for section_index in range(self.NT_HEADERS.FILE_HEADER.NumberOfSections):
            section_offset = offset + section_index * 0x28
            section = self.__unpack_section__(self.__IMAGE_SECTION_HEADER_format__,
                                           self.__data__[section_offset: section_offset + 0x28],
                                           section_offset, SECTION_HEADER_BYTE)

            if section.VirtualAddress > len(self.__data__):
                self.__warnings.append(
                    'Error parsing section {0}. VirtualAddress points beyond the end of the memory.'
                        .format(section_index))

            if section.VirtualSize+section.VirtualAddress > len(self.__data__):
                self.__warnings.append(
                    'Error parsing section {0}. VirtualSize is larger than memory.'.format(section_index))

            if (self.NT_HEADERS.OPTIONAL_HEADER.FileAlignment != 0 and
                    (section.PointerToRawData % self.NT_HEADERS.OPTIONAL_HEADER.FileAlignment) != 0):
                self.__warnings.append('Error parsing section {0}. PointerToRawData should normally be a multiple of '
                                       'FileAlignment, this might imply the file is trying to confuse tools which parse '
                                       'this incorrectly.'.format(section_index))

            section.__pe__ = self
            try:
                # Identifying padding space at end of sections
                if all_zeros(section.data, min(section.SizeOfRawData, section.VirtualSize)):
                        self.set_visited(section.VirtualAddress + min(section.SizeOfRawData, section.VirtualSize),
                        section.real_size - min(section.SizeOfRawData, section.VirtualSize), END_PAGE_PADDING)

                elif all_zeros(section.data, max(section.SizeOfRawData, section.VirtualSize)):
                    self.set_visited(section.VirtualAddress + max(section.SizeOfRawData, section.VirtualSize),
                        section.real_size - max(section.SizeOfRawData, section.VirtualSize), END_PAGE_PADDING)
            except PeMemError as e:
                if e.code == NULL_PAGE:
                    pass
                else:
                    raise e

            self.sections.append(section)
        del section_index
        self.sections.sort(key=lambda a: a.VirtualAddress)

        # Identifying padding space at end of pe header
        if all_zeros(self.__data__[self.sections[0].PointerToRawData: self.sections[0].VirtualAddress]):
            self.set_visited(self.sections[0].PointerToRawData,
                             self.sections[0].VirtualAddress - self.sections[0].PointerToRawData, END_PAGE_PADDING)


        # Creating a virtual section for header
        header_section = SectionStructure(self.__IMAGE_SECTION_HEADER_format__, 0)
        header_section.Name = 'header'
        header_section.PointerToRawData = 0
        header_section.VirtualAddress = 0
        header_section.SizeOfRawData = self.sections[0].PointerToRawData
        header_section.VirtualSize = self.sections[0].VirtualAddress
        header_section.__pe__ = self
        self.sections.append(header_section)

        # Creating a virtual PE section
        pe_section = SectionStructure(self.__IMAGE_SECTION_HEADER_format__, 0)
        pe_section.Name = 'PE'
        pe_section.PointerToRawData = None
        pe_section.VirtualAddress = 0
        pe_section.SizeOfRawData = None
        pe_section.VirtualSize = self.__size__
        pe_section.__pe__ = self
        self.sections.append(pe_section)

        if self.NT_HEADERS.FILE_HEADER.NumberOfSections > 0 and self.sections:
            return offset + self.sections[0].sizeof()*self.NT_HEADERS.FILE_HEADER.NumberOfSections
        else:
            return offset

    def get_section_by_rva(self, rva):
        """Get the section containing the given address."""

        for section in self.sections:
            if section.contains_rva(rva):
                return section
        return None

    def get_section_by_name(self, section_name):
        for section in self.sections:
            if re.match(section_name, section.Name):
            #if section.Name == section_name:
                return section
        return None

    def get_string_at_rva(self, rva, byte_mark, padding=None, alignment=2):
        """Get an ASCII string located at the given address."""
        # XXX: Check alignment in all callers
        if rva is None:
            return None
        index = rva
        string_out = ''
        try:
            while self.__data__[index] != '\x00':
                self.set_visited(index, 1, byte_mark)
                string_out = string_out.__add__(self.__data__[index])
                index += 1
            self.set_visited(index, 1, byte_mark)
            string_out = string_out.__add__(self.__data__[index])
            index += 1
            if padding:
                while (self.__data__[index] == padding) and (index % alignment != 0):
                    self.set_visited(index, 1, byte_mark)
                    string_out = string_out.__add__(self.__data__[index])
                    index += 1
        except PeMemError as e:
            if e.code != NULL_PAGE:
                debug.warning(e)
        except IndexError as e:
            debug.warning(e)
        return string_out

    def parse_data_directories(self):
        """Parse and process the PE file's data directories.

        If the optional argument 'directories' is given, only
        the directories at the specified indexes will be parsed.
        Such functionality allows parsing of areas of interest
        without the burden of having to parse all others.
        The directories can then be specified as:

        For export / import only:

          directories = [ 0, 1 ]

        or (more verbosely):

          directories = [ DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
            DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'] ]

        If 'directories' is a list, the ones that are processed will be removed,
        leaving only the ones that are not present in the image.

        If `forwarded_exports_only` is True, the IMAGE_DIRECTORY_ENTRY_EXPORT
        attribute will only contain exports that are forwarded to another DLL.

        If `import_dllnames_only` is True, symbols will not be parsed from
        the import table and the entries in the IMAGE_DIRECTORY_ENTRY_IMPORT
        attribute will not have a `symbols` attribute.
        """

        directory_parsing = (('IMAGE_DIRECTORY_ENTRY_EXPORT', self.parse_export_directory),
                             ('IMAGE_DIRECTORY_ENTRY_IMPORT', self.parse_import_directory),
                             ('IMAGE_DIRECTORY_ENTRY_RESOURCE', self.parse_resources_directory),
                             ('IMAGE_DIRECTORY_ENTRY_EXCEPTION', self.parse_exception_directory),
                             #('IMAGE_DIRECTORY_ENTRY_SECURITY', self.parse_security_directory),
                             ('IMAGE_DIRECTORY_ENTRY_BASERELOC', self.parse_relocations_directory),
                             ('IMAGE_DIRECTORY_ENTRY_DEBUG', self.parse_debug_directory),
                             ('IMAGE_DIRECTORY_ENTRY_COPYRIGHT', self.parse_copyright_directory),
                             #('IMAGE_DIRECTORY_ENTRY_GLOBALPTR', self.parse_globalptr_directory),
                             ('IMAGE_DIRECTORY_ENTRY_TLS', self.parse_directory_tls),
                             ('IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG', self.parse_directory_load_config),
                             ('IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT', self.parse_directory_bound_imports),
                             ('IMAGE_DIRECTORY_ENTRY_IAT', self.parse_iat_directory),
                             ('IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT', self.parse_delay_import_directory),
                             ('IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR', self.parse_com_descriptor_directory),
                             )





        for entry in directory_parsing:
            # OC Patch:
            #
            try:
                directory_index = DIRECTORY_ENTRY[entry[0]]
                dir_entry = self.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[directory_index]
            except IndexError:
                break

            if dir_entry.VirtualAddress and dir_entry.VirtualAddress < len(self.__data__):
                value = entry[1](dir_entry.VirtualAddress, dir_entry.Size)
                if value:
                    dir_entry.directory = value

            '''if (directories is not None) and isinstance(directories, list) and (entry[0] in directories):
                directories.remove(directory_index)'''

    def parse_export_directory(self, rva, size):
        """Parse the export directory.

        Given the RVA of the export directory, it will process all
        its entries.

        The exports will be made available as a list of ExportData
        instances in the 'IMAGE_DIRECTORY_ENTRY_EXPORT' PE attribute.
        """

        try:
            export_dir = self.__unpack_data__(
                self.__IMAGE_EXPORT_DIRECTORY_format__, self.__data__[rva: rva + 0x28],
                rva, EXPORT_DIRECTORY_BYTE)
        except PEFormatError:
            self.__warnings.append(
                'Error parsing export directory at RVA: 0x{}'.format(rva))
            return
        except PeMemError:
            return None

        if not export_dir:
            return

        '''# We keep track of the bytes left in the file and use it to set a upper
        # bound in the number of items that can be read from the different
        # arrays.
        def length_until_eof(rva):
            return len(self.__data__) - rva'''
        export_dir.Name_str = self.get_string_at_rva(export_dir.Name, EXPORT_DIRECTORY_BYTE)
        export_dir.AddressOfFunctions_tab = []

        section = self.get_section_by_rva(rva)
        for func_pointer in range(export_dir.AddressOfFunctions,
                                  export_dir.AddressOfFunctions + export_dir.NumberOfFunctions * 4, 4):
            try:
                func_row = self.__unpack_data__(
                    self.__EXPORT_ADDRESS_TABLE_EXPORT_format__, self.__data__[func_pointer: func_pointer + 4],
                    func_pointer, EXPORT_DIRECTORY_BYTE)

                if not section.contains_rva(rva):
                    func_row = self.__unpack_data__(
                        self.__EXPORT_ADDRESS_TABLE_FORWARDER_format__, self.__data__[func_pointer: func_pointer + 4],
                        func_pointer, EXPORT_DIRECTORY_BYTE)
                    func_row.Name = self.get_string_at_rva(func_row.Forwarder , EXPORT_DIRECTORY_BYTE)
                export_dir.AddressOfFunctions_tab.append(func_row)
            except PeMemError as e:
                if e.code != NULL_PAGE:
                    debug.warning(e)

        export_dir.AddressOfNames_tab = []

        for func_pointer in range(export_dir.AddressOfNames,
                              export_dir.AddressOfNames + export_dir.NumberOfNames * 4, 4):
            try:
                func_row = self.__unpack_data__(
                    self.__ADDRESS_ELEMENT_format__, self.__data__[func_pointer: func_pointer + 4],
                    func_pointer, EXPORT_DIRECTORY_BYTE)
                func_row.Name = self.get_string_at_rva(func_row.Address, EXPORT_DIRECTORY_BYTE)
                export_dir.AddressOfNames_tab.append(func_row)
            except PeMemError as e:
                if e.code != NULL_PAGE:
                    debug.warning(e)

        export_dir.AddressOfNameOrdinals_tab = []
        for func_pointer in range(export_dir.AddressOfNameOrdinals,
                                  export_dir.AddressOfNameOrdinals + export_dir.NumberOfNames * 2, 2):
            try:
                func_row = self.__unpack_data__(
                    self.__ORDINAL_format__, self.__data__[func_pointer: func_pointer + 2],
                    func_pointer, EXPORT_DIRECTORY_BYTE)
                export_dir.AddressOfNameOrdinals_tab.append(func_row)
            except PeMemError as e:
                if e.code != NULL_PAGE:
                    debug.warning(e)

        return export_dir

    def parse_import_directory(self, rva, size):
        """Walk and parse the import directory."""
        import_dir = []
        for import_descriptor_address in range(rva, rva+size, 0x14):
            try:
                import_descriptor_row = self.__unpack_data__(self.__IMAGE_IMPORT_DESCRIPTOR_format__,
                    self.__data__[import_descriptor_address: import_descriptor_address + 0x14],
                    import_descriptor_address, IMPORT_DIRECTORY_BYTE)
                import_dir.append(import_descriptor_row)
            except PeMemError as e:
                if e.code != NULL_PAGE:
                    debug.warning(e)
                import_descriptor_row=None

            if not import_descriptor_row or import_descriptor_row.all_zeroes():
                break

            # Originnal First Thunk
            thunk_table = []
            if self.NT_HEADERS.FILE_HEADER.Machine == MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']:
                import_lookup_address = import_descriptor_row.OriginalFirstThunk
                while True:
                    try:
                        thunk = self.__unpack_data__(self.__IMAGE_THUNK_DATA_format__,
                                    self.__data__[import_lookup_address: import_lookup_address + 4],
                                    import_lookup_address, IMPORT_DIRECTORY_BYTE_original_THUNK)
                    except PeMemError as e:
                        if e.code != NULL_PAGE:
                            debug.warning(e)
                        break
                    if not thunk:
                        raise PEFormatError('Unable to create thunk structure in import directory.')

                    thunk_table.append(thunk)

                    if thunk.all_zeroes():
                        break

                    if thunk.ForwarderString & 0x80000000:
                        # Ordinal
                        thunk.Ordinal = thunk.ForwarderString & 0xFFFF
                        if thunk.ForwarderString & 0xFFFF0000:
                            self.__warnings.append(
                                'Error parsing Import Lookup Table like ordinal in, : 0x{}'.format(import_lookup_address))
                    else:
                        # Hint / Name
                        thunk.ImportByName = thunk.ForwarderString
                        try:
                            thunk.hint_name = self.__unpack_data__(self.__IMAGE_IMPORT_BY_NAME_format__,
                                    self.__data__[thunk.ImportByName: thunk.ImportByName + 2],
                                    thunk.ImportByName, IMPORT_DIRECTORY_BYTE_IMPORT_NAME)
                            thunk.hint_name.Name = self.get_string_at_rva(thunk.ImportByName+2, IMPORT_DIRECTORY_BYTE_IMPORT_NAME, '\x00')
                        except PeMemError as e:
                            if e.code != NULL_PAGE:
                                debug.warning(e)
                            break
                    import_lookup_address += 4
            else:
                import_lookup_address = import_descriptor_row.OriginalFirstThunk
                while True:
                    try:
                        thunk = self.__unpack_data__(self.__IMAGE_THUNK_DATA64_format__,
                                                     self.__data__[import_lookup_address: import_lookup_address + 8],
                                                     import_lookup_address, IMPORT_DIRECTORY_BYTE)
                        thunk_table.append(thunk)

                        if thunk.all_zeroes():
                            break
                    except PeMemError as e:
                        if e.code != NULL_PAGE:
                            debug.warning(e)
                        break

                    if thunk.ForwarderString & 0x8000000000000000:
                        # Ordinal
                        thunk.Ordinal = thunk.ForwarderString & 0xFFFF
                        if thunk.ForwarderString & 0xFFFFFFFFFFFF0000:
                            self.__warnings.append(
                                'Error parsing Import Lookup Table like ordinal in 0x{}'.format(
                                    import_lookup_address))
                    else:
                        # Hint / Name
                        thunk.ImportByName = thunk.ForwarderString & 0xFFFFFFFF
                        try:
                            thunk.hint_name = self.__unpack_data__(self.__IMAGE_IMPORT_BY_NAME_format__,
                                                                   self.__data__[
                                                                   thunk.ImportByName: thunk.ImportByName + 2],
                                                                   thunk.ImportByName, IMPORT_DIRECTORY_BYTE)
                            thunk.hint_name.Name = self.get_string_at_rva(thunk.ImportByName + 2, EXPORT_DIRECTORY_BYTE, 0x0)
                        except PeMemError as e:
                            if e.code != NULL_PAGE:
                                debug.warning(e)
                        if thunk.ForwarderString & 0xFFFFFFFF00000000:
                            self.__warnings.append(
                                'Error parsing Import Lookup Table like Import Name in 0x{}'.format(
                                    import_lookup_address))
                    import_lookup_address += 8

            import_descriptor_row.original_first_thunk_table = thunk_table
            import_descriptor_row.name = self.get_string_at_rva(import_descriptor_row.Name, IMPORT_DIRECTORY_BYTE_name, '\x90')

        return import_dir

    def parse_resources_directory(self, rva, size=0, level=0):
        if level == 3:
            try:
                language = self.__unpack_data__(
                    self.__IMAGE_RESOURCE_DATA_ENTRY_format__, self.__data__[rva: rva + 0x10],
                    rva, RESOURCE_DIRECTORY_BYTE)
                language.resource = self.parse_resource(language.OffsetToData, language.Size)
                return language
            except PeMemError:
                return None
        else:
            try:
                resource_dir = self.__unpack_data__(self.__IMAGE_RESOURCE_DIRECTORY_format__,
                                                self.__data__[rva: rva + 0x10], rva, RESOURCE_DIRECTORY_BYTE)
            except PeMemError as e:
                if e.code != NULL_PAGE:
                    debug.warning(e)
                return None

            resource_name_entry = rva + 0x10

            resource_dir.resource_Name_entry_table = []
            for resource_entry_index in range(resource_name_entry, resource_name_entry +
                                                                   resource_dir.NumberOfNamedEntries * 8, 8):
                resource_entry = self.__unpack_data__(self.__IMAGE_RESOURCE_DIRECTORY_ENTRY_format__,
                    self.__data__[resource_entry_index: resource_entry_index + 8],
                    resource_entry_index, RESOURCE_DIRECTORY_BYTE)
                resource_dir.resource_Name_entry_table.append(resource_entry)
                resource_entry.SubdirectoType = self.parse_resources_directory(
                    self.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[2].VirtualAddress +
                    (resource_entry.OffsetToData & 0x7FFFFFFF), size=0, level=4)
            resource_ID_entry = resource_name_entry + resource_dir.NumberOfNamedEntries * 8

            resource_dir.resource_ID_entry_table = []
            for resource_entry_index in range(resource_ID_entry, resource_ID_entry +
                                                resource_dir.NumberOfIdEntries * 8, 8):
                try:
                    resource_entry = self.__unpack_data__(
                        self.__IMAGE_RESOURCE_DIRECTORY_ENTRY_format__,
                        self.__data__[resource_entry_index: resource_entry_index + 8],
                        resource_entry_index, RESOURCE_DIRECTORY_BYTE)
                    resource_dir.resource_ID_entry_table.append(resource_entry)
                    resource_entry.SubdirectoType = self.parse_resources_directory(
                        self.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[2].VirtualAddress +
                        (resource_entry.OffsetToData & 0x7FFFFFFF), level=level+1)
                except PeMemError as e:
                    if e.code != NULL_PAGE:
                        debug.warning(e)

            return resource_dir

    def parse_resource(self, rva, size):
        try:
            self.set_visited(rva, size, RESOURCE_DIRECTORY_BYTE_ToDo)
        except PeMemError as e:
            if e.code != NULL_PAGE:
                debug.warning(e)
        return self.__data__[rva: rva + size]

    def parse_exception_directory(self, rva, size):
        excep_array = []


        for exception_address in range(rva, rva + size, 12):
            try:
                exception = self.__unpack_data__(self.__RUNTIME_FUNCTION_format__,
                                                 self.__data__[exception_address: exception_address + 12],
                                                 exception_address, EXCEPTION_DIRECTORY_BYTE)
                excep_array.append(exception)
            except PeMemError as e:
                if e.code != NULL_PAGE:
                    debug.warning(e)

        # As some UnwindInfo points to the RUNTIME_FUNCTION sequence, It's necessary parsing first the
        # RUNTIME_FUNCTION list
        for index in range(0, len(excep_array)):
            if excep_array[index].UnwindInfo & 1:
                excep_array[index].RuntimeFunctionStruct = self.parse_exception_directory((excep_array[index].UnwindInfo ^ 1), 12)
            else:
                excep_array[index].UnwindInfoStruct = self.parse_unwind_info(excep_array[index].UnwindInfo)

        return excep_array

    def parse_unwind_info(self, pointer):
        try:
            unwind = self.__unpack_data__(self.__UNWIND_INFO_format_1__, self.__data__[pointer: pointer + 4], pointer,
                                          EXCEPTION_DIRECTORY_UNWIND)

            unwind.Version = unwind.Version_Flags & 0x7
            unwind.Flags = (unwind.Version_Flags & 0xF8) >> 3

            # ToDo: Deal with version 2
            '''if unwind.Version != 1:
                debug.warning('Warning: the other endian {}, {}'.format(unwind.Version_Flags, pointer))
                return None'''

            array_codes = []
            for code_pointer in range(pointer + 4, pointer + 4 + unwind.CountOfUnwindCode * 2, 2):
                code = self.__unpack_data__(self.__UNWIND_CODE_format__, self.__data__[code_pointer: code_pointer + 2],
                                            code_pointer, EXCEPTION_DIRECTORY_BYTE_CODE)
                array_codes.append(code)
            code_end_pointer = pointer + 4 + unwind.CountOfUnwindCode * 2
            unwind.code = array_codes

            # For alignment purposes, this array always has an even number of entries,
            # and the final entry is potentially unused. In that case, the array is one
            # longer than indicated by the count of unwind codes field.
            # https://docs.microsoft.com/en-gb/cpp/build/exception-handling-x64?view=vs-2019#struct-unwind_info
            if unwind.CountOfUnwindCode % 2 != 0:
                self.set_visited(code_end_pointer, 2, EXCEPTION_DIRECTORY_BYTE_PAD)
                code_end_pointer += 2
                # if ord(self.__data__[code_pointer]) + ord(self.__data__[code_pointer+1]) == 0:
            # ToDo: Get structures by flags and write warning

            if unwind.Flags & UNW_FLAG_CHAININFO and not unwind.Flags & (UNW_FLAG_UHANDLER+UNW_FLAG_EHANDLER):
                unwind.chained_unwind_info = self.__unpack_data__(self.__RUNTIME_FUNCTION_format__,
                                                 self.__data__[code_end_pointer: code_end_pointer + 12],
                                                 code_end_pointer, EXCEPTION_DIRECTORY_BYTE)
                unwind.chained_unwind_info.UnwindInfoStruct = self.parse_unwind_info(unwind.chained_unwind_info.UnwindInfo)
            elif unwind.Flags & UNW_FLAG_CHAININFO and unwind.Flags & (UNW_FLAG_UHANDLER+UNW_FLAG_EHANDLER):
                debug.warning('Error: unwind_info struct too many flags')

        except PeMemError as e:
            if e.code != NULL_PAGE:
                debug.warning(e)
            unwind = None
        return unwind

    def parse_security_directory(self, rva, size):
        try:
            signature = self.__unpack_data__(self.__WIN_CERTIFICATE_format__, self.__data__[rva: rva + 8], rva,
                                             SECURITY_DIRECTORY_BYTE)
            signature.bCertificate = self.__data__[rva+8: rva+8+signature.dwLength]
            self.__warnings.append('Warning: Attribute Certificate Table should not exist on memory (Address: {} Size: {}'.format(rva, size))
            return signature
        except PeMemError as e:
            if e.code != NULL_PAGE:
                debug.warning(e)

    def parse_relocations_directory(self, rva, size):
        base_relocation_index = rva
        relocation_array = []
        while base_relocation_index < rva + size:
            try:
                relocation = self.__unpack_data__(self.__IMAGE_BASE_RELOCATION_format__, self.__data__[
                                                    base_relocation_index: base_relocation_index + 8], base_relocation_index,
                                                    BASERELOC_DIRECTORY_BYTE)
                relocation.TypeOffsetArray = []
                for index in range(base_relocation_index+8, base_relocation_index + relocation.SizeOfBlock, 2):
                    try:
                        typeOffset = self.__unpack_data__(self.__IMAGE_TYPEOFFSET_format__, self.__data__[index: index + 2],
                                                          index, BASERELOC_DIRECTORY_BYTE)
                        relocation.TypeOffsetArray.append(typeOffset.TypeOffset)
                    except PeMemError as e:
                        if e.code != NULL_PAGE:
                            debug.warning(e)
                        return relocation_array
                relocation_array.append(relocation)
            except PeMemError as e:
                if e.code != NULL_PAGE:
                    debug.warning(e)
                return relocation_array
            base_relocation_index += relocation.SizeOfBlock

        return relocation_array

    def parse_debug_directory(self, rva, size):
        debug_array = []
        for index in range(rva, rva + size, 28):
            try:
                debug_element = self.__unpack_data__(self.__IMAGE_DEBUG_DIRECTORY_format__, self.__data__[rva: rva + 28], rva,
                                             DEBUG_DIRECTORY_BYTE)
                debug_array.append(debug_element)
            except PeMemError as e:
                if e.code != NULL_PAGE:
                    debug.warning(e)

        return debug_array

    def parse_copyright_directory(self, rva, size):
        try:
            self.set_visited(rva,size, COPYRIGHT_DIRECTORY_BYTE)
            return self.__data__[rva:rva+size]
        except PeMemError as e:
            if e.code != NULL_PAGE:
                debug.warning(e)

    def parse_directory_tls(self, rva, size):
        if self.NT_HEADERS.OPTIONAL_HEADER.Magic == OPTIONAL_HEADER_MAGIC_PE: # X86
            try:
                TLS = self.__unpack_data__(self.__IMAGE_TLS_DIRECTORY_format__, self.__data__[rva: rva + 24], rva,
                                           TLS_DIRECTORY_BYTE)
                TLS.CallBacksList = []
                RVACallBacks = TLS.AddressOfCallBacks - self.__base_address__
                while True:
                    try:
                        CallBack = self.__unpack_data__(self.__IMAGE_TLS_CALLBACK_format__,
                                                        self.__data__[RVACallBacks: RVACallBacks + 4], RVACallBacks,
                                                        TLS_DIRECTORY_BYTE)
                        TLS.CallBacksList.append(CallBack.Callback)
                        if CallBack.Callback == 0:
                            break
                        RVACallBacks += 4
                    except PeMemError as e:
                        if e.code != NULL_PAGE:
                            debug.warning(e)
                        break

                return TLS
            except PeMemError as e:
                if e.code != NULL_PAGE:
                    debug.warning(e)
        else: # X64
            try:
                TLS = self.__unpack_data__(self.__IMAGE_TLS_DIRECTORY64_format__, self.__data__[rva: rva + 40], rva,
                                           TLS_DIRECTORY_BYTE)
                TLS.CallBacksList = []
                RVACallBacks = TLS.AddressOfCallBacks - self.__base_address__
                while True:
                    try:
                        CallBack = self.__unpack_data__(self.__IMAGE_TLS_CALLBACK64_format__,
                                                        self.__data__[RVACallBacks: RVACallBacks + 8], RVACallBacks,
                                                        TLS_DIRECTORY_BYTE)
                        TLS.CallBacksList.append(CallBack.Callback)
                        if CallBack.Callback == 0:
                            break
                        RVACallBacks += 8
                    except PeMemError as e:
                        if e.code != NULL_PAGE:
                            debug.warning(e)
                        break

                return TLS
            except PeMemError as e:
                if e.code != NULL_PAGE:
                    debug.warning(e)

    def parse_directory_load_config(self, rva, size):
        # https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_load_config_directory32
        # https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_load_config_directory64
        # http://redplait.blogspot.com/2016/10/imageloadconfigdirectory-from-sdk-14951.html
        try:
            if size > 0x18:
                image_load_config = self.__unpack_data__(self.__IMAGE_LOAD_CONFIG_DIRECTORY_format__,
                                                       self.__data__[rva: rva + 0x18], rva,
                                                    LOAD_CONFIG_DIRECTORY_BYTE)
                index = 0x18

                if self.NT_HEADERS.OPTIONAL_HEADER.Magic == OPTIONAL_HEADER_MAGIC_PE:  # X86

                    if index < image_load_config.Size:
                        self.set_visited(rva+index, 4, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.DeCommitFreeBlockThreshold = struct.unpack('I',
                            self.__data__[rva+index: rva + index + 4])[0]
                        index += 4
                    if index < image_load_config.Size:
                        self.set_visited(rva+index, 4, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.DeCommitTotalFreeThreshold = struct.unpack('I',
                            self.__data__[rva+index: rva + index + 4])[0]
                        index += 4
                    if index < image_load_config.Size:
                        self.set_visited(rva+index, 4, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.LockPrefixTable = struct.unpack('I',
                            self.__data__[rva+index: rva + index + 4])[0]
                        index += 4
                    if index < image_load_config.Size:
                        self.set_visited(rva+index, 4, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.MaximumAllocationSize = struct.unpack('I',
                            self.__data__[rva+index: rva + index + 4])[0]
                        index += 4
                    if index < image_load_config.Size:
                        self.set_visited(rva+index, 4, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.VirtualMemoryThreshold = struct.unpack('I',
                            self.__data__[rva+index: rva + index + 4])[0]
                        index += 4
                    if index < image_load_config.Size:
                        self.set_visited(rva+index, 4, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.ProcessHeapFlags = struct.unpack('I',
                            self.__data__[rva+index: rva + index + 4])[0]
                        index += 4
                    if index < image_load_config.Size:
                        self.set_visited(rva+index, 4, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.ProcessAffinityMask = struct.unpack('I',
                            self.__data__[rva+index: rva + index + 4])[0]
                        index += 4
                    if index < image_load_config.Size:
                        self.set_visited(rva+index, 2, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.CSDVersion = struct.unpack('H',
                            self.__data__[rva+index: rva + index + 2])[0]
                        index += 2
                    if index < image_load_config.Size:
                        self.set_visited(rva+index, 2, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.DependentLoadFlags = struct.unpack('H',
                            self.__data__[rva+index: rva + index + 2])[0]
                        index += 2
                    if index < image_load_config.Size:
                        self.set_visited(rva+index, 4, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.EditList = struct.unpack('I',
                            self.__data__[rva+index: rva + index + 4])[0]
                        index += 4
                    if index < image_load_config.Size:
                        self.set_visited(rva+index, 4, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.SecurityCookie = struct.unpack('I',
                            self.__data__[rva+index: rva + index + 4])[0]
                        index += 4
                    if index < image_load_config.Size:
                        self.set_visited(rva+index, 4, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.SEHandlerTable = struct.unpack('I',
                            self.__data__[rva+index: rva + index + 4])[0]
                        index += 4
                        image_load_config.SEHandlerTableList = []
                    if index < image_load_config.Size:
                        self.set_visited(rva+index, 4, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.SEHandlerCount = struct.unpack('I',
                            self.__data__[rva+index: rva + index + 4])[0]
                        index += 4
                        try:
                            for i in range(0, image_load_config.SEHandlerCount):
                                self.set_visited(image_load_config.SEHandlerTable - self.__base_address__ + i * 4,
                                                 4, LOAD_CONFIG_DIRECTORY_BYTE)
                                SEHandlerAddress = struct.unpack('I',
                                self.__data__[image_load_config.SEHandlerTable - self.__base_address__ + i * 4:
                                              image_load_config.SEHandlerTable - self.__base_address__ + i * 4 + 4])[0]
                                image_load_config.SEHandlerTableList.append(SEHandlerAddress)
                        except PeMemError as e:
                            if e.code != NULL_PAGE:
                                debug.warning(e)

                    if index < image_load_config.Size:
                        self.set_visited(rva+index, 4, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.GuardCFCheckFunctionPointer = struct.unpack('I',
                            self.__data__[rva+index: rva + index + 4])[0]
                        index += 4
                    if index < image_load_config.Size:
                        self.set_visited(rva+index, 4, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.GuardCFDispatchFunctionPointer = struct.unpack('I',
                            self.__data__[rva+index: rva + index + 4])[0]
                        index += 4
                    if index < image_load_config.Size:
                        self.set_visited(rva+index, 4, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.GuardCFFunctionTable = struct.unpack('I',
                            self.__data__[rva+index: rva + index + 4])[0]
                        index += 4
                        image_load_config.GuardCFFunctionTableList = []
                    if index < image_load_config.Size:
                        self.set_visited(rva+index, 4, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.GuardCFFunctionCount = struct.unpack('I',
                            self.__data__[rva+index: rva + index + 4])[0]
                        index += 4
                    if index < image_load_config.Size:
                        self.set_visited(rva+index, 4, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.GuardFlags = struct.unpack('I',
                            self.__data__[rva+index: rva + index + 4])[0]
                        index += 4

                        extra_bytes = (image_load_config.GuardFlags & IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK) >> IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT
                        try:
                            for i in range(0, image_load_config.GuardCFFunctionCount):
                                self.set_visited(image_load_config.GuardCFFunctionTable - self.__base_address__ + i * (4 + extra_bytes),
                                                 4+extra_bytes, LOAD_CONFIG_DIRECTORY_BYTE)
                                GuardCFFunctionAddress = struct.unpack('I',
                                                                       self.__data__[
                                                                       image_load_config.GuardCFFunctionTable - self.__base_address__ + i * (4 + extra_bytes):
                                                                       image_load_config.GuardCFFunctionTable - self.__base_address__ + i * (4 + extra_bytes) + 4])[0]
                                if extra_bytes:
                                    image_load_config.GuardCFFunctionTableList.append(
                                        (GuardCFFunctionAddress, self.__data__[image_load_config.GuardCFFunctionTable - self.__base_address__ + i * (4 + extra_bytes)+ 4:
                                                                       image_load_config.GuardCFFunctionTable - self.__base_address__ + i * (4 + extra_bytes) + 4 + extra_bytes]))
                                else:
                                    image_load_config.GuardCFFunctionTableList.append(GuardCFFunctionAddress)
                        except PeMemError as e:
                            if e.code != NULL_PAGE:
                                debug.warning(e)

                    if index < image_load_config.Size:
                        image_load_config.CodeIntegrity = self.__unpack_data__(self.__IMAGE_LOAD_CONFIG_CODE_INTEGRITY_format__,
                                                                 self.__data__[rva + index: rva + index + 12], rva + index,
                                                                 LOAD_CONFIG_DIRECTORY_BYTE)
                        index += 12

                    if index < image_load_config.Size:
                        self.set_visited(rva+index, 4, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.GuardAddressTakenIatEntryTable = struct.unpack('I',
                            self.__data__[rva+index: rva + index + 4])[0]
                        index += 4
                        image_load_config.GuardAddressTakenIatEntryTableList = []
                    if index < image_load_config.Size:
                        self.set_visited(rva+index, 4, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.GuardAddressTakenIatEntryCount = struct.unpack('I',
                            self.__data__[rva+index: rva + index + 4])[0]
                        index += 4
                        try:
                            for i in range(0, image_load_config.GuardAddressTakenIatEntryCount):
                                self.set_visited(image_load_config.GuardAddressTakenIatEntryTable - self.__base_address__ + i * 4,
                                                 4, LOAD_CONFIG_DIRECTORY_BYTE)
                                GuardAddressTakenIatEntryTableAddress = struct.unpack('I',
                                self.__data__[image_load_config.GuardAddressTakenIatEntryTable - self.__base_address__ + i * 4:
                                              image_load_config.GuardAddressTakenIatEntryTable - self.__base_address__ + i * 4 + 4])[0]
                                image_load_config.SEHandlerTableList.append(GuardAddressTakenIatEntryTableAddress)
                        except PeMemError as e:
                            if e.code != NULL_PAGE:
                                debug.warning(e)
                    if index < image_load_config.Size:
                        self.set_visited(rva+index, 4, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.GuardLongJumpTargetTable = struct.unpack('I',
                            self.__data__[rva+index: rva + index + 4])[0]
                        index += 4
                        image_load_config.GuardLongJumpTargetTableList = []
                    if index < image_load_config.Size:
                        self.set_visited(rva+index, 4, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.GuardLongJumpTargetCount = struct.unpack('I',
                            self.__data__[rva+index: rva + index + 4])[0]
                        index += 4
                        try:
                            for i in range(0, image_load_config.GuardLongJumpTargetCount):
                                self.set_visited(image_load_config.GuardLongJumpTargetTable - self.__base_address__ + i * 4,
                                                 4, LOAD_CONFIG_DIRECTORY_BYTE)
                                GuardLongJumpTargetTableAddress = struct.unpack('I',
                                self.__data__[image_load_config.GuardLongJumpTargetTable - self.__base_address__ + i * 4:
                                              image_load_config.GuardLongJumpTargetTable - self.__base_address__ + i * 4 + 4])[0]
                                image_load_config.SEHandlerTableList.append(GuardLongJumpTargetTableAddress)
                        except PeMemError as e:
                            if e.code != NULL_PAGE:
                                debug.warning(e)
                    if index < image_load_config.Size:
                        self.set_visited(rva+index, 4, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.DynamicValueRelocTable = struct.unpack('I',
                            self.__data__[rva+index: rva + index + 4])[0]
                        index += 4
                    if index < image_load_config.Size:
                        self.set_visited(rva+index, 4, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.CHPEMetadataPointer = struct.unpack('I',
                            self.__data__[rva+index: rva + index + 4])[0]
                        index += 4
                    if index < image_load_config.Size:
                        self.set_visited(rva+index, 4, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.GuardRFFailureRoutine = struct.unpack('I',
                            self.__data__[rva+index: rva + index + 4])[0]
                        index += 4
                    if index < image_load_config.Size:
                        self.set_visited(rva+index, 4, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.GuardRFFailureRoutineFunctionPointer = struct.unpack('I',
                            self.__data__[rva+index: rva + index + 4])[0]
                        index += 4
                    if index < image_load_config.Size:
                        self.set_visited(rva+index, 4, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.DynamicValueRelocTableOffset = struct.unpack('I',
                            self.__data__[rva+index: rva + index + 4])[0]
                        index += 4
                    if index < image_load_config.Size:
                        self.set_visited(rva+index, 2, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.DynamicValueRelocTableSection = struct.unpack('H',
                            self.__data__[rva+index: rva + index + 2])[0]
                        index += 2
                    if index < image_load_config.Size:
                        self.set_visited(rva+index, 2, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.Reserved2 = struct.unpack('H',
                            self.__data__[rva+index: rva + index + 2])[0]
                        index += 2
                    if index < image_load_config.Size:
                        self.set_visited(rva+index, 4, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.GuardRFVerifyStackPointerFunctionPointer = struct.unpack('I',
                            self.__data__[rva+index: rva + index + 4])[0]
                        index += 4
                    if index < image_load_config.Size:
                        self.set_visited(rva+index, 4, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.HotPatchTableOffset = struct.unpack('I',
                            self.__data__[rva+index: rva + index + 4])[0]
                        index += 4
                    if index < image_load_config.Size:
                        self.set_visited(rva+index, 4, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.Reserved3 = struct.unpack('I',
                            self.__data__[rva+index: rva + index + 4])[0]
                        index += 4
                    if index < image_load_config.Size:
                        self.set_visited(rva+index, 4, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.EnclaveConfigurationPointer = struct.unpack('I',
                            self.__data__[rva+index: rva + index + 4])[0]
                        index += 4
                    if index < image_load_config.Size:
                        self.set_visited(rva+index, 4, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.VolatileMetadataPointer = struct.unpack('I',
                            self.__data__[rva+index: rva + index + 4])[0]
                        index += 4
                        pass

                else:

                    if index < image_load_config.Size:
                        self.set_visited(rva + index, 8, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.DeCommitFreeBlockThreshold = struct.unpack('Q',
                                                                                     self.__data__[
                                                                                     rva + index: rva + index + 8])[0]
                        index += 8
                    if index < image_load_config.Size:
                        self.set_visited(rva + index, 8, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.DeCommitTotalFreeThreshold = struct.unpack('Q',
                                                                                     self.__data__[
                                                                                     rva + index: rva + index + 8])[0]
                        index += 8
                    if index < image_load_config.Size:
                        self.set_visited(rva + index, 8, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.LockPrefixTable = struct.unpack('Q',
                                                                          self.__data__[rva + index: rva + index + 8])[
                            0]
                        index += 8
                    if index < image_load_config.Size:
                        self.set_visited(rva + index, 8, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.MaximumAllocationSize = struct.unpack('Q',
                                                                                self.__data__[
                                                                                rva + index: rva + index + 8])[0]
                        index += 8
                    if index < image_load_config.Size:
                        self.set_visited(rva + index, 8, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.VirtualMemoryThreshold = struct.unpack('Q',
                                                                                 self.__data__[
                                                                                 rva + index: rva + index + 8])[0]
                        index += 8
                    if index < image_load_config.Size:
                        self.set_visited(rva + index, 8, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.ProcessAffinityMask = struct.unpack('Q',
                                                                           self.__data__[rva + index: rva + index + 8])[
                            0]
                        index += 8
                    if index < image_load_config.Size:
                        self.set_visited(rva + index, 4, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.ProcessHeapFlags = struct.unpack('I',
                                                                              self.__data__[
                                                                              rva + index: rva + index + 4])[0]
                        index += 4
                    if index < image_load_config.Size:
                        self.set_visited(rva + index, 2, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.CSDVersion = struct.unpack('H',
                                                                     self.__data__[rva + index: rva + index + 2])[0]
                        index += 2
                    if index < image_load_config.Size:
                        self.set_visited(rva + index, 2, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.DependentLoadFlags = struct.unpack('H',
                                                                    self.__data__[rva + index: rva + index + 2])[0]
                        index += 2
                    if index < image_load_config.Size:
                        self.set_visited(rva + index, 8, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.EditList = struct.unpack('Q',
                                                                   self.__data__[rva + index: rva + index + 8])[0]
                        index += 8
                    if index < image_load_config.Size:
                        self.set_visited(rva + index, 8, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.SecurityCookie = struct.unpack('Q',
                                                                         self.__data__[rva + index: rva + index + 8])[0]
                        index += 8
                    if index < image_load_config.Size:
                        self.set_visited(rva + index, 8, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.SEHandlerTable = struct.unpack('Q',
                                                                         self.__data__[rva + index: rva + index + 8])[0]
                        index += 8
                        image_load_config.SEHandlerTableList = []
                    if index < image_load_config.Size:
                        self.set_visited(rva + index, 8, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.SEHandlerCount = struct.unpack('Q',
                                                                         self.__data__[rva + index: rva + index + 8])[0]
                        index += 8
                        try:
                            for i in range(0, image_load_config.SEHandlerCount):
                                self.set_visited(image_load_config.SEHandlerTable - self.__base_address__ + i * 8,
                                                 8, LOAD_CONFIG_DIRECTORY_BYTE)
                                SEHandlerAddress = struct.unpack('Q',
                                                                 self.__data__[
                                                                 image_load_config.SEHandlerTable - self.__base_address__ + i * 8:
                                                                 image_load_config.SEHandlerTable - self.__base_address__ + i * 8 + 8])[
                                    0]
                                image_load_config.SEHandlerTableList.append(SEHandlerAddress)
                        except PeMemError as e:
                            if e.code != NULL_PAGE:
                                debug.warning(e)

                    if index < image_load_config.Size:
                        self.set_visited(rva + index, 8, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.GuardCFCheckFunctionPointer = struct.unpack('Q',
                                                                    self.__data__[rva + index: rva + index + 8])[0]
                        index += 8
                    if index < image_load_config.Size:
                        self.set_visited(rva + index, 8, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.GuardCFDispatchFunctionPointer = struct.unpack('Q',
                                                                    self.__data__[rva + index: rva + index + 8])[0]
                        index += 8
                    if index < image_load_config.Size:
                        self.set_visited(rva + index, 8, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.GuardCFFunctionTable = struct.unpack('Q',
                                                                               self.__data__[
                                                                               rva + index: rva + index + 8])[0]
                        index += 8
                        image_load_config.GuardCFFunctionTableList = []
                    if index < image_load_config.Size:
                        self.set_visited(rva + index, 8, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.GuardCFFunctionCount = struct.unpack('Q',
                                                                               self.__data__[
                                                                               rva + index: rva + index + 8])[0]
                        index += 8
                    if index < image_load_config.Size:
                        self.set_visited(rva + index, 4, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.GuardFlags = struct.unpack('I',
                                                                     self.__data__[rva + index: rva + index + 4])[0]
                        index += 4
                        extra_bytes = (image_load_config.GuardFlags & IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK) >> IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT
                        try:
                            for i in range(0, image_load_config.GuardCFFunctionCount):
                                self.set_visited(
                                    image_load_config.GuardCFFunctionTable - self.__base_address__ + i * (4 + extra_bytes),
                                    4 + extra_bytes, LOAD_CONFIG_DIRECTORY_BYTE)
                                GuardCFFunctionAddress = struct.unpack('I',
                                                                       self.__data__[image_load_config.GuardCFFunctionTable - self.__base_address__ +
                                                                                     i * (4 + extra_bytes):image_load_config.GuardCFFunctionTable -
                                                                                                           self.__base_address__ + i * (4 + extra_bytes) + 4])[0]
                                if extra_bytes:
                                    image_load_config.GuardCFFunctionTableList.append(
                                        (GuardCFFunctionAddress, self.__data__[
                                                                 image_load_config.GuardCFFunctionTable - self.__base_address__ + i * (
                                                                             4 + extra_bytes) + 4:
                                                                 image_load_config.GuardCFFunctionTable - self.__base_address__ + i * (
                                                                             4 + extra_bytes) + 4 + extra_bytes]))
                                else:
                                    image_load_config.GuardCFFunctionTableList.append(GuardCFFunctionAddress)
                        except PeMemError as e:
                            if e.code != NULL_PAGE:
                                debug.warning(e)

                    if index < image_load_config.Size:
                        image_load_config.CodeIntegrity = self.__unpack_data__(self.__IMAGE_LOAD_CONFIG_CODE_INTEGRITY_format__,
                            self.__data__[rva + index: rva + index + 12], rva + index, LOAD_CONFIG_DIRECTORY_BYTE)
                        index += 12

                    if index < image_load_config.Size:
                        self.set_visited(rva+index, 8, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.GuardAddressTakenIatEntryTable = struct.unpack('Q',
                            self.__data__[rva+index: rva + index + 8])[0]
                        index += 8
                        image_load_config.GuardAddressTakenIatEntryTableList = []

                    if index < image_load_config.Size:
                        self.set_visited(rva+index, 8, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.GuardAddressTakenIatEntryCount = struct.unpack('Q',
                            self.__data__[rva+index: rva + index + 8])[0]
                        index += 8
                        try:
                            for i in range(0, image_load_config.GuardAddressTakenIatEntryCount):
                                self.set_visited(image_load_config.GuardAddressTakenIatEntryTable - self.__base_address__ + i * 8,
                                                 8, LOAD_CONFIG_DIRECTORY_BYTE)
                                GuardAddressTakenIatEntryTableAddress = struct.unpack('Q',
                                                                 self.__data__[
                                                                 image_load_config.GuardAddressTakenIatEntryTable - self.__base_address__ + i * 8:
                                                                 image_load_config.GuardAddressTakenIatEntryTable - self.__base_address__ + i * 8 + 8])[
                                    0]
                                image_load_config.GuardAddressTakenIatEntryTableList.append(GuardAddressTakenIatEntryTableAddress)
                        except PeMemError as e:
                            if e.code != NULL_PAGE:
                                debug.warning(e)
                    if index < image_load_config.Size:
                        self.set_visited(rva+index, 8, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.GuardLongJumpTargetTable = struct.unpack('Q',
                            self.__data__[rva+index: rva + index + 8])[0]
                        index += 8
                        image_load_config.GuardLongJumpTargetTableList = []
                    if index < image_load_config.Size:
                        self.set_visited(rva+index, 8, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.GuardLongJumpTargetCount = struct.unpack('Q',
                            self.__data__[rva+index: rva + index + 8])[0]
                        index += 8
                        try:
                            for i in range(0, image_load_config.GuardLongJumpTargetCount):
                                self.set_visited(image_load_config.GuardLongJumpTargetTable - self.__base_address__ + i * 8,
                                                 8, LOAD_CONFIG_DIRECTORY_BYTE)
                                GuardLongJumpTargetTableAddress = struct.unpack('Q',
                                                                 self.__data__[
                                                                 image_load_config.GuardLongJumpTargetTable - self.__base_address__ + i * 8:
                                                                 image_load_config.GuardLongJumpTargetTable - self.__base_address__ + i * 8 + 8])[
                                    0]
                                image_load_config.GuardLongJumpTargetTableList.append(GuardLongJumpTargetTableAddress)
                        except PeMemError as e:
                            if e.code != NULL_PAGE:
                                debug.warning(e)
                    if index < image_load_config.Size:
                        self.set_visited(rva+index, 8, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.DynamicValueRelocTable = struct.unpack('Q',
                            self.__data__[rva+index: rva + index + 8])[0]
                        index += 8
                    if index < image_load_config.Size:
                        self.set_visited(rva+index, 8, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.CHPEMetadataPointer = struct.unpack('Q',
                            self.__data__[rva+index: rva + index + 8])[0]
                        index += 8
                    if index < image_load_config.Size:
                        self.set_visited(rva+index, 8, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.GuardRFFailureRoutine = struct.unpack('Q',
                            self.__data__[rva+index: rva + index + 8])[0]
                        index += 8
                    if index < image_load_config.Size:
                        self.set_visited(rva+index, 8, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.GuardRFFailureRoutineFunctionPointer = struct.unpack('Q',
                            self.__data__[rva+index: rva + index + 8])[0]
                        index += 8
                    if index < image_load_config.Size:
                        self.set_visited(rva+index, 4, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.DynamicValueRelocTableOffset = struct.unpack('I',
                            self.__data__[rva+index: rva + index + 4])[0]
                        index += 4
                    if index < image_load_config.Size:
                        self.set_visited(rva+index, 2, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.DynamicValueRelocTableSection = struct.unpack('H',
                            self.__data__[rva+index: rva + index + 2])[0]
                        index += 2
                    if index < image_load_config.Size:
                        self.set_visited(rva+index, 2, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.Reserved2 = struct.unpack('H',
                            self.__data__[rva+index: rva + index + 2])[0]
                        index += 2
                    if index < image_load_config.Size:
                        self.set_visited(rva+index, 8, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.GuardRFVerifyStackPointerFunctionPointer = struct.unpack('Q',
                            self.__data__[rva+index: rva + index + 8])[0]
                        index += 8
                    if index < image_load_config.Size:
                        self.set_visited(rva+index, 4, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.HotPatchTableOffset = struct.unpack('I',
                            self.__data__[rva+index: rva + index + 4])[0]
                        index += 4
                    if index < image_load_config.Size:
                        self.set_visited(rva+index, 4, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.Reserved3 = struct.unpack('I',
                            self.__data__[rva+index: rva + index + 4])[0]
                        index += 4
                    if index < image_load_config.Size:
                        self.set_visited(rva+index, 8, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.EnclaveConfigurationPointer = struct.unpack('Q',
                            self.__data__[rva+index: rva + index + 8])[0]
                        index += 8
                    if index < image_load_config.Size:
                        self.set_visited(rva+index, 8, LOAD_CONFIG_DIRECTORY_BYTE)
                        image_load_config.VolatileMetadataPointer = struct.unpack('Q',
                            self.__data__[rva+index: rva + index + 8])[0]
                        index += 8


                if index != image_load_config.Size:
                    debug.warning('Not all fields were parsed, or they were not parsed correctly')
                return image_load_config
            else:
                debug.warning('Directory_load_config is smaller than it is hoped')

        except PeMemError as e:
            if e.code != NULL_PAGE:
                debug.warning(e)
            if 'image_load_config' in locals():
                return image_load_config

    def parse_directory_bound_imports(self, rva, size):
        try:
            #XXX: parsing less space than size
            bound_import = self.__unpack_data__(self.__IMAGE_BOUND_IMPORT_DESCRIPTOR_format__,
                                            self.__data__[rva: rva + 8], rva,
                                                BOUND_IMPORT_DIRECTORY_BYTE)
            return bound_import
        except PeMemError as e:
            if e.code != NULL_PAGE:
                debug.warning(e)

    def parse_iat_directory(self, rva, size):
        IAT_directory = []
        if self.NT_HEADERS.OPTIONAL_HEADER.Magic == OPTIONAL_HEADER_MAGIC_PE:
            try:
                for iat_index in range(rva, rva+size, 4):
                    address = self.__unpack_data__(self.__ADDRESS_ELEMENT_format__,
                                                self.__data__[iat_index: iat_index + 4], iat_index,
                                                   IAT_DIRECTORY_BYTE)
                    IAT_directory.append(address.Address)

            except PeMemError as e:
                if e.code != NULL_PAGE:
                    debug.warning(e)
        else:
            try:
                for iat_index in range(rva, rva + size, 8):
                    address = self.__unpack_data__(self.__ADDRESS_ELEMENT64_format__,
                                                   self.__data__[iat_index: iat_index + 8], iat_index,
                                                   IAT_DIRECTORY_BYTE)
                    IAT_directory.append(address.Address)

            except PeMemError as e:
                if e.code != NULL_PAGE:
                    debug.warning(e)
        return IAT_directory

    def parse_delay_import_directory(self, rva, size):
        try:
            delay_import_list = []
            for index in range(rva, rva+size, 32):
                delay_import = self.__unpack_data__(self.__IMAGE_DELAY_IMPORT_DESCRIPTOR_format__,
                                                       self.__data__[index: index + 32], index,
                                                    DELAY_IMPORT_DIRECTORY_BYTE)
                if delay_import.szName:
                    delay_import.Name = self.get_string_at_rva(delay_import.szName, DELAY_IMPORT_DIRECTORY_BYTE)
                if delay_import.pIAT:
                    delay_import.IAT = self.parse_delay_iat(delay_import.pIAT)
                if delay_import.pINT:
                    delay_import.INT = self.parse_delay_int(delay_import.pINT)
                if delay_import.pBoundIAT:
                    delay_import.BoundIAT = self.parse_delay_array_iat(delay_import.pBoundIAT, len(delay_import.IAT) if len(delay_import.IAT) else len(delay_import.INT))
                if delay_import.pUnloadIAT:
                    delay_import.UnloadIAT = self.parse_delay_array_iat(delay_import.pUnloadIAT, len(delay_import.IAT) if len(delay_import.IAT) else len(delay_import.INT))
                delay_import_list.append(delay_import)
            return delay_import_list
        except PeMemError as e:
            if e.code != NULL_PAGE:
                debug.warning(e)

    def parse_delay_iat(self, rva):
        IAT_directory = []
        index = rva
        if self.NT_HEADERS.OPTIONAL_HEADER.Magic == OPTIONAL_HEADER_MAGIC_PE:
            try:
                while True:
                    address = self.__unpack_data__(self.__ADDRESS_ELEMENT_format__,
                                                   self.__data__[index: index + 4], index,
                                                   DELAY_IMPORT_IAT_BYTE)
                    IAT_directory.append(address.Address)
                    if address.Address == 0:
                        break
                    index += 4

            except PeMemError as e:
                if e.code != NULL_PAGE:
                    debug.warning(e)
        else:
            try:
                while True:
                    address = self.__unpack_data__(self.__ADDRESS_ELEMENT64_format__,
                                                   self.__data__[index: index + 8], index,
                                                   DELAY_IMPORT_IAT_BYTE)
                    IAT_directory.append(address.Address)
                    if address.Address == 0:
                        break
                    index += 8

            except PeMemError as e:
                if e.code != NULL_PAGE:
                    debug.warning(e)
        return IAT_directory

    def parse_delay_int(self, rva):
        INT_directory = []
        index = rva
        if self.NT_HEADERS.OPTIONAL_HEADER.Magic == OPTIONAL_HEADER_MAGIC_PE:
            try:
                while True:
                    hint_name = self.__unpack_data__(self.__ADDRESS_ELEMENT_format__,
                                                   self.__data__[index: index + 4], index,
                                                   DELAY_IMPORT_INT_BYTE)

                    if hint_name.Address == 0:
                        INT_directory.append(hint_name)
                        break
                    if hint_name.Address >= self.__size__:
                        INT_directory.append(hint_name)
                        index += 4
                        continue

                    hint_name.hint = self.__unpack_data__(self.__IMAGE_IMPORT_BY_NAME_format__,
                                    self.__data__[hint_name.Address: hint_name.Address + 2],
                                                          hint_name.Address, DELAY_IMPORT_INT_BYTE)

                    hint_name.hint.Name = self.get_string_at_rva(hint_name.Address+2, DELAY_IMPORT_INT_BYTE)
                    INT_directory.append(hint_name)
                    index += 4

            except PeMemError as e:
                if e.code != NULL_PAGE:
                    debug.warning(e)
        else:
            try:
                while True:
                    hint_name = self.__unpack_data__(self.__ADDRESS_ELEMENT64_format__,
                                                     self.__data__[index: index + 8], index,
                                                     DELAY_IMPORT_INT_BYTE)

                    if hint_name.Address == 0:
                        INT_directory.append(hint_name)
                        break
                    if hint_name.Address >= self.__size__:
                        INT_directory.append(hint_name)
                        index += 4
                        continue
                    hint_name.hint = self.__unpack_data__(self.__IMAGE_IMPORT_BY_NAME_format__,
                                                          self.__data__[hint_name.Address: hint_name.Address + 2],
                                                          hint_name.Address, DELAY_IMPORT_INT_BYTE)

                    hint_name.hint.Name = self.get_string_at_rva(hint_name.Address + 2, DELAY_IMPORT_INT_BYTE)
                    INT_directory.append(hint_name)
                    index += 8

            except PeMemError as e:
                if e.code != NULL_PAGE:
                    debug.warning(e)
        return INT_directory

    def parse_delay_array_iat(self, rva, elements):
        array_IAT_directory = []
        if self.NT_HEADERS.OPTIONAL_HEADER.Magic == OPTIONAL_HEADER_MAGIC_PE:
            try:
                for index in range(rva, rva+elements*4, 4):
                    address = self.__unpack_data__(self.__ADDRESS_ELEMENT_format__,
                                                   self.__data__[index: index + 4], index,
                                                   DELAY_IMPORT_IAT_BYTE)

                    array_IAT_directory.append(address.Address)

            except PeMemError as e:
                if e.code != NULL_PAGE:
                    debug.warning(e)
        else:
            try:
                for index in range(rva, rva + elements * 8, 8):
                    address = self.__unpack_data__(self.__ADDRESS_ELEMENT64_format__,
                                                   self.__data__[index: index + 8], index,
                                                   DELAY_IMPORT_IAT_BYTE)
                    array_IAT_directory.append(address.Address)

            except PeMemError as e:
                if e.code != NULL_PAGE:
                    debug.warning(e)
        return array_IAT_directory

    def parse_com_descriptor_directory(self, rva, size):
        try:
            net = self.__unpack_data__(self.__IMAGE_COR20_HEADER_format__, self.__data__[rva: rva + 72], rva,
                                       COM_DESCRIPTOR_DIRECTORY_BYTE)

            if net.MetaDataVirtualAddress:
                net.MetaData = self.parse_metadata(net.MetaDataVirtualAddress, net.MetaDataSize)

            return net

        except PeMemError as e:
            if e.code != NULL_PAGE:
                debug.warning(e)

    def parse_metadata(self, rva, size):
        try:
            meta = self.__unpack_data__(self.__METADATAHDR_format__, self.__data__[rva: rva + 16], rva,
                                           COM_DESCRIPTOR_DIRECTORY_BYTE)
            self.set_visited(rva+16, meta.VersionLength, COM_DESCRIPTOR_DIRECTORY_BYTE)
            meta.Version = self.__data__[rva + 16: rva + 16 + meta.VersionLength]
            meta2 = self.__unpack_data__(self.__METADATAHDR2_format__, self.__data__[rva + 16 + meta.VersionLength:
                        rva + 16 + meta.VersionLength + 4], rva + 16 + meta.VersionLength,
                                           COM_DESCRIPTOR_DIRECTORY_BYTE)
            meta.Flags = meta2.Flags
            meta.Streams = meta2.Streams
            meta.StreamHeaders = self.parse_streams(rva + 16 + meta.VersionLength + 4, meta.Streams, rva)

            return meta
        except PeMemError as e:
            if e.code != NULL_PAGE:
                debug.warning(e)

    def parse_streams(self, rva, number, base_address_metadata):
        streams = []
        offset = rva
        for index in range(number):

            try:
                stream = self.__unpack_data__(self.__METADATASTRAMHDR_format__, self.__data__[offset: offset + 8], offset,
                                           COM_DESCRIPTOR_DIRECTORY_BYTE)
                stream.string = self.get_string_at_rva(offset+8, COM_DESCRIPTOR_DIRECTORY_BYTE, '\x00', 4)
            except PeMemError as e:
                if e.code != NULL_PAGE:
                    debug.warning(e)
                    break

            try:
                self.set_visited(base_address_metadata + stream.offset, stream.size, COM_DESCRIPTOR_DIRECTORY_BYTE + 'Machete')
                stream.content = self.__data__[base_address_metadata + stream.offset: base_address_metadata + stream.offset+stream.size]
            except PeMemError as e:
                if e.code != NULL_PAGE:
                    debug.warning(e)

            streams.append(stream)
            offset += 8 + len(stream.string)

        return streams

    def set_zero_word(self, address):
        self.__data__ = self.__data__[:address + 2] + '\x00\x00' + self.__data__[address + 4:]

    def set_zero_double_word(self, address):
        self.__data__ = self.__data__[:address + 2] + '\x00\x00\x00\x00\x00\x00' + self.__data__[address + 8:]

class Structure(object):
    """Prepare structure object to extract members from data.

    Format is a list containing definitions for the elements
    of the structure.
    """
    def __init__(self, format, offset=None):
        # Format is forced little endian, for big endian non Intel platforms
        self.__format__ = '<'
        self.__keys__ = []
        self.__format_length__ = 0
        self.__field_offsets__ = dict()
        self.__unpacked_data_elms__ = []
        self.__set_format__(format[1])
        self.__all_zeroes__ = True
        self.__offset__ = offset
        self.__name__ = format[0]

    def __get_format__(self):
        return self.__format__

    def __set_format__(self, format):

        offset = 0
        for elm in format:
            if ',' in elm:
                elm_type, elm_name = elm.split(',', 1)
                self.__format__ += elm_type
                self.__unpacked_data_elms__.append(None)

                elm_names = elm_name.split(',')
                names = []
                for elm_name in elm_names:
                    if elm_name in self.__keys__:
                        search_list = [x[:len(elm_name)] for x in self.__keys__]
                        occ_count = search_list.count(elm_name)
                        elm_name =  '{0}_{1:d}'.format(elm_name, occ_count)
                    names.append(elm_name)
                    self.__field_offsets__[elm_name] = offset

                offset += self.sizeof_type(elm_type)

                # Some PE header structures have unions on them, so a certain
                # value might have different names, so each key has a list of
                # all the possible members referring to the data.
                self.__keys__.append(names)

        self.__format_length__ = struct.calcsize(self.__format__)

    def sizeof_type(self, t):
        count = 1
        _t = t
        if t[0] in string.digits:
            # extract the count
            count = int(''.join([d for d in t if d in string.digits]) )
            _t = ''.join([d for d in t if d not in string.digits])
        return STRUCT_SIZEOF_TYPES[_t] * count

    def get_field_absolute_offset(self, field_name):
        """Return the offset within the field for the requested field in the structure."""
        return self.__offset__ + self.__field_offsets__[field_name]

    def get_field_relative_offset(self, field_name):
        """Return the offset within the structure for the requested field."""
        return self.__field_offsets__[field_name]

    def get_offset(self):
        return self.__offset__

    def sizeof(self):
        """Return size of the structure."""
        return self.__format_length__

    def all_zeroes(self):
        """Returns true is the unpacked data is all zeros."""

        return self.__all_zeroes__

    def __unpack__(self, data):


        # OC Patch:
        # Some malware have incorrect header lengths.
        # Fail gracefully if this occurs
        # Buggy malware: a29b0118af8b7408444df81701ad5a7f
        #
        if len(data) != self.__format_length__:
            raise PEFormatError('Data length does not match with header length.')

        self.__unpacked_data_elms__ = struct.unpack(self.__format__, data)
        for i in range(len(self.__unpacked_data_elms__)):
            for key in self.__keys__[i]:
                setattr(self, key, self.__unpacked_data_elms__[i])

        for byte in data:
            if ord(byte) != 0:
                self.__all_zeroes__ = False
                break


    def __repr__(self):
        return '<Structure: %s>' % (' '.join( [' '.join(s.split()) for s in self.dump()] ))


    def dump(self, indentation=0):
        """Returns a string representation of the structure."""

        dump = []

        dump.append('[{0}]'.format(self.__name__))

        printable_bytes = [ord(i) for i in string.printable if i not in string.whitespace]

        # Refer to the __set_format__ method for an explanation
        # of the following construct.
        for keys in self.__keys__:
            for key in keys:

                val = getattr(self, key)
                if isinstance(val, (int, long)):
                    val_str = '0x%-8X' % (val)
                    if key == 'TimeDateStamp' or key == 'dwTimeStamp':
                        try:
                            val_str += ' [%s UTC]' % time.asctime(time.gmtime(val))
                        except ValueError as e:
                            val_str += ' [INVALID TIME]'
                else:
                    val_str = bytearray(val)
                    val_str = ''.join(
                            [chr(i) if (i in printable_bytes) else
                             '\\x{0:02x}'.format(i) for i in val_str.rstrip(b'\x00')])

                dump.append('0x%-8X 0x%-3X %-30s %s' % (
                    self.__field_offsets__[key] + self.__offset__,
                    self.__field_offsets__[key], key+':', val_str))

        return dump

    def dump_dict(self):
        """Returns a dictionary representation of the structure."""

        dump_dict = dict()

        dump_dict['Structure'] = self.name

        # Refer to the __set_format__ method for an explanation
        # of the following construct.
        for keys in self.__keys__:
            for key in keys:

                val = getattr(self, key)
                if isinstance(val, (int, long)):
                    if key == 'TimeDateStamp' or key == 'dwTimeStamp':
                        try:
                            val = '0x%-8X [%s UTC]' % (val, time.asctime(time.gmtime(val)))
                        except ValueError as e:
                            val = '0x%-8X [INVALID TIME]' % val
                else:
                    val = ''.join(chr(d) if chr(d) in string.printable
                                  else "\\x%02x" % d for d in
                                    [ord(c) if not isinstance(c, int) else c for c in val])

                dump_dict[key] = {'FileOffset': self.__field_offsets__[key] + self.__file_offset__,
                                  'Offset': self.__field_offsets__[key],
                                  'Value': val}

        return dump_dict


class SectionStructure(Structure):
    """Convenience section handling class."""

    @property
    def real_size(self):
        max_size = max(self.SizeOfRawData, self.VirtualSize)
        return max_size if not max_size % PAGE_SIZE else (max_size / PAGE_SIZE + 1) * PAGE_SIZE


    @property
    def data(self):
        return self.get_data()

    def get_data(self, start=None, length=None):
        """Get data chunk from a section.

        Allows to query data from the section by passing the
        addresses where the PE file would be loaded by default.
        It is then possible to retrieve code and data by its real
        addresses as it would be if loaded.

        Returns bytes() under Python 3.x and set() under 2.7
        """

        if start is None:
            offset = self.VirtualAddress
        else:
            offset = start

        if length is not None:
            end = offset + length
        else:
            end = offset + self.real_size

        return self.__pe__.__data__[offset:end]


    def contains_rva(self, rva):
        max_size = max(self.SizeOfRawData, self.VirtualSize)
        return self.VirtualAddress <= rva <= self.VirtualAddress + self.real_size


class PeMemError(Exception):
    def __init__(self, code, msg, address=None):
        self.code = code
        self.msg = msg
        self.add = address

    def __str__(self):
        return repr('Error: {}: {} - {}'.format(self.code, self.msg, self.add))

class PEFormatError(Exception):
    """Generic PE format error exception."""

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)

def all_zeros(data, start=None, end=None):
    for byte in data[start:end]:
        if ord(byte) != 0:
            return False
    return True

