import re
import struct
from struct import unpack
from marked_pefile.marked_pefile import OPTIONAL_HEADER_MAGIC_PE, MARKS, PeMemError, PEFormatError
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
from capstone.x86_const import X86_OP_MEM, X86_OP_IMM
import pefile

PAGE_SIZE = 4096
NUM_PAD_ELEMENTS = 4
NUM_PAD_ELEMENTS_64 = 4
ELEMENTS_TO_TABLE = 3
ELEMENTS_TO_TABLE_64 = 3
LIMIT_ASCII_STRING_LEN = 5
LIMIT_UNICODE_STRING_LEN = 5

# LINEAR SWEEP DE-RELOCATION
def derelocation_OptionalHeader_ImageBase(pe):
    if pe.NT_HEADERS.OPTIONAL_HEADER.Magic == OPTIONAL_HEADER_MAGIC_PE:  # X86
        rva_BaseOfCode = pe.NT_HEADERS.OPTIONAL_HEADER.get_file_offset() + 28
        pe.set_zero_word(rva_BaseOfCode)
    else:
        rva_BaseOfCode = pe.NT_HEADERS.OPTIONAL_HEADER.get_file_offset() + 24
        pe.set_zero_double_word(rva_BaseOfCode)

def derelocation_delay_import(pe):
    if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[13].VirtualAddress and hasattr(pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[13], 'directory'):
        if pe.NT_HEADERS.OPTIONAL_HEADER.Magic == OPTIONAL_HEADER_MAGIC_PE:  # X86
            for iat_list in pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[13].directory:
                if hasattr(iat_list, 'IAT'):
                    for iat_element_index in range(iat_list.pIAT, iat_list.pIAT+4*len(iat_list.IAT), 4):
                        pe.set_zero_word(iat_element_index)
        else:
            for iat_list in pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[13].directory:
                if hasattr(iat_list, 'IAT'):
                    for iat_element_index in range(iat_list.pIAT, iat_list.pIAT+8*len(iat_list.IAT), 8):
                        pe.set_zero_double_word(iat_element_index)


def derelocation_LoadConfig(pe):
    # https://lucasg.github.io/2017/02/05/Control-Flow-Guard/
    try:
        if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].VirtualAddress and hasattr(pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10], 'directory'):
            if pe.NT_HEADERS.OPTIONAL_HEADER.Magic == OPTIONAL_HEADER_MAGIC_PE:  # X86
                if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.Size >= 36:
                    if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.LockPrefixTable:
                        pe.set_zero_word(pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.get_file_offset()+32)
                else:
                    return
                if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.Size >= 60:
                    if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.EditList:
                        pe.set_zero_word(pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.get_file_offset()+56)
                else:
                    return
                if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.Size >= 64:
                    if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.SecurityCookie:
                        pe.set_zero_word(pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.get_file_offset()+60)
                else:
                    return
                if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.Size >= 68:
                    if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.SEHandlerTable:
                        pe.set_zero_word(pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.get_file_offset()+64)
                else:
                    return
                if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.Size >= 76:
                    if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.GuardCFCheckFunctionPointer:
                        pe.set_zero_word(pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.get_file_offset()+72)
                else:
                    return
                if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.Size >= 80:
                    if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.GuardCFDispatchFunctionPointer:
                        pe.set_zero_word(pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.get_file_offset()+76)
                else:
                    return
                if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.Size >= 84:
                    if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.GuardCFFunctionTable:
                        pe.set_zero_word(pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.get_file_offset()+80)
                else:
                    return
                if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.Size >= 108:
                    if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.GuardAddressTakenIatEntryTable:
                        pe.set_zero_word(pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.get_file_offset()+108)
                else:
                    return
                if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.Size >= 116:
                    if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.GuardLongJumpTargetTable:
                        pe.set_zero_word(pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.get_file_offset()+116)
                else:
                    return
                if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.Size >= 124:
                    if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.DynamicValueRelocTable:
                        pe.set_zero_word(pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.get_file_offset()+120)
                else:
                    return
                if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.Size >= 128:
                    if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.CHPEMetadataPointer:
                        pe.set_zero_word(pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.get_file_offset()+124)
                else:
                    return

                if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.Size >= 132:
                    if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.GuardRFFailureRoutine:
                        pe.set_zero_word(pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.get_file_offset() + 128)
                else:
                    return
                if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.Size >= 136:
                    if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.GuardRFFailureRoutineFunctionPointer:
                        pe.set_zero_word(pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.get_file_offset() + 132)
                else:
                    return

                if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.Size >= 148:
                    if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.GuardRFVerifyStackPointerFunctionPointer:
                        pe.set_zero_word(pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.get_file_offset() + 144)
                else:
                    return
                if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.Size >= 160:
                    if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.EnclaveConfigurationPointer:
                        pe.set_zero_word(pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.get_file_offset() + 156)
                else:
                    return
                if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.Size >= 164:
                    if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.VolatileMetadataPointer:
                        pe.set_zero_word(pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.get_file_offset() + 160)
                else:
                    return

            else:
                if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.Size >= 48:
                    if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.LockPrefixTable:
                        pe.set_zero_double_word(pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.get_file_offset() + 40)
                else:
                    return
                if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.Size >= 88:
                    if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.EditList:
                        pe.set_zero_double_word(pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.get_file_offset() + 80)
                else:
                    return
                if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.Size >= 96:
                    if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.SecurityCookie:
                        pe.set_zero_double_word(pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.get_file_offset() + 88)
                else:
                    return
                if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.Size >= 104:
                    if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.SEHandlerTable:
                        pe.set_zero_double_word(pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.get_file_offset() + 96)
                else:
                    return
                if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.Size >= 120:
                    if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.GuardCFCheckFunctionPointer:
                        pe.set_zero_double_word(pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.get_file_offset() + 112)
                else:
                    return
                if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.Size >= 128:
                    if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.GuardCFDispatchFunctionPointer:
                        pe.set_zero_double_word(pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.get_file_offset() + 120)
                else:
                    return
                if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.Size >= 136:
                    if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.GuardCFFunctionTable:
                        pe.set_zero_double_word(pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.get_file_offset() + 128)
                else:
                    return
                if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.Size >= 168:
                    if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.GuardAddressTakenIatEntryTable:
                        pe.set_zero_double_word(pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.get_file_offset() + 160)
                else:
                    return
                if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.Size >= 184:
                    if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.GuardLongJumpTargetTable:
                        pe.set_zero_double_word(pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.get_file_offset() + 176)
                else:
                    return
                if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.Size >= 200:
                    if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.DynamicValueRelocTable:
                        pe.set_zero_double_word(pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.get_file_offset() + 192)
                else:
                    return
                if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.Size >= 208:
                    if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.CHPEMetadataPointer:
                        pe.set_zero_double_word(pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.get_file_offset() + 200)
                else:
                    return

                if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.Size >= 216:
                    if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.GuardRFFailureRoutine:
                        pe.set_zero_double_word(pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.get_file_offset() + 208)
                else:
                    return
                if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.Size >= 224:
                    if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.GuardRFFailureRoutineFunctionPointer:
                        pe.set_zero_double_word(pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.get_file_offset() + 216)
                else:
                    return

                if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.Size >= 240:
                    if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.GuardRFVerifyStackPointerFunctionPointer:
                        pe.set_zero_double_word(pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.get_file_offset() + 232)
                else:
                    return
                if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.Size >= 256:
                    if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.EnclaveConfigurationPointer:
                        pe.set_zero_double_word(pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.get_file_offset() + 248)
                else:
                    return
                if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.Size >= 264:
                    if pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.VolatileMetadataPointer:
                        pe.set_zero_double_word(pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[10].directory.get_file_offset() + 256)
                else:
                    return
    except Exception as e:
        print e


def derelocation_iat(pe):
    iat_rva = pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[12].VirtualAddress
    iat_size = pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[12].Size

    if pe.NT_HEADERS.OPTIONAL_HEADER.Magic == OPTIONAL_HEADER_MAGIC_PE:  # X86
        for index in range(iat_rva, iat_rva + iat_size, 4):
            pe.set_zero_word(index)
    else:
        for index in range(iat_rva, iat_rva + iat_size, 8):
            pe.set_zero_double_word(index)


def derelocation_code_86(pe):
    #code_section = pe.get_section_by_rva(pe.NT_HEADERS.OPTIONAL_HEADER.AddressOfEntryPoint)
    code_section =pe.get_section_by_name('.text')
    if not code_section:
        code_section =pe.get_section_by_name('dump')
        if not code_section:
            return

    # Finding strings

    # Finding UNICODE
    index = code_section.VirtualAddress
    string_len = 0
    pad_after_string = 0
    end_string = False
    while index < code_section.VirtualAddress + code_section.real_size:
        for byte_index in range(index, code_section.VirtualAddress + code_section.real_size, 2):
            if pe.__visited__[byte_index] == MARKS['UNKW_BYTE']:
                if 32 <= ord(pe.__data__[byte_index]) <= 122 and pe.__data__[byte_index + 1] == '\x00':
                    if end_string:
                        if string_len >= LIMIT_UNICODE_STRING_LEN:
                            pe.set_visited(pointer=index, size=(string_len + pad_after_string) * 2, tag=MARKS['STRING_UNICODE'])
                            address = struct.unpack('I', pe.__data__[index - 4:index])[0]
                            if pe.__base_address__ <= address <= pe.__base_address__ + pe.__size__:
                                pe.set_zero_word(index - 4)
                                pe.set_visited(pointer=index - 4, size=4, tag=MARKS['STRING_UNICODE'])
                            elif address == 2425393296:
                                address = struct.unpack('I', pe.__data__[index - 8:index - 4])[0]
                                if pe.__base_address__ <= address <= pe.__base_address__ + pe.__size__:
                                    pe.set_zero_word(index - 8)
                                    pe.set_visited(pointer=index - 8, size=8, tag=MARKS['STRING_UNICODE'])
                        index = byte_index
                        string_len = 1
                        pad_after_string = 0
                        end_string = False
                    else:
                        string_len += 1
                elif pe.__data__[byte_index] == '\x00' and pe.__data__[byte_index + 1] == '\x00':
                    if end_string:
                        pad_after_string += 1
                    else:
                        if string_len >= LIMIT_UNICODE_STRING_LEN:
                            end_string = True
                            string_len += 1
                        else:
                            index = byte_index + 2
                            string_len = 0
                            pad_after_string = 0
                            end_string = False
                elif pe.__data__[byte_index] == '\x90' and pe.__data__[byte_index + 1] == '\x90':
                    if end_string:
                        pad_after_string += 1
                    else:
                        index = byte_index + 2
                        string_len = 0
                        pad_after_string = 0
                        end_string = False
                else:
                    if string_len >= LIMIT_UNICODE_STRING_LEN and end_string:
                        pe.set_visited(pointer=index, size=(string_len + pad_after_string) * 2, tag=MARKS['STRING_UNICODE'])
                        address = struct.unpack('I', pe.__data__[index - 4:index])[0]
                        if pe.__base_address__ <= address <= pe.__base_address__ + pe.__size__:
                            pe.set_zero_word(index - 4)
                            pe.set_visited(pointer=index - 4, size=4, tag=MARKS['STRING_UNICODE'])
                        elif address == 2425393296:
                            address = struct.unpack('I', pe.__data__[index - 8:index - 4])[0]
                            if pe.__base_address__ <= address <= pe.__base_address__ + pe.__size__:
                                pe.set_zero_word(index - 8)
                                pe.set_visited(pointer=index - 8, size=8, tag=MARKS['STRING_UNICODE'])

                    index = byte_index + 2
                    string_len = 0
                    pad_after_string = 0
                    end_string = False
            else:
                if string_len >= LIMIT_UNICODE_STRING_LEN:
                    pe.set_visited(pointer=index, size=string_len + pad_after_string * 2, tag=MARKS['STRING_UNICODE'])
                    address = struct.unpack('I', pe.__data__[index - 4:index])[0]
                    if pe.__base_address__ <= address <= pe.__base_address__ + pe.__size__:
                        pe.set_zero_word(index - 4)
                        pe.set_visited(pointer=index - 4, size=4, tag=MARKS['STRING_UNICODE'])
                    elif address == 2425393296:
                        address = struct.unpack('I', pe.__data__[index - 8:index - 4])[0]
                        if pe.__base_address__ <= address <= pe.__base_address__ + pe.__size__:
                            pe.set_zero_word(index - 8)
                            pe.set_visited(pointer=index - 8, size=8, tag=MARKS['STRING_UNICODE'])
                try:
                    index = byte_index + pe.__visited__[
                                         byte_index:code_section.VirtualAddress + code_section.real_size].index(
                        MARKS['UNKW_BYTE'])
                except ValueError as e:
                    index = code_section.VirtualAddress + code_section.real_size
                string_len = 0
                pad_after_string = 0
                end_string = False
                break

    # Finding ASCII
    index = code_section.VirtualAddress
    string_len = 0
    pad_after_string = 0
    end_string = False
    while index < code_section.VirtualAddress + code_section.real_size:
        for byte_index in range(index, code_section.VirtualAddress + code_section.real_size):
            if pe.__visited__[byte_index] == MARKS['UNKW_BYTE']:
                if 32 <= ord(pe.__data__[byte_index]) <= 122:
                    if end_string:
                        if string_len >= LIMIT_ASCII_STRING_LEN and byte_index % 2 == 0:
                            pe.set_visited(pointer=index, size=string_len+pad_after_string, tag=MARKS['STRING_ASCII'])
                        index = byte_index
                        string_len = 1
                        pad_after_string = 0
                        end_string = False
                    else:
                        string_len += 1
                elif pe.__data__[byte_index] == '\x00':
                    if end_string:
                        pad_after_string += 1
                    else:
                        while string_len >= LIMIT_ASCII_STRING_LEN:
                            if index % 2 == 0:
                                end_string = True
                                string_len += 1
                                break
                            else:
                                index += 1
                                string_len -=1
                        if string_len < LIMIT_ASCII_STRING_LEN:
                            index = byte_index + 1
                            string_len = 0
                            pad_after_string = 0
                            end_string = False
                elif pe.__data__[byte_index] == '\x90':
                    if end_string:
                        pad_after_string += 1
                    else:
                        index = byte_index + 1
                        string_len = 0
                        pad_after_string = 0
                        end_string = False
                else:
                    if string_len >= LIMIT_ASCII_STRING_LEN and end_string and byte_index % 2 == 0:
                        pe.set_visited(pointer=index, size=string_len + pad_after_string, tag=MARKS['STRING_ASCII'])
                    index = byte_index + 1
                    string_len = 0
                    pad_after_string = 0
                    end_string = False
            else:
                if string_len >= LIMIT_ASCII_STRING_LEN:
                    pe.set_visited(pointer=index, size=string_len + pad_after_string, tag=MARKS['STRING_ASCII'])
                try:
                    index = byte_index + pe.__visited__[byte_index:code_section.VirtualAddress + code_section.real_size].index(MARKS['UNKW_BYTE'])
                except ValueError as e:
                    index = code_section.VirtualAddress + code_section.real_size
                string_len = 0
                pad_after_string = 0
                end_string = False
                break

    # Finding tables
    padding_elements = NUM_PAD_ELEMENTS
    num_elements = 0
    previous_element = []
    for index in range(code_section.VirtualAddress, code_section.VirtualAddress + code_section.real_size, 4):
        address = struct.unpack('I', pe.__data__[index:index + 4])[0]
        if pe.__base_address__ <= address <= pe.__base_address__ + pe.__size__:
            num_elements += 1
            if num_elements > ELEMENTS_TO_TABLE:
                not_visited = True
                for index_byte in range(index - 4 * (NUM_PAD_ELEMENTS - padding_elements), index + 4):
                    if pe.__visited__[index_byte] != MARKS['UNKW_BYTE']:
                        not_visited = False

                if not_visited:
                    pe.set_visited(pointer=index, size=4, tag=MARKS['TABLE'])
                    pe.set_zero_word(index)
                    if padding_elements != NUM_PAD_ELEMENTS:
                        pe.set_visited(pointer=index - 4 * (NUM_PAD_ELEMENTS - padding_elements),
                                       size=4 * (NUM_PAD_ELEMENTS - padding_elements), tag=MARKS['TABLE'])
            elif num_elements == ELEMENTS_TO_TABLE:
                not_visited = True
                for index_byte in range(previous_element[0], index + 4):
                    if pe.__visited__[index_byte] != MARKS['UNKW_BYTE']:
                        not_visited = False

                if not_visited:
                    pe.set_visited(pointer=previous_element[0], size=index - previous_element[0] + 4, tag=MARKS['TABLE'])
                    for element in previous_element:
                        pe.set_zero_word(element)
                    pe.set_zero_word(index)
            else:
                previous_element.append(index)
            padding_elements = NUM_PAD_ELEMENTS

        elif address == 2425393296: # '\x90\x90\x90\x90'
            if padding_elements != NUM_PAD_ELEMENTS and num_elements >= ELEMENTS_TO_TABLE:
                not_visited = True
                for index_byte in range(
                        index - 4 * (NUM_PAD_ELEMENTS - padding_elements) - 4, index - 4):
                    if pe.__visited__[index_byte] != MARKS['UNKW_BYTE']:
                        not_visited = False

                if not_visited:
                    pe.set_visited(pointer=index - 4 * (NUM_PAD_ELEMENTS - padding_elements) - 4,
                               size=4 * (NUM_PAD_ELEMENTS - padding_elements), tag=MARKS['TABLE'])
            num_elements = 0
            previous_element = []
            padding_elements = NUM_PAD_ELEMENTS

        else:
            if num_elements:
                if padding_elements:
                    padding_elements -= 1
                else:
                    num_elements = 0
                    previous_element = []
                    padding_elements = NUM_PAD_ELEMENTS

    # Finding known pattern xfe\xff\xff\xff
    index = code_section.VirtualAddress
    pattern = re.compile('\xfe\xff')
    offset = pattern.search(pe.__data__[index:code_section.VirtualAddress + code_section.real_size])
    while offset:
        if pe.__data__[index + offset.end()] == '\xff' and pe.__data__[index + offset.end()+1] == '\xff':
            index += offset.end() + 2
            address = struct.unpack('I', pe.__data__[index:index + 4])[0]
            try:
                if pe.__base_address__ <= address <= pe.__base_address__ + pe.__size__:
                    pe.set_visited(pointer=index-4, size=12, tag=MARKS['PRE_TABLE'])
                    pe.set_zero_word(index)
                    address = struct.unpack('I', pe.__data__[index + 4:index + 8])[0]
                    if pe.__base_address__ <= address <= pe.__base_address__ + pe.__size__:
                        pe.set_visited(pointer=index + 4, size=4, tag=MARKS['PRE_TABLE'])
                        pe.set_zero_word(index+4)
                else:
                    address = struct.unpack('I', pe.__data__[index + 4:index + 8])[0]
                    if pe.__base_address__ <= address <= pe.__base_address__ + pe.__size__:
                        not_visited = True
                        for index_byte in range(index-4, index-4 +16):
                            if pe.__visited__[index_byte] != MARKS['UNKW_BYTE']:
                                not_visited = False
                        if not_visited:
                            pe.set_visited(pointer=index-4, size=16, tag=MARKS['PRE_TABLE'])
                            pe.set_zero_word(index + 4)
            except PeMemError as e:
                pass
            offset = pattern.search(pe.__data__[index:code_section.real_size])

        else:
            index += offset.end()
            offset = pattern.search(pe.__data__[index:code_section.real_size])

    # disassembling
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True

    code_rva_offset = code_section.VirtualAddress
    while code_rva_offset < code_section.VirtualAddress + code_section.real_size and \
            MARKS['UNKW_BYTE'] in pe.__visited__[code_rva_offset:code_section.VirtualAddress + code_section.real_size]:

        code_rva_offset = code_rva_offset + pe.__visited__[code_rva_offset:code_section.VirtualAddress + code_section.real_size].index(MARKS['UNKW_BYTE'])
        # Finding the longest sequence of instructions
        instruction_vector = [0] * 15 # Max length of a intel instruction
        inst_adds = []
        while 0 in instruction_vector: # While exist a possible initial address
            instuction_index = instruction_vector.index(0) # First address not disassemble like instruction
            length_inst_sec = 0
            #instruction_vector[instuction_index + length_inst_sec] = -1 # Avoid inspect a instruction several times

            break_loop = False
            for inst in md.disasm(pe.__data__[code_rva_offset + instuction_index:code_section.real_size], code_rva_offset + instuction_index):
                break_loop = False
                for inst_byte in range(inst.address, inst.address+inst.size):
                    if pe.__visited__[inst_byte] != MARKS['UNKW_BYTE']:
                        break_loop = True
                if break_loop:
                    break
                length_inst_sec += inst.size
                if instuction_index + length_inst_sec < 15:
                    instruction_vector[instuction_index + length_inst_sec] = -1
                if inst.address in inst_adds:
                    length_inst_sec = -1
                    break
                else:
                    inst_adds.append(inst.address)

            instruction_vector[instuction_index] = length_inst_sec if length_inst_sec else -1 # Avoid inspect a instruction several times
            if break_loop:
                break
        max_length = max(instruction_vector)
        if max_length > 0:
            longest_index = instruction_vector.index(max_length)
            for byte in range(code_rva_offset, code_rva_offset + longest_index):
                try:
                    pe.set_visited(pointer=byte, size=1, tag=MARKS['JUMPED_BYTE'])
                except PeMemError as e:
                    if e.code == MARKS['NULL_PAGE']:
                        break
            for inst in md.disasm(pe.__data__[code_rva_offset + longest_index:code_rva_offset + longest_index + max_length], code_rva_offset+longest_index):
                #print "{}\t{}\t{}".format(hex(inst.address), inst.mnemonic, inst.op_str)
                try:
                    pe.set_visited(pointer=inst.address, size=inst.size, tag=MARKS['INSTRUCTION_BYTE'])
                    for operand in inst.operands:
                        # ToDo: Check coverage of all instruction
                        if operand.type == X86_OP_MEM and operand.mem.disp != 0 and pe.__base_address__ <= operand.mem.disp <= pe.__base_address__ + pe.__size__:
                            pe.set_zero_word(inst.address + inst.disp_offset)  # delete high value of address
                        if operand.type == X86_OP_IMM and pe.__base_address__ <= operand.imm <= pe.__base_address__ + pe.__size__:
                            pe.set_zero_word(inst.address + inst.imm_offset)
                except PeMemError as e:
                    if e.code == MARKS['NULL_PAGE']:
                        break
                    else:
                        raise e
        if pe.__visited__[code_rva_offset] == MARKS['UNKW_BYTE']:
            code_rva_offset += 1

def derelocation_code_64(pe):
    #code_section = pe.get_section_by_rva(pe.NT_HEADERS.OPTIONAL_HEADER.AddressOfEntryPoint)
    code_section =pe.get_section_by_name('.text')
    if not code_section:
        code_section =pe.get_section_by_name('dump')
        if not code_section:
            return


    for index in range(code_section.VirtualAddress, code_section.VirtualAddress + code_section.real_size, 8):
        address = struct.unpack('Q', pe.__data__[index:index + 8])[0]
        if pe.__base_address__ <= address <= pe.__base_address__ + pe.__size__:
            pe.set_zero_double_word(index)
    

def linear_sweep_derelocation(pe):
    if pe.PE_TYPE:
        derelocation_OptionalHeader_ImageBase(pe)
        derelocation_delay_import(pe)
        derelocation_LoadConfig(pe)

        derelocation_iat(pe)
        if not pe.__architecture__:
            if  pe.NT_HEADERS.OPTIONAL_HEADER.Magic == OPTIONAL_HEADER_MAGIC_PE:  # X86
                derelocation_code_86(pe)
            else:
                derelocation_code_64(pe)
            return
    if not pe.__architecture__:
        raise DerelocationError('Error: Unidentifiable architecture. ')
    elif pe.__architecture__ == '32':
        derelocation_code_86(pe)
    else:
        derelocation_code_64(pe)

    

# GUIDED DE-RELOCATION
def get_section(pe, section_name):
    for section in pe.sections:
        if section.Name[:len(section_name)] == section_name:
            return section
    return None

def valid_section(page):
    for byte in page:
        if ord(byte) != 0:
            return True
    return False

def get_pe_from_file_object(self, file_obj):
    try:
        # This code is copied from volatility/plugins/dumpfile
        all_list = []
        control_area_list = []
        offset = file_obj.obj_offset
        name = None

        if file_obj.FileName:
            name = str(file_obj.file_name_with_device())

        # The SECTION_OBJECT_POINTERS structure is used by the memory
        # manager and cache manager to store file-mapping and cache information
        # for a particular file stream. We will use it to determine what type
        # of FILE_OBJECT we have and how it should be parsed.
        if file_obj.SectionObjectPointer:
            DataSectionObject = file_obj.SectionObjectPointer.DataSectionObject
            ImageSectionObject = file_obj.SectionObjectPointer.ImageSectionObject

            # The ImageSectionObject is used to track state information for
            # an executable file stream. We will use it to extract memory
            # mapped binaries.

            if ImageSectionObject and ImageSectionObject != 0:
                summaryinfo = {}
                # It points to a image section object( CONTROL_AREA )
                control_area = ImageSectionObject.dereference_as('_CONTROL_AREA')

                if not control_area in control_area_list:
                    control_area_list.append(control_area)

                    # The format of the filenames: file.<pid>.<control_area>.[img|dat]
                    ca_offset_string = "0x{0:x}".format(control_area.obj_offset)
                    #file_string = ".".join(["file", str(pid), ca_offset_string, IMAGE_EXT])
                    #of_path = os.path.join(self._config.DUMP_DIR, file_string)
                    (mdata, zpad) = control_area.extract_ca_file(True) # Try to set True
                    summaryinfo['name'] = name
                    summaryinfo['type'] = "ImageSectionObject"
                    summaryinfo['present'] = mdata
                    summaryinfo['pad'] = zpad
                    summaryinfo['fobj'] = int(offset)
                    #summaryinfo['ofpath'] = of_path
                    all_list.append(summaryinfo)

            # The DataSectionObject is used to track state information for
            # a data file stream. We will use it to extract artifacts of
            # memory mapped data files.

            if DataSectionObject and DataSectionObject != 0:
                summaryinfo = {}
                # It points to a data section object (CONTROL_AREA)
                control_area = DataSectionObject.dereference_as('_CONTROL_AREA')

                if not control_area in control_area_list:
                    control_area_list.append(control_area)

                    # The format of the filenames: file.<pid>.<control_area>.[img|dat]
                    ca_offset_string = "0x{0:x}".format(control_area.obj_offset)

                    #file_string = ".".join(["file", str(pid), ca_offset_string, DATA_EXT])
                    #of_path = os.path.join(self._config.DUMP_DIR, file_string)

                    (mdata, zpad) = control_area.extract_ca_file(False)
                    summaryinfo['name'] = name
                    summaryinfo['type'] = "DataSectionObject"

                    summaryinfo['present'] = mdata
                    summaryinfo['pad'] = zpad
                    summaryinfo['fobj'] = int(offset)
                    #summaryinfo['ofpath'] = of_path
                    all_list.append(summaryinfo)

        output = []
        self.kaddr_space = utils.load_as(self._config)
        for summaryinfo in all_list:
            if summaryinfo['type'] == "DataSectionObject":
                if len(summaryinfo['present']) == 0:
                    continue

                for mdata in summaryinfo['present']:
                    rdata = None
                    if not mdata[0]:
                        continue

                    try:
                        rdata = self.kaddr_space.base.read(mdata[0], mdata[2])
                    except (IOError, OverflowError):
                        debug.debug("IOError: Pid: {0} File: {1} PhysAddr: {2} Size: {3}".format(summaryinfo['pid'], summaryinfo['name'], mdata[0], mdata[2]))

                    if not rdata:
                        continue
                    if len(output) < mdata[1]:
                        output += ['\x00'] * (mdata[1]-len(output))
                    if len(output) == mdata[1]:
                        output += rdata
                    if len(output) < mdata[1] + mdata[2]:
                        if len(output) < mdata[1] + mdata[2]:
                            output += ['\x00'] * (mdata[1] + mdata[2] - len(output))
                        for index in range(0, mdata[2]):
                            output[mdata[1] + index] = rdata[index]

                    continue
                # XXX Verify FileOffsets
                # for zpad in summaryinfo['pad']:
                #    of.seek(zpad[0])
                #    of.write("\0" * zpad[1])

            elif summaryinfo['type'] == "ImageSectionObject":
                if len(summaryinfo['present']) == 0:
                    continue

                for mdata in summaryinfo['present']:
                    rdata = None
                    if not mdata[0]:
                        continue

                    try:
                        rdata = self.kaddr_space.base.read(mdata[0], mdata[2])
                    except (IOError, OverflowError):
                        debug.debug("IOError: Pid: {0} File: {1} PhysAddr: {2} Size: {3}".format(summaryinfo['pid'],
                                                                                                 summaryinfo['name'],
                                                                                                 mdata[0], mdata[2]))

                    if not rdata:
                        continue
                    if len(output) < mdata[1]:
                        output += ['\x00'] * (mdata[1]-len(output))
                    if len(output) == mdata[1]:
                        output += rdata
                        continue
                    if len(output) < mdata[1] + mdata[2]:
                        if len(output) < mdata[1] + mdata[2]:
                            output += ['\x00'] * (mdata[1] + mdata[2] - len(output))
                        for index in range(0, mdata[2]):
                            output[mdata[1] + index] = rdata[index]
                    continue
            else:
                debug.debug("Caso no esperado: {0}".format(summaryinfo['type']))
        if output:
            output = ''.join(output)
            try:
                pe = pefile.PE(data=output, fast_load=True)
                del output
                return pe
            except PEFormatError:
                pass
        else:
            return None
    except AttributeError:
        debug.debug("Warning: Something was wrong when retrieving {0} from dump".format(file_obj.FileName))
        return None

def get_normalized_module_name(mod):
    # Normalizing module name
    if mod.FullDllName:
        if str(mod.FullDllName)[0] != '\\':  # "C:\folder1\folder2\.." or "D:\folder1\folder2\.."
            return str(mod.FullDllName).lower()[2::]
        elif re.search(r'\\SystemRoot', str(mod.FullDllName), re.I):  # "\SystemRoot\FolderX\.."
            return re.sub(r'^\\SystemRoot\\', r'\\Windows\\', str(mod.FullDllName)).lower()
        else:
            debug.debug('Warning: Module name pattern not recognized for {0}'.format(str(mod.FullDllName)))
            return str(mod.FullDllName).lower()
    else:
        return None

def get_reloc_section(self, mod):
    mod_sys_name = get_normalized_module_name(mod)
    if mod_sys_name:
        reloc_data = self.reloc_list.get(mod_sys_name)  # Retrieving reloc section previously found
        if not reloc_data:
            file_handler = self.files_opened_in_system.get(mod_sys_name)  # Finding file handler
            if file_handler:
                try:
                    pe = get_pe_from_file_object(self, file_handler)
                    if pe:
                        reloc_section = get_section(pe, '.reloc')
                        if reloc_section:
                            reloc_data = reloc_section.get_data()
                        if reloc_data and valid_section(reloc_data):
                            self.reloc_list[mod_sys_name] = reloc_data
                        else:
                            self.reloc_list[mod_sys_name] = None
                            debug.debug('Invalid reloc section for {0}\n'.format(file_handler.FileName))
                            return None
                    else:
                        debug.debug('Error: PEfile coulde not be created for {0}\n'.format(file_handler.FileName))
                    del pe
                except PEFormatError as e:
                    debug.debug('Error retrieving Reloc for {0}\n'.format(file_handler.FileName))
                    self.reloc_list[mod_sys_name] = None
                    return None
            else:
                debug.debug('{0} does not have file_handler\n'.format(mod_sys_name))
        return reloc_data
    else: 
        debug.debug('Error retrieving module name\n')
        return None

def acquire_sys_file_handlers(PFH, conf):
    ''' Acquiring all dlls and exes that were opened in system
    '''

    # 'scanfile' need config without processfuzzyhash parameters, deleting parameters
    config = conf.ConfObject()
    for option in ['PID', 'PROC-EXPRESSION', 'PROC-NAME', 'DLL-EXPRESSION', 'ALGORITHM', 'MODE', 'SECTION',
                   'PROTECTION', 'EXECUTABLE', 'COMPARE-HASH', 'COMPARE-FILE',
                   'HUMAN-READABLE', 'TIME', 'STRINGS', 'TMP-FOLDER', 'NO-DEVICE', 'LIST-SECTIONS', 'JSON', ]:
        config.remove_option(option)

    # Filtering end file name
    fs = plugins.filescan.FileScan(config)
    for file_opened in fs.calculate():
        if file_opened.FileName == '\$Directory':
            continue
        PFH.files_opened_in_system[str(file_opened.FileName).lower()] = file_opened

def guided_derelocation(pe, reloc):
    derelocation_OptionalHeader_ImageBase(pe)
    index = 0
    try:
        RVA_page = unpack('I', reloc[index:index + 4])[0]
        block_size = unpack('I', reloc[index + 4:index + 8])[0]
    except Exception as e:
        pass

    while block_size != 0:
        for reloc_typ_add in unpack('H'*(len(reloc[index+8:index+block_size]) / 2), reloc[index+8:index+block_size]):
            reloc_type = (reloc_typ_add & 0xF000) >> 12
            reloc_offset = (reloc_typ_add & 0x0FFF)
            if RVA_page + reloc_offset >= len(pe.__data__):  # Out of range
               continue
            if reloc_type == 0:
                continue
            elif reloc_type == 1:
                '''The base relocation adds the high 16 bits of the difference to the 16-bit field at offset. 
                The 16-bit field represents the high value of a 32-bit word.'''
                pe.__data__ = pe.__data__[:RVA_page + reloc_offset] + chr(0) + chr(
                    0) + pe.__data__[RVA_page + reloc_offset + 2:]
                debug.debug(
                    'Warning: Unrelocation error: Case {0} in block {1} offset {2}, module {3}\n'.format(
                        reloc_type, RVA_page, reloc_offset, pe.__modul_name__))

            elif reloc_type == 2:
                '''The base relocation adds the low 16 bits of the difference to the 16-bit field at offset. 
                The 16-bit field represents the low half of a 32-bit word.'''
                pe.__data__ = pe.__data__[:RVA_page + reloc_offset] + chr(0) + chr(
                    0) + pe.__data__[RVA_page + reloc_offset + 2:]
                debug.debug(
                    'Warning: Unrelocation error: Case {0} in block {1} offset {2}, module {3}\n'.format(
                        reloc_type, RVA_page, reloc_offset, pe.__modul_name__))

            elif reloc_type == 3:
                '''The base relocation applies all 32 bits of the difference to the 32-bit field at offset.'''
                # As low 16-bit of image base address are always \x00\x00, only it's necessary set higher 16-bit to zero.
                pe.__data__ = pe.__data__[:RVA_page + reloc_offset + 2] + chr(0) + chr(
                    0) + pe.__data__[RVA_page + reloc_offset + 4:]

            elif reloc_type == 4:
                '''The base relocation adds the high 16 bits of the difference to the 16-bit field at offset. 
                The 16-bit field represents the high value of a 32-bit word. The low 16 bits of the 32-bit value 
                are stored in the 16-bit word that follows this base relocation. This means that this base 
                relocation occupies two slots. '''
                pe.__data__ = pe.__data__[:RVA_page + reloc_offset] + chr(0) + chr(0) + chr(0) + \
                               chr(0) + pe.__data__[RVA_page + reloc_offset + 4:]
                debug.debug(
                    'Warning: Unrelocation error: Case {0} in block {1} offset {2}, module {3}\n'.format(
                        reloc_type, RVA_page, reloc_offset, pe.__modul_name__))
            elif reloc_type == 10:
                '''The base relocation applies the difference to the 64-bit field at offset. '''
                pe.__data__ = pe.__data__[:RVA_page + reloc_offset+2] + \
                               chr(0) + chr(0) + chr(0) + chr(0) + chr(0) + chr(0) + \
                              pe.__data__[RVA_page + reloc_offset + 8:]

            else:
                # Set 0x00 0x00 bytes modified by relocation
                pe.__data__ = pe.__data__[:RVA_page + reloc_offset] + chr(0) + chr(0) + chr(0) + \
                               chr(0) + pe.__data__[RVA_page + reloc_offset + 4:]
                '''unreloc_data[RVA_page - PAGE_SIZE + reloc_offset] = 0x00
                unreloc_data[RVA_page - PAGE_SIZE + reloc_offset + 1] = 0x00'''
                debug.debug('Warning: Unrelocation error: Case {0} in block {1} offset {2}, module {3}\n'.format(
                    reloc_type, RVA_page, reloc_offset, pe.__modul_name__))

        index += block_size
        if index+8 > len(reloc):
            break
        RVA_page = unpack('I', reloc[index:index + 4])[0]
        block_size = unpack('I', reloc[index + 4:index + 8])[0]


class DerelocationError(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return repr('Error: {}: {} - {}'.format(self.code, self.msg, self.add))