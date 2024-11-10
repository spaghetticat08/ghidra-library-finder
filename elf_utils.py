"""
Some binaries/libraries need transformations before they can be used for matching byte sequences
This file contains some utility functions to edit them
It also contains helper functions for extracting info from the elf file format
"""

import subprocess
import re


def get_compiler_type_from_elf(file_name):
    """
    Retrieve which compiler was used to compile this elf.
    Note that this is only tested with GCC, this method might not work on Clang or VC
    """
    input_file_arg = "test_samples/{elf_file}".format(elf_file=file_name)
    readelf_raw_output = subprocess.run(["readelf", "-p", ".comment", input_file_arg], capture_output=True, text=True)
    
    re_expression_str = """([a-zA-Z]*)[\:]\s*(?:\([\w\s\d\.\-]*\))\s*([\d\.]*)"""

    compiler_type_output = re.findall(re_expression_str, readelf_raw_output.stdout)
    compiler_type_output = " ".join(compiler_type_output[0])
    return compiler_type_output


def neutralizeBlInstruction(file_handle, byte_sequence_with_bl):
    """
    In arm branch link instruction carries bytes that contains the offset positive or negative
    from the PC register to where the the CPU should jump to. However, in the library this is a relocation
    yet to be performed and thus will not match the binary. Therefore in a binary we will neutralize any bl instructions
    to match it with the library. We know from the ARMV6-M datasheet that bl will always be 32-bits wide and for a positive 
    jump it will start with f0xx and a negative jump will start with f7xx
    """
    #file_handle.write("\nIn neutralize_branch_without_link_instr()")
    #file_handle.write("\nAbout to neutralize following byte sequence: \n")
    #file_handle.write(byte_sequence_with_bl)
    byte_sequence_neutralized = re.sub(r"\s[\da-f]{2}\sf[0-7]\s[\da-f]{2}\s[f|d][\da-f]", " ff f7 fe ff", byte_sequence_with_bl,flags=re.IGNORECASE)

    # python's sub function has a pesky implementation that doesn't allow two adjacent matches, so we need to do this again to 
    # cover the scenario where multiple bl instructions occur
    #while (len(re.findall(r"\s[\da-f]{2}\sf[0-7]\s[\da-f]{2}\s[f|d][\da-f]", byte_sequence_neutralized)) > 0):
        #byte_sequence_neutralized = re.sub(r"\s[\da-f]{2}\sf[0-7]\s[\da-f]{2}\s[f|d][\da-f]", " ff f7 fe ff", byte_sequence_with_bl,flags=re.IGNORECASE)
    

    # only do this when debugging, it clogs up the logging file quickly
    #file_handle.write("\nNeutralized instruction: ")
    #file_handle.write(byte_sequence_neutralized)

    return byte_sequence_neutralized

