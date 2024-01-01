"""
Some binaries/libraries need transformations before they can be used for matching byte sequences
This file contains some utility functions to edit them
"""
import subprocess
import re


def neutralize_branch_link_instr(byte_sequence_with_bl):
    """
    In arm branch link instruction carries bytes that contains the offset positive or negative
    from the PC register to where the the CPU should jump to. However, in the library this is a relocation
    yet to be performed and thus will not match the binary. Therefore in a binary we will neutralize any bl instructions
    to match it with the library. We know from the ARMV6-M datasheet that bl will always be 32-bits wide and for a positive 
    jump it will start with f0xx and a negative jump will start with f7xx
    """
    #print("About to neutralize the following section....")
    #print(byte_sequence_with_bl)
    byte_sequence_neutralized = re.sub(r"\s(f7[\da-f]f|f00\d)\s[\da-f]{4}", " f7ff fffe", byte_sequence_with_bl,flags=re.IGNORECASE)
    return byte_sequence_neutralized

