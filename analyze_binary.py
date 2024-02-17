import argparse
import re

import elf_utils
import db_utils

def dump_raw_binary_bytes(binary_name):
    """
        Dumps the binary in hexadecimal bytes using hexlify and writes it to a file 
        for analysis. In a terminal we can use hexdump but hexlify is standard python 
        library and much easier to use
        Note that this is reading raw bytes, so we have no information about the elf header, symbols,
        sections, etc.
    """

    #TODO: for very large binaries this method can cause memory errors
    # it would be good to read in chunks instead and write them
    # or alternatively not read chunks and write them but read chunks and directly try
    # to match the byte sequence
    with open('analysis-files/hexlify_'+binary_name, 'w') as w_handle:
        with open('test-samples/'+binary_name, 'rb') as r_handle:
            r_bytes = r_handle.read()
            hexlified_bytes = r_bytes.hex(' ')
            w_handle.write(hexlified_bytes)

    return 'analysis-files/hexlify_'+binary_name


def analyze_binary_byte_sections(binary_name):
    """
        This function is an enhanced version of dump_raw_binary_bytes, where we dump the bytes of a binary, but
        per section/symbol. For this we will use objdump and the result will be that bytes are stored in data structure
        The advantage is that matching is easier as we can filter out sections we don't need and the matching of bl instructions
        is also easier. However, this might miss matches as we start to work with more complex binaries.
    """
    pass



def match_byte_patterns_per_symbol(lib_mapping, bin_mapping, lib_in_db):
    """
        With two given dicts (one for the binary to analyze, the other library to compare with) the function will check per symbol
        if the byte sequence in the binary matches with one of those in the library. If there is a match, it is highly likely the
        binary makes use of this library functionality.
        Note that this function matches the byte sequence per section for both the binary and library. This is fine but for more complex
        binaries this method might miss out on matches and working with raw binary bytes would be preferred

    """
    # we will iterate through the sections present in the library mapping and check if they occur in the binary
    # note that for the bl instruction we need to search a bit different as the library does not contain all correct
    # bytes since it is a relocatable

    # we maintain a dict where we will put in our matched symbols using the format {binary symbol : symbolID}
    # this is only if we match symbols from the database!
    matched_lib_dict = dict()

    for lib_section in lib_mapping:
        bl_present = False
        
        # TODO: these are debug prints that can be removed later
        #print("Trying to match the following section and sequence:.....")
        #print(lib_section + ':' + lib_mapping[lib_section])

        # check if our function contains a bl instruction
        # TODO: maybe safer if we can check on case insensitive
        if (len(re.findall("\sf7ff\sfffe\s", lib_mapping[lib_section])) > 0):
            # there is at least one branch instruction so we need to check this seperately.
            bl_present = True

        for bin_section in bin_mapping:
            if (bl_present == True and len(re.findall(r"\s(f7[\da-f]f|f00\d)\s[\da-f]{4}", bin_mapping[bin_section])) > 0):
                bin_mapping[bin_section] = elf_utils.neutralize_branch_link_instr(bin_mapping[bin_section])

            if (bin_mapping[bin_section] == lib_mapping[lib_section]):
                if lib_in_db:
                    # since we used lib from the db we need to retrieve the function name and headers and so on
                    #db_lib_entry = db_utils.retrieve_table_entry(lib_section)
                    # print(db_lib_entry)
                    print("Matched: library section: " + str(lib_section) + " " + lib_mapping[lib_section] + " with binary section: " + str(bin_section) + " " + bin_mapping[bin_section])
                    
                    # add our match to the dict
                    matched_lib_dict.update({bin_section:lib_section})
                    break
                else:
                    print("Matched: library section: " + lib_section + lib_mapping[lib_section]+ " with binary section: " + bin_section + " " + bin_mapping[bin_section])
                    break        
    
    print(matched_lib_dict)
    return matched_lib_dict


def match_byte_patterns(byte_mapping, input_binary):
    """
        With a given binary as input and a dict that maps byte sequences to symbols (aka functions)
        we try to find in the binary ocurrences where byte sequences match the ones in the dict and thus
        prove that the symbol of that library there is being used
    """
    #TODO: also here, a large binary will likely result in memory errors
    with open(input_binary, 'r') as r_handle:
        bytes_to_be_analyzed = r_handle.read()

    for entry in byte_mapping:
        print("trying to match following sequence:.....")
        print(entry + ':' + byte_mapping[entry])
        #if (bytes_to_be_analyzed.find(byte_mapping[entry])):
        match_val = (bytes_to_be_analyzed.find(byte_mapping[entry]))
        # important to make sure the find function value is not negative, 
        # else python will just go in the if statement.
        # this is not ideal yet, if somehow we have the match on the very first
        # byte this part will fail
        if match_val > 0:
            print("Found match on index: " + str(match_val))
            print("matched: " + entry + " - " + byte_mapping[entry])

