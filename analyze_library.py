import os
import re
import subprocess

import db_utils

arm_isa = True

def map_byte_seq_to_symbol(symbolname, library_name, is_arm):
    disassemble_arg = "--disassemble={target_name}".format(target_name=symbolname)
    byte_sequence = list()
    if (is_arm == True):
        #print("objdumping for arm isa...")
        objdump_output = subprocess.run(["arm-none-eabi-objdump", disassemble_arg, library_name], capture_output=True, text=True)
        #print(objdump_output)
        byte_sequence = re.findall("(?<=:\t)((?:[\da-fA-F]{4}\s)+)", objdump_output.stdout)
        #print(byte_sequence)
    else:
        #print("objdumping for x86.....")
        objdump_output = subprocess.run(["objdump", disassemble_arg, library_name], capture_output=True, text=True)
        #print(objdump_output)
        byte_sequence = re.findall("(?<=:\t)((?:[\da-fA-F][\da-fA-F]\s)+)", objdump_output.stdout)
        #print(byte_sequence)

    for i in range(len(byte_sequence)):
        byte_sequence[i] = byte_sequence[i].rstrip()
    byte_sequence = " ".join(byte_sequence)
    #print(byte_sequence)
    return byte_sequence


def library_build_symbol_byte_mapping(library_name, is_arm):
    # with readelf or objdump we can capture the symbols of the binary
    # apparently readelf finds more than objdump
    input_library_arg = "test-samples/lib_files/{lib_name}".format(lib_name=library_name)
    sections_output = subprocess.run(["readelf", "-s", input_library_arg], capture_output=True, text= True)
    s_names = set()
    for line in sections_output.stdout.splitlines():
        fields = line.split()
        if len(fields) == 8:
            #print(fields[-1])
            if fields[-1] != 'Name':
                s_names.add(fields[-1])
    #print(s_names)

    symbol_bytes_map = dict()

    for sym in s_names:
        byte_sequence = map_byte_seq_to_symbol(sym, "test-samples/lib_files/"+library_name, is_arm)
        if len(byte_sequence) > 0:
            symbol_bytes_map.update({sym:byte_sequence})

    return symbol_bytes_map


if __name__=="__main__":

    lib_name = "liblib_collector.a"
    dir_str = "test-samples/lib_files/"
    for file_name in os.listdir(dir_str):
        print("Analyzing library: " + file_name)
        lib_symbol_byte_mapping = library_build_symbol_byte_mapping(file_name, True)
        if len(lib_symbol_byte_mapping) > 0:
            print("Library mapping results: ")
            print(lib_symbol_byte_mapping)
            db_utils.insert_library_in_table(lib_symbol_byte_mapping, file_name)
