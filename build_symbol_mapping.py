import argparse
import logging
import re
import shlex
import subprocess

import analyze_binary
import db_utils

arm_isa = False
# not so pretty variable to use our db instead of mapping the library
lib_in_db = True

#logging.basicConfig(filename='result_log.txt', encoding='utf-8', level=logging.ERROR)


def map_byte_seq_to_symbol(symbolname, library_name):
    disassemble_arg = "--disassemble={target_name}".format(target_name=symbolname)
    byte_sequence = list()
    if arm_isa:
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


def dump_binary(binary_name):
    # Dump binary contents in a file, helper function
    with open('dump_'+binary_name, 'w') as outfile:
        if arm_isa:
            subprocess.run(["arm-none-eabi-objdump", "-d", binary_name], stdout=outfile)
        else:
            subprocess.run(["objdump", "-d", binary_name], stdout=outfile)



def library_build_symbol_byte_mapping(library_name):

    # with readelf or objdump we can capture the symbols of the binary
    # apparently readelf finds more than objdump
    input_library_arg = "test-samples/{lib_name}".format(lib_name=library_name)
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
        #TODO: change libmylib.so to a variable to support variable binary input
        byte_sequence = map_byte_seq_to_symbol(sym, "test-samples/"+library_name)
        if len(byte_sequence) > 0:
            symbol_bytes_map.update({sym:byte_sequence})

    return symbol_bytes_map


    #TODO: move this to a different python script    
    #bin_dump_output = subprocess.run(["hexdump", " -ve", "'1/1", "\"", "", "%02x\"'", "libmylib.so"], capture_output=True, text=True)
    #if (bin_dump_output.stdout.find(symbol_bytes_map["sum_up"])):
        #print("Found substring!")
    #else:
        #print("didnt find the match :(")



def analyze_dump(library_name, binary_name, arm_arch):
    
    # TODO: need more structuring
    bin_symbol_byte_mapping = library_build_symbol_byte_mapping(binary_name)
    #print("----------- binary symbol byte mapping -------")
    #print(bin_symbol_byte_mapping)
    
    if lib_in_db:
        # no need to analyze library, use the database
        lib_mapping = db_utils.load_function_bytes_in_struct()
        # we need to convert out lib_symbol mapping from a list of tuples into a dict {rowid : function_bytes}
        lib_symbol_mapping_dict = dict()
        for elem in lib_mapping:
            lib_symbol_mapping_dict.update({elem[0]:elem[1]})

        analyze_binary.match_byte_patterns_per_symbol(lib_symbol_mapping_dict, bin_symbol_byte_mapping, True)

    else:
        #TODO add argparser to add it as a parameter instead of hardcoded
        #symbol_byte_mapping = library_build_symbol_byte_mapping("test-samples/libmylib.so")
        if (arm_arch):
            arm_isa = True
        lib_symbol_byte_mapping = library_build_symbol_byte_mapping(library_name)
        #print("----------library symbol byte mapping -------")
        #print(lib_symbol_byte_mapping)
        analyze_binary.match_byte_patterns_per_symbol(lib_symbol_byte_mapping, bin_symbol_byte_mapping, False)
        #analysis_file = analyze_binary.dump_raw_binary_bytes(binary_name)
        #analyze_binary.match_byte_patterns(lib_symbol_byte_mapping, analysis_file)
 

if __name__=="__main__":
    parser = argparse.ArgumentParser(
                        prog='Library-finder',
                        description='Analyzes libraries and searches byte sequences that matches in binaries'
                        )
    parser.add_argument('--lib', dest='library_name', required=True, 
                        help='library which symbols and byte sequences should be parsed. For now only supports libraries stored in the test-samples folder')
    parser.add_argument('--binary', dest='binary_name', required=True)
    parser.add_argument('--arm', default=False, action='store_true')
    parser.add_argument('')
    args = parser.parse_args()

    #TODO: clean up the print statements and use logging module for cleaner logging
    if (args.arm):
        arm_isa = True
    analyze_dump(args.library_name, args.binary_name, args.arm)
