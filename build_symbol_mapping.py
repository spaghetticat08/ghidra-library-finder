import argparse
import subprocess
import re
import shlex

import analyze_binary

def map_byte_seq_to_symbol(symbolname, binary_name):
    disassemble_arg = "--disassemble={target_name}".format(target_name=symbolname)
    objdump_output = subprocess.run(["objdump", disassemble_arg, binary_name], capture_output=True, text=True)
    byte_sequence = re.findall("(?<=:\t)((?:[\da-fA-F][\da-fA-F]\s)+)", objdump_output.stdout)

    for i in range(len(byte_sequence)):
        byte_sequence[i] = byte_sequence[i].rstrip()
    byte_sequence = " ".join(byte_sequence)
    return byte_sequence


def dump_binary(binary_name):
    # Dump binary contents in a file, helper function
    with open('dump_'+binary_name, 'w') as outfile:
        subprocess.run(["objdump", "-d", binary_name], stdout=outfile)


def build_symbol_byte_mapping(binary_name):

    # with readelf or objdump we can capture the symbols of the binary
    # apparently readelf finds more than objdump
    input_binary_arg = "test-samples/{bin_name}".format(bin_name=binary_name)
    sections_output = subprocess.run(["readelf", "-s", input_binary_arg], capture_output=True, text= True)
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
        byte_sequence = map_byte_seq_to_symbol(sym, "test-samples/"+binary_name)
        symbol_bytes_map.update({sym:byte_sequence})

    return symbol_bytes_map

    #TODO: move this to a different python script    
    #bin_dump_output = subprocess.run(["hexdump", " -ve", "'1/1", "\"", "", "%02x\"'", "libmylib.so"], capture_output=True, text=True)
    #if (bin_dump_output.stdout.find(symbol_bytes_map["sum_up"])):
        #print("Found substring!")
    #else:
        #print("didnt find the match :(")



def analyze_dump(library_name, binary_name):
    #TODO add argparser to add it as a parameter instead of hardcoded
    #symbol_byte_mapping = build_symbol_byte_mapping("test-samples/libmylib.so")
    symbol_byte_mapping = build_symbol_byte_mapping(library_name)
    print(symbol_byte_mapping)

    analysis_file = analyze_binary.dump_binary_bytes(binary_name)
    analyze_binary.match_byte_patterns(symbol_byte_mapping, analysis_file)
 

if __name__=="__main__":
    parser = argparse.ArgumentParser(
                        prog='Library-finder',
                        description='Analyzes libraries and searches byte sequences that matches in binaries'
                        )
    parser.add_argument('--lib', dest='library_name', required=True, 
                        help='library which symbols and byte sequences should be parsed. For now only supports libraries stored in the test-samples folder')
    parser.add_argument('--binary', dest='binary_name', required=True)
    args = parser.parse_args()

    analyze_dump(args.library_name, args.binary_name)
