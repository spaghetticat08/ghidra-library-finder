import subprocess
import re
import shlex


def map_byte_seq_to_symbol():
    pass


def retrieve_sections():
    # with readelf or objdump we can capture the symbols of the binary
    # apparently readelf finds more than objdump
    sections_output = subprocess.run(["readelf", "-s", "libmylib.so"], capture_output=True, text= True)
    s_names = set()
    for line in sections_output.stdout.splitlines():
        fields = line.split()
        if len(fields) == 8:
            #print(fields[-1])
            if fields[-1] != 'Name':
                s_names.add(fields[-1])
    #print(s_names)

    symbol_bytes_map = dict()
    #for elem in s_names:
        #disassemble_arg = "--disassemble={symbol_name}".format(symbol_name=elem)
        #objdump_output = subprocess.run(["objdump", disassemble_arg, "libmylib.so"], capture_output=True, text=True)

        #print("Output of " + elem +":\n" + objdump_output.stdout)
        #obj_matches = re.findall("(?<=:\t)((?:[\da-fA-F][\da-fA-F]\s)+)",objdump_output)
        #print(obj_matches)

    objdump_output = subprocess.run(["objdump", "--disassemble=sum_up", "libmylib.so"], capture_output=True, text=True)

    #print("Output of " + objdump_output.stdout)
    
    obj_matches = re.findall("(?<=:\t)((?:[\da-fA-F][\da-fA-F]\s)+)",objdump_output.stdout)
    for i in range(len(obj_matches)):
        obj_matches[i] = obj_matches[i].rstrip()
    #print(obj_matches)
    #print(" ".join(obj_matches))
    obj_matches = " ".join(obj_matches)

    symbol_bytes_map.update({"sum_up":obj_matches})
    print(symbol_bytes_map)


    # We should split this later, but for testing now we keep this as one whole function
    # dump the binary in pure bytes hex format
    #hexdump_args = shlex.split("""hexdump -ve '1/1 " %02x"' libmylib.so""")
    bin_dump_output = subprocess.run(["hexdump", " -ve", "'1/1", "\"", "", "%02x\"'", "libmylib.so"], capture_output=True, text=True)
    if (bin_dump_output.stdout.find(symbol_bytes_map["sum_up"])):
        print("Found substring!")
    else:
        print("didnt find the match :(")


def dump_binary():
    with open('dump_libmylibso', 'w') as outfile:
        subprocess.run(["objdump", "-d", "libmylib.so"], stdout=outfile)


def analyze_dump():
    dump_binary()
    retrieve_sections()


if __name__=="__main__":
    analyze_dump()