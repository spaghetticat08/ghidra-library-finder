

def dump_binary_bytes(binary_name):
    """
        Dumps the binary in hexadecimal bytes using hexlify and writes it to a file 
        for analysis. In a terminal we can use hexdump but hexlify is standard python 
        library and much easier to use
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
        if (bytes_to_be_analyzed.find(byte_mapping[entry])):
            print("matched: " + entry + " - " + byte_mapping[entry])
