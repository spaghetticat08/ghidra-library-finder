


from binascii import hexlify


from ghidra.app.decompiler import DecompileOptions, DecompInterface
from ghidra.util.task import ConsoleTaskMonitor


def signedIntToUnsigned(input_value):
    """
        Small helper function to convert signed integer to unsigned. This is 
        required because the Ghidra api retrieves with getBytes bytes, but in 
        java a byte is a signed value from -127 to 127. The jep python wrapper 
        converts this to an int in the python array but python cant deal with signed
        values and covnerting it to a byte would result in a value error.
        Hence, this function retrieves the respective unsigned value ranging from 0 to 256
    """
    return input_value % 256


def getBytesInFunction(current_function, current_listing):
    """
        Retrieve the bytes from a given ghidra function object
    """
    function_bytes_list = list()
    function_address_set = current_function.getBody()
    codeUnits = current_listing.getCodeUnits(function_address_set, True)

    for codeUnit in codeUnits:
        codeUnit_bytes = codeUnit.getBytes()
        function_bytes_list.append(bytes(map(signedIntToUnsigned, codeUnit_bytes)).hex(' ', 1))

    function_bytes_sequence = ' '.join(function_bytes_list)
    return function_bytes_sequence


def mapBytesToAllFunctionsInProgram(file_handle, current_program):
    """
        This function iterates through all functions present in a program, retrieves their bytes and
        stores these in a dict
    """
    file_handle.write("\nIn mapBytesToAllFunctionsInProgram()\n")
    current_listing = current_program.getListing()

    # Use the function manager to retrieve all functions
    function_manager = current_program.getFunctionManager()
    function_iterator = function_manager.getFunctions(True)

    file_handle.write("Processing {} functions\n".format(function_iterator.__sizeof__()))
    #print("Processing {} functions".format(function_iterator.__sizeof__()))
    function_bytes_map = dict()

    while (function_iterator.hasNext()):
        function_elem = function_iterator.next()
        if function_elem.isThunk() == True:
            # skip thunked functions for now
            continue
        function_bytes = getBytesInFunction(function_elem, current_listing)
        function_name = function_elem.getName()

        function_bytes_map.update({function_name:function_bytes})
    return function_bytes_map

