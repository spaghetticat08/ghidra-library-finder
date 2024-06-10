# analyzer function that uses ghidra analysis capabilities to store analyzed functions for the library finder
#@author
#@category Python 3
#@keybinding
#@menupath
#@toolbar

import os
import re
import subprocess

from binascii import hexlify

from ghidra.app.decompiler import DecompileOptions, DecompInterface
from ghidra.util.task import ConsoleTaskMonitor


current_program = getCurrentProgram()
current_listing = current_program.getListing()

def signed_int_to_unsigned(input_value):
    """
        Small helper function to convert signed integer to unsigned. This is 
        required because the Ghidra api retrieves with getBytes bytes, but in 
        java a byte is a signed value from -127 to 127. The jep python wrapper 
        converts this to an int in the python array but python cant deal with signed
        values and covnerting it to a byte would result in a value error.
        Hence, this function retrieves the respective unsigned value ranging from 0 to 256
    """
    return input_value % 256



def getBytesInFunction(current_function):
    """
        Retrieve the bytes from a given ghidra function object
    """
    function_bytes_list = list()
    function_address_set = current_function.getBody()
    codeUnits = current_listing.getCodeUnits(function_address_set, True)

    for codeUnit in codeUnits:
        codeUnit_bytes = codeUnit.getBytes()
        function_bytes_list.append(bytes(map(signed_int_to_unsigned, codeUnit_bytes)).hex(' ', 1))

    function_bytes_sequence = ' '.join(function_bytes_list)
    return function_bytes_sequence



def mapBytesToAllFunctionsInProgram():
    """
        This function iterates through all functions present in a program, retrieves their bytes and
        stores these in a dict
    """
    # Use the function manager to retrieve all functions
    function_manager = current_program.getFunctionManager()
    function_iterator = function_manager.getFunctions(True)

    function_bytes_map = dict()

    while (function_iterator.hasNext()):
        function_elem = function_iterator.next()
        function_bytes = getBytesInFunction(function_elem)
        function_name = function_elem.getName()

        function_bytes_map.update({function_name:function_bytes})
    return function_bytes_map


        
output_handle = open('/home/happy-pony/Projects/ghidra_scripts/output_data/ghidra_analyzer_out', 'w')

function_symbol_map = mapBytesToAllFunctionsInProgram()
for function_elem in function_symbol_map:
    output_handle.write("{}  :  {}\n".format(function_elem,function_symbol_map[function_elem]))

output_handle.close()