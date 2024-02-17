import argparse
import datetime
import logging
import os

import analyze_binary
import analyze_library
import build_symbol_mapping
import db_utils

#TODO: look into creating own logger since we will need it over several modules
#logfile_name = datetime.datetime.now().strftime("%y_%m_%d_%H_%M") + "_lib_finder_run.log"
#logging.basicConfig(filename=logfile_name, format='%(asctime)s - %(levelname)s - %(message)s')

def analyze_library_and_store_db(lib_file, comp_type, comp_flags, headers, lib_name, plat_type, is_arm):
    lib_symbol_byte_mapping = analyze_library.library_build_symbol_byte_mapping(lib_file, is_arm)
    print(lib_symbol_byte_mapping)
    lib_db_entries = db_utils.get_library_based_on_all_but_id(lib_name, comp_type, comp_flags, plat_type, headers)
    if (len(lib_db_entries) > 0):
        # The library already exists in this db, we should proceed to retrieve the libraryID and
        # then check in the symbols table whether these symbols based on the linked libraryID exist
        # TODO: we leave this for the future, for now we assume that we will only add the library and symbols once
        print("Library already exists in database, please check if symbols are already present!")

    library_id = db_utils.insert_libraries_entry(lib_name, plat_type, comp_type, comp_flags, headers)

    for symbol_byte_elem in lib_symbol_byte_mapping:
        print("symbol: " + symbol_byte_elem)
        print("symbol bytecode: " + lib_symbol_byte_mapping[symbol_byte_elem])
        db_utils.insert_symbols_entry(library_id, symbol_byte_elem, lib_symbol_byte_mapping[symbol_byte_elem])

    print("Finished analyzing library and saving to database!")


def match_binary_with_db(bin_file, is_arm):
    bin_symbol_byte_mapping = build_symbol_mapping.library_build_symbol_byte_mapping(bin_file, is_arm)
    db_bytecode_mappping = db_utils.load_bytecode_in_struct()
    
    # we convert the list of tuples into a dict of form {symbolID : bytecode}
    symbol_bytecode_mapping_dict = dict()
    for elem in db_bytecode_mappping:
        symbol_bytecode_mapping_dict.update({elem[0]:elem[3]})
    
    matched_bin_symbols_dict = analyze_binary.match_byte_patterns_per_symbol(symbol_bytecode_mapping_dict, bin_symbol_byte_mapping, True)
    library_id_set = set()
    # We receive a dict back that has for each binary symbol the matched symbolID from the db, so now we should
    # per match retrieve the libraryID that is linked to the symbolID and with that we can retrieve the headers
    for matched_elem in matched_bin_symbols_dict:
        linked_library_id = db_utils.get_linked_libraryID_from_symbolID(matched_bin_symbols_dict[matched_elem])
        if (linked_library_id not in library_id_set):
            library_id_set.add(linked_library_id)

    # once we have a set with unique libraryID's, we can retrieve them from the database and extract the headers used
    headers_set = set()
    for lib_elem in library_id_set:
        library_db_entry = db_utils.get_libraries_based_on_id(lib_elem)
        headers_set.add(library_db_entry[0][5])

    print("The following headers need to be included: ")
    print(headers_set)


def match_binary_with_lib_file(bin_file, lib_file, is_arm):
    bin_symbol_byte_mapping = build_symbol_mapping.library_build_symbol_byte_mapping(bin_file, is_arm)
    lib_symbol_byte_mapping = analyze_library.library_build_symbol_byte_mapping(lib_file, is_arm)

    analyze_binary.match_byte_patterns_per_symbol(lib_symbol_byte_mapping, bin_symbol_byte_mapping, False)


if __name__=="__main__":
    parser = argparse.ArgumentParser(
        prog='Library-finder',
        description='Analyzer for libraries and binaries to match functions'
    )

    
    parser.add_argument('--arm', default=False, action='store_true')
    subparsers = parser.add_subparsers(help='sub-command help', dest='command')

    # create parser to analyze the library
    parser_analyze_lib = subparsers.add_parser('analyze', help='analyze a library and save it into the db')
    parser_analyze_lib.add_argument('library_file')
    parser_analyze_lib.add_argument('-c', '--compiler', dest='compiler_type', default='gcc')
    # TODO: we might want to ensure that a list of arguments for this one is supplied
    parser_analyze_lib.add_argument('-f', '--compilerflags', dest='compiler_flags')
    parser_analyze_lib.add_argument('-i', '--headerfiles', dest='header_files')
    parser_analyze_lib.add_argument('-l', '--lib_name', dest='library_name')
    parser_analyze_lib.add_argument('-p', '--platform', dest='platform_arch')
    #parser_analyze_lib.add_argument('--arm', default=False, action='store_true')
    # TODO: We might add this functionality later
    #parser_analyze_lib.add_argument('-x', '--extract_from_file', dest='manual_extract', help='Perform manual extraction of the other parameters instead of passing them as arguments')

    # create parser to match binary
    parser_match_bin_db = subparsers.add_parser('match', help='analyze a binary and match functions found in the db or in a given library file to match with')
    parser_match_bin_db.add_argument('binary_file')

    parser_match_bin_man = subparsers.add_parser('compare', help='analyze a binary and match functions found in the given library file')
    parser_match_bin_man.add_argument('binary_file')
    parser_match_bin_man.add_argument('library_file')

    args = parser.parse_args()
    print(args)
    print(args.command)

    if (args.command == 'analyze'):
        print("Analyze subcommand invoked")
        analyze_library_and_store_db(args.library_file, args.compiler_type, args.compiler_flags, args.header_files, args.library_name, args.platform_arch, args.arm)
    elif (args.command == 'match'):
        print("Match subcommand invoked")
        match_binary_with_db(args.binary_file, args.arm)
    elif (args.command == 'compare'):
        print("Compare subcommand inoked")
        match_binary_with_lib_file(args.binary_file, args.library_file, args.arm)
    else:
        print("No valid subcommand found")