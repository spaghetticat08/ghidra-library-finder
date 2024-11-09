# analyzer function that uses ghidra analysis capabilities to store analyzed functions for the library finder
#@author
#@category Python 3
#@keybinding
#@menupath
#@toolbar


import datetime
import logging
import os
from pathlib import Path

import db_utils
import ghidra_analyzer
import ghidra_matcher


#TODO: look into creating own logger since we will need it over several modules
#logfile_name = datetime.datetime.now().strftime("%y_%m_%d_%H_%M") + "_lib_finder_run.log"
#logging.basicConfig(filename=logfile_name, format='%(asctime)s - %(levelname)s - %(message)s')


def findFunctionMatches(current_prog, file_handle, db_name):
    
    file_handle.write("\nIn findFunctionMatches()")
    # this list will be returned ad the end for reporting. It contains combined info in the following format:
    # List of tuples: [(librayId, libraryName, headerfile, symbolId, symbolName, symbolBytecode)] 
    # [(1, "gpio_libs", "stdio.h", 3, "gpio_init", "de ad be ef 00 00"), (1, "gpio_libs", "stdio.h", 7, "gpio_deinit", "aa bb cc dd ee ff")]
    found_function_matches_list = list()
    # this program should first get all functions in this program and their byte mapping
    input_fb_mapping = ghidra_analyzer.mapBytesToAllFunctionsInProgram(file_handle, current_prog)
    # ask user to search smart (so retrieve program properties like architecture, compiler, etc.) or
    # to do a full search
    # only enable this print if really needed because it clogs up the logging file
    #file_handle.write("\nFunction bytecode mapping of input file:\n")
    #file_handle.write(str(input_fb_mapping))

    search_algorithm = askChoice("Choose type of search", "Do you want to do a smart search(reduce time) or full search?", ["smart", "full"], "full")
        # if smart search is chose, we filter libraries from the db based on the architecture (maybe later differen filters)
        # the smart search should reduce the runtime of the matching 
    if search_algorithm == "smart":
        pass
    elif search_algorithm == "full":
        # first we should query the number of libraries from the db and their libraryIda
        library_id_set = set()
        matched_symbol_id_set = set()
        db_library_id_list = db_utils.getLibraryIdOfAllLibraries(db_name)
        
        for library_id in db_library_id_list:
            library_id_set.add(library_id[0])

        if (len(library_id_set) > 0):
        # if we do full search we will retrieve per library the function byte mapping
            for library_id in library_id_set:
                # retrieve the corresponding functions and store them in a dict {functionId : function bytecode}
                db_symbol_struct = db_utils.getSymbolsBasedOnLibraryId(db_name, library_id)
                reference_fb_mapping = dict()
                for symbol_elem in db_symbol_struct:
                    reference_fb_mapping.update({symbol_elem[0]:symbol_elem[3]})
                
                # retrieve a set that is either empty or contains symbolIds of matched functions
                matched_symbol_id_subset = ghidra_matcher.matchByteSequencesFromInputs(file_handle, reference_fb_mapping, input_fb_mapping)    
                matched_symbol_id_set.update(matched_symbol_id_subset)            
        else:
            # library db is empty, no point in continueing further
            print("Oops! Seems that the datbase is empty. Ending the script")
            return
        
        # after iterating through the entire set of symbols within all libraries
        # we have a set of all symbolIds that were matched. We can now per symbolId 
        # get the symbolname, libraryId and header and report this
        # this algorithm can likely be more optimized but we leave it for now as is.
        for symbol_id in matched_symbol_id_set:
            db_symbol_struct = db_utils.getSymbolBasedOnSymbolId(db_name, symbol_id)
            file_handle.write("\nfindFunctionMatches() >> db_symbol_struct retrieved : {}".format(db_symbol_struct))
            db_library_struct = db_utils.getLibraryBasedOnLibraryId(db_name, db_symbol_struct[1])
            file_handle.write("\nfindFunctionMatches() >> db_library_struct retrieved : {}".format(db_library_struct))
            # update this list for reporting
            found_function_matches_list.append((db_library_struct[0], db_library_struct[1], db_library_struct[5], db_symbol_struct[0], db_symbol_struct[2], db_symbol_struct[3]))    
        # once the search ends, use the earlier created structure to extract the headers and report
    return found_function_matches_list


def analyzeFunctionsAndAddToDB(current_prog, file_handle, db_name):
    
    # request if user wants a different name than ghidra retrieves
    program_name = current_prog.getName()[:-4]

    user_library_name = askString("Input library name", "Input the name for the library", program_name)
    # ask platform arch
    # for now we only get the processor, later we can improve this
    platform_arch = current_prog.getLanguage().getProcessor().toString()
    user_platform_arch = askString("Input architecture", "Input the name for the architecture: (ARM/x86/MIPS/Xtensa)", platform_arch)
    # ask compiler type
    # we cannot currently retrieve this from ghidra. Probably with readelf
    compiler_type = askString("Input compiler", "Input the compiler this library is compiled with (default gcc)", "gcc")
    # ask compiler arguments
    # this is pretty advanced, won't do much with it for now
    compiler_args = askString("Input compilerflags", "Input compiler flags used to compiler this library (default none)", "none")
    # ask headerfiles
    headerfiles = askString("Input headers", "Input include headers that code should use (please include quotes and seperate with spaces)", "")

    # log user input
    file_handle.write("Received following user input: library name = {}, architecture = {}, compiler = {}, \
                      compiler flags = {}, headerfiles {}\n\n".format(user_library_name, user_platform_arch, compiler_type, compiler_args, headerfiles))

    # start retrieving all functions in ghidra mapped to bytecode per function
    functions_bytecode_mapping = ghidra_analyzer.mapBytesToAllFunctionsInProgram(file_handle, current_prog)

    file_handle.write("Analyzed and identfied the following function bytecode mappping:\n")
    for function_elem in functions_bytecode_mapping:
        file_handle.write("{}   :   {}\n".format(function_elem, functions_bytecode_mapping[function_elem]))
    
    # search for existing library in db
    library_db_res = db_utils.getLibraryBasedOnAllButId(db_name, user_library_name, platform_arch, compiler_type, compiler_args, headerfiles)

    if (len(library_db_res) > 0 ):
        # if library exists, we should check per function
        # not supported atm for now we reject the script run 
        print("library already exists, stopping this script")
        return

        # else we make new library entry in db and retrieve linked libray id
    else:
        db_library_id = db_utils.addLibraryToDB(db_name, user_library_name, user_platform_arch, compiler_type, compiler_args, headerfiles)

        # iterate per function byte pair and add function entry in db linked to
        # library id
        # to make it more efficient we sent the whole dict to db_utils and let them 
        #iterate and add to the db
        db_utils.addMultipleFunctionsOneLibraryToDB(db_name, db_library_id, functions_bytecode_mapping)
        file_handle.write("Adding library and functions to DB done!")



if __name__=="__main__":

    project_location = Path.home().joinpath('Projects').joinpath('RE_embedded').joinpath('ghidra-library-finder')

    output_file_name = os.path.join(project_location, "ghidra_library_finder_log.txt")
    # file to dump all debugging info in
    with open(output_file_name, 'w') as output_file_handle:
    #output_file_handle = open(output_file_name, 'w')
        output_file_handle.write("New run started at : {}\n".format(datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S")))

        # This method is easier to extend program options
        choice_arr = ["Add library to db", "Find match in db", "Create db", "Delete table"]
        action = askChoice("action", "Please choose what action to perform", choice_arr, choice_arr[0])

        output_file_handle.write("Action selected: {}\n".format(action))

        # quick and dirty variable to save ourself from mistakes
        default_db_name = "pico_libraries"

        current_program = getCurrentProgram()
        # if action is to add library to db
        if action == choice_arr[0]:
            db_name = askString("Db name","Please provide a name for the database", default_db_name)
            db_name = str(project_location / (db_name+".db"))

            analyzeFunctionsAndAddToDB(current_program, output_file_handle, db_name)

        # Find matches for the functions in our opened binary
        elif action == choice_arr[1]:
            db_name = askString("Db name","Please provide a name for the database", default_db_name)
            db_name = str(project_location / (db_name+".db"))


            found_matched_list = findFunctionMatches(current_program, output_file_handle, db_name)

            if (len(found_matched_list) > 0):
                change_code = askYesNo("Insert libraries", "We have found matched library functions, would you like to insert the headers?")
                if (change_code):
                    # insert the header files in the struct on top of the code
                    # implement later
                    # we cannot currently implement it as ghidra doesn't allow us to 
                    # add #include statements in the listing. So for now we will just report
                    # this in our logging file
                    pass
                else:
                    # do nothing, we will report our matches anyway
                    pass
                
                generate_report = askYesNo("Generate Report", "Do you want to generate a report with all identified functions and libraries?")
                if generate_report:
                    report_name = os.path.join(project_location, "matched_functions_report.txt")
                    with open(report_name, 'w') as report_file_handle:
                        for match_elem in found_matched_list:
                            report_file_handle.write("\nLibrary={lib_name}, Function={func_name}, Headerfile={header_name}\n".format(lib_name=match_elem[1], func_name=match_elem[4], header_name=match_elem[2]))
                output_file_handle.write("\nReport of the found matches:\n")
                for match_elem in found_matched_list:
                    output_file_handle.write(str(match_elem) + "\n")

                
        # create database
        elif action == choice_arr[2]:
            db_name = askString("Db name","Please provide a name for the database", default_db_name)
            db_name = str(project_location / (db_name+".db"))
            db_utils.createNewDB(db_name)
            print("Db created!")

        # delete database
        elif action == choice_arr[3]:
            db_name = askString("Db name","Please type name of db", default_db_name)
            db_name = str(project_location / (db_name +".db"))
            table_names = db_utils.getAllTablesFromDB(db_name)
            table_delete_list = askChoices("Delete tables", "Please select which tables to delete", table_names)
            confirm_str = askYesNo("Delete", "Are you sure you want to delete tables?")
            if confirm_str:
                for table_item in table_delete_list:
                    db_utils.delete_table(db_name, table_item)
        else:
            print("Whoops! Seems like no valid action was chosen. Ending the script...")


        #output_file_handle.close()

