"""
This file contains utility functions to save our analyzed libraries into a database and retrieve library functions from the database
"""

import sqlite3

def create_lib_finder_db(db_name):
    conn = sqlite3.connect(str(db_name))
    cursor = conn.cursor()

    libraries_table_string = """ CREATE TABLE IF NOT EXISTS libraries ( libraryID INTEGER PRIMARY KEY, libraryName TEXT, platformArch TEXT, compiler TEXT, compilerFlags TEXT, headerfiles TEXT)"""
    symbols_table_string = """ CREATE TABLE IF NOT EXISTS symbols ( symbolID INTEGER PRIMARY KEY, libraryID INTEGER, symbolName TEXT, symbolBytecode BLOB, FOREIGN KEY(libraryID) REFERENCES libraries(libraryID)) """

    cursor.execute(libraries_table_string)
    cursor.execute(symbols_table_string)

    # we will insert a dummy value in both tables and then remove them to test our database
    cursor.execute("INSERT INTO libraries(libraryID, libraryName, platformArch, compiler, compilerFlags, headerfiles) VALUES (2, 'dummy_lib', 'dummy_arch', 'dummy_gcc', '-d -u -m -m -y', 'path/to/dummy/lib')")
    cursor.execute("INSERT INTO symbols(libraryID, symbolName, symbolBytecode) VALUES(2, 'dummy_symbol', '48 8d 3d d9 2f 00 00 48 8d 05 d2 2f 00 00 48 39 f8') ")
    conn.commit()

    res = cursor.execute("SELECT name FROM sqlite_master")
    print(res.fetchall())
    res = cursor.execute("SELECT * FROM libraries")
    print(res.fetchall())
    res = cursor.execute("SELECT * FROM symbols")
    print(res.fetchall())

    res = cursor.execute("DELETE FROM symbols WHERE symbolName='dummy_symbol' ")
    res = cursor.execute("DELETE FROM libraries WHERE libraryName='dummy_lib' ")
    conn.commit()

    res = cursor.execute("SELECT * FROM libraries").fetchall()
    print(res)
    res = cursor.execute("SELECT * FROM symbols").fetchall()
    print(res)

    conn.close()


def test_initial_db():
    """
    Function to create the db for the first time. We use Sqlite3 and for now have one table with the following fields:
        - library_name : the name of the object file (not unique)
        - function_name : the name of a function from a library(unique per library)
        - function_bytes : sequence of bytes that belong to a function of a library
        A more efficient database could be made later where we split the table in a library table and function table, but for time constraints
        we keep it simple now.
        Note: Sqlite has no native array type so we have to convert our list/array/whatever to a string representation
    """
    conn = sqlite3.connect("libraries.db")
    cursor = conn.cursor()

    library_table_string = """ CREATE TABLE IF NOT EXISTS library ( library_name TEXT, function_name TEXT, function_bytes BLOB, includes TEXT)"""

    cursor.execute(library_table_string)

    # insert a dummy entry to test our database and table
    cursor.execute("INSERT INTO library VALUES('dummy_lib', 'dummy_func_1', '48 8d 3d d9 2f 00 00 48 8d 05 d2 2f 00 00 48 39 f8', 'stdlib.h pico_stdlib.h pico_hardware.h')")
    conn.commit()
    
    # verify we have a table added to the sqlite_master inbuilt table
    res = cursor.execute("SELECT name FROM sqlite_master")
    print(res.fetchall())

    res = cursor.execute("SELECT * FROM library")
    print(res.fetchall())

    #once this is done, we remove our dummy entry so we don't create accidentally a mismatch
    res = cursor.execute("""DELETE FROM library WHERE library_name="dummy_lib" """)
    conn.commit()

    res = cursor.execute("SELECT * FROM library").fetchall()
    print(res)

    conn.close()



def delete_table(table_name):
    """
        Helper function to delete table. To delete the entire db we should remove the file
    """

    conn = sqlite3.connect("libraries.db")
    cursor = conn.cursor()

    delete_table_string = "DROP TABLE {t_name}".format(t_name=table_name)
    cursor.execute(delete_table_string)
    conn.commit()
    conn.close()


def insert_libraries_entry(library_name, platform_architecture, compiler_type, compiler_flags, header_files):
    conn = sqlite3.connect("library_symbols.db")
    cursor = conn.cursor()

    insert_statement_string = "INSERT INTO libraries(libraryName, platformArch, compiler, compilerFlags, headerfiles) VALUES ('{libname}', '{platarch}', '{comp}', '{compflags}', '{headerf}')".format(libname=library_name, 
                                platarch=platform_architecture, comp=compiler_type, compflags=compiler_flags, headerf=header_files)
    res = cursor.execute(insert_statement_string)

    # we return the rowid of the last inserted entry
    get_lib_id_string = "SELECT libraryID FROM libraries WHERE rowid={r_id}".format(r_id=cursor.lastrowid)
    res = cursor.execute(get_lib_id_string).fetchone()[0]

    conn.commit()
    conn.close()

    return res

                   
def insert_libraries_multiple_entries(list_libraries_entries):
    """
        Function to insert multiple entries in the table
    """
    conn = sqlite3.connect("library_symbols.db")
    cursor = conn.cursor()

    for lib_elem in list_libraries_entries:
        # construct the string for inserting in the database
        insert_statement_string = "INSERT INTO libraries(libraryName, platformArch, compiler, compilerFlags, headerfiles) VALUES ('{libname}', '{platarch}', '{comp}', '{compflags}', '{headerf}')".format(libname=lib_elem[0],
                                    platarch=lib_elem[1], comp=lib_elem[2], compflags=lib_elem[3], headerf=lib_elem[4])

        res = cursor.execute(insert_statement_string)

    conn.commit()
    conn.close()    


def insert_symbols_entry(library_id, symbol_name, symbol_bytecode):
    conn = sqlite3.connect("library_symbols.db")    
    cursor = conn.cursor()

    insert_statement_string = "INSERT INTO symbols(libraryID, symbolName, symbolBytecode) VALUES ('{lib_id}', '{symbol_n}', '{symbol_byte}')".format(lib_id=library_id, symbol_n=symbol_name, symbol_byte=symbol_bytecode)
    res = cursor.execute(insert_statement_string)
    conn.commit()
    conn.close()


def insert_symbols_multiple_entries(list_symbols_entries):
    """
        Function to insert multiple entries in the table
    """
    conn = sqlite3.connect("library_symbols.db")
    cursor = conn.cursor()

    for sym_elem in list_symbols_entries:
        # construct the string for inserting in the database
        insert_statement_string = "INSERT INTO symbols(libraryID, symbolName, symbolBytecode) VALUES ('{lib_id}', '{symbol_n}', '{symbol_byte}')".format(lib_id=sym_elem[0], symbol_n=sym_elem[1], symbol_byte=sym_elem[2])

        res = cursor.execute(insert_statement_string)

    conn.commit()
    conn.close()  



def insert_library_in_table(library_mapping, library_name):
    """
        The cleaneast way would be to seperate the library analysis and adding to the table, but this would result in calling the insert_single_table_entry
        function 30 times in a row with opening and closing the connection. Not a great idea.
        Instead we have this helper function for populating many entries at once when we analyzed an entire library. 
    """
    conn = sqlite3.connect("libraries.db")
    cursor = conn.cursor()

    # the library mapping is a dict where the function name is the key and the function bytes the corresponding value. We will iterate through the dict
    # to make an insertion string to add it to the table
    for lib_section in library_mapping:
        insert_table_string = "INSERT INTO library VALUES ('{lib_name}', '{func_name}', '{func_bytes}', '{headers}')".format(lib_name=library_name, 
                                                                                                                         func_name=lib_section, 
                                                                                                                         func_bytes=library_mapping[lib_section], 
                                                                                                                         headers='')
        cursor.execute(insert_table_string)
    conn.commit()
    conn.close()


def insert_single_table_entry(library_name, function_name, function_bytes, include_headers):
    """
        function to insert a new single entry in the table. For now we assume it is always table library and some info will be pre-filled
    """
    
    conn = sqlite3.connect("libraries.db")
    cursor = conn.cursor()

    insert_entry_string = "INSERT INTO library VALUES ('{lib_name}', '{func_name}', '{func_bytes}', '{headers}')".format(lib_name=library_name, 
                                                                                                                         func_name=function_name, 
                                                                                                                         func_bytes=function_bytes, 
                                                                                                                         headers=include_headers)
    cursor.execute(insert_entry_string)
    conn.commit()

    # verify our entry is in the table
    print("Current entries in the table:")
    res = cursor.execute("SELECT * FROM library")
    print(res.fetchall())

    conn.close()


def load_bytecode_in_struct():
    conn = sqlite3.connect("library_symbols.db")
    cursor = conn.cursor()

    res = cursor.execute("SELECT * FROM symbols").fetchall()
    conn.close()

    return res


def get_libraries_based_on_id(library_id):
    conn = sqlite3.connect("library_symbols.db")
    cursor = conn.cursor()
    select_statement_string = "SELECT * FROM libraries WHERE libraryID='{lib_id}'".format(lib_id=library_id)
    res = cursor.execute(select_statement_string).fetchall()
    conn.close()
    
    return res


def get_linked_libraryID_from_symbolID(symbol_id):
    conn = sqlite3.connect("library_symbols.db")
    cursor = conn.cursor()

    select_statement_string = "SELECT libraryID FROM symbols WHERE symbolID='{sym_id}'".format(sym_id=symbol_id)
    res = cursor.execute(select_statement_string).fetchone()[0]
    conn.close()

    return res


def get_library_based_on_all_but_id(lib_name, comp_type, comp_flags, plat_type, headers):
    """
    Helper function to determine whether a library entry already exists, but we do not know the id
    Returns a list of id's if found matches or empty list if not
    """
    conn = sqlite3.connect("library_symbols.db")
    cursor = conn.cursor()

    select_statement_str = "SELECT libraryID FROM libraries WHERE libraryName='{libname}' AND platformArch='{platarch}' AND compiler='{comp}' AND compilerFlags='{comp_f}' AND headerfiles='{head}'".format(libname=lib_name, 
                                                                                                                                                                                                  platarch=plat_type, 
                                                                                                                                                                                                  comp=comp_type, 
                                                                                                                                                                                                  comp_f=comp_flags, 
                                                                                                                                                                                                  head=headers)
    res = cursor.execute(select_statement_str).fetchall()
    conn.close()
    
    return res


def load_function_bytes_in_struct():
    """
    This function loads from the current library table all function names and the function bytes in a struct. We use this struct to iterate and compare with the binary
    instead of everytime querying the db for the function bytes. The idea is that this is faster although this is an unknown yet.
    We use the rowid (a unique identifier for each table entry that sqlite generates under the hood) to ensure we have a unique id per function.
    We can then later if we have matched one of the function bytes use the rowid to quickly retrieve the table entry from the database and then get the headers info (or anything else)
    Furthermore, we might extend this functionality later to filter first for certain libraries or platform or compiler options.
    """
    conn = sqlite3.connect("libraries.db")
    cursor = conn.cursor()

    # The result will be a list made of zero or more tuples
    # in principle we can work with it as is, but we could optimize this into a dict using only the rowid and the function bytes
    # the rowid can then be used as an identifier to find back the other information
    # TODO: convert the tuple into a dict with rowid: function_bytes, but first check if a dict will be faster than a tuple
    res = cursor.execute("SELECT rowid, library_name, function_bytes FROM library").fetchall()

    conn.close()
    return res


def retrieve_table_entry(row_id):
    """
    Retrieve an entry from the table based on the rowid
    """
    conn = sqlite3.connect("libraries.db")
    cursor = conn.cursor()

    select_st_str = "SELECT * FROM library WHERE rowid={row_id_nr}".format(row_id_nr=row_id)
    res = cursor.execute(select_st_str).fetchall()

    #print(res)

    conn.close()

    return res