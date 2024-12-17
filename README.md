# library-finder


## Requirements
- Ghidra, https://github.com/NationalSecurityAgency/ghidra
  - Ghidra version 10.3 was used to develop this script
- Python 3
  - Python 3.11 was used to develop and run this script
- Ghidrathon, https://github.com/mandiant/Ghidrathon
  - Ghidra by default supports only Python 2, this extension allows scripting capabilities in Python 3
 
## How to run
Make sure that the python files are in a directory that is added to Ghidra's script manager. To do this, open Ghidra and open the CodeBrowser.
Then select Window --> Script Manager --> Manage Script Directories (the icon of a bullet list). This will open the Bundle Manager and here you can add the location of the 
python files by selecting the green '+' icon on the top right. Make sure you add the directory locations where the python files are placed and not a directory above, or Ghidra will be unable to find the script files!

The script can be found in the Script Manager under category 'Python' under the name 'ghidra_library_finder.py'. Double click to execute the script

## Usage
When running the script, you will be ask to choose between several options:
1. Add library to db - This will add all the functions in the program that is currently opened in the CodeBrowser to the database.
2. Find match in db - This will search all the functions in the program that is currently opened in the CodeBroswer for matches with the database.
3. Create db - This will create the database tables.
4. Delete table - This will empty the specified table.

### Adding libraries to the db
Libraries first need to be added to the database before matches can be found. Choosing this function will prompt all functions in the currently opened program in the CodeBrowser to be added to the database. When choosing this function, several prompts will pop up asking to provide the database name, the library name, the architecture type, the compiler used, optional compiler flags and the headerfiles. Please make sure to perform all required analysis first because Library-Finder will take the current state of the program, even if has not executed any analysis prior.

### Find match in db
When choosing this option, Library-Finder will start comparing the bytecode of each function in the program currently opened in the CodeBroswer with the bytecode of all functions present in the database. First it will prompt to fill in the name of the database to use and whether to perform a full search or a smart search. Note that the selection between full search and smart search is not implemented yet and therefore will not make a difference. Library-Finder will report the found matches in a text file once it has finished. Note that the implementation currently does not support selecting a location for the output file so it will place the file in 'Projects\RE-embedded\ghidra-library-finder'. Due to limitations no headerfiles are inserted in the program in Ghidra if matches are found. Instead these are reported in the output file.
