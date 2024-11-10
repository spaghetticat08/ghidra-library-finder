import re

import db_utils
import elf_utils

def matchByteSequencesFromInputs(file_handle, reference_fb_mapping, input_fb_mapping):
    #print("I should be here")
    file_handle.write("\nIn function matchByteSequencesFromInputs()")
    matchedFunctionsId = set()

    # then take the mapping from the database (reference_mapping) and the mapping from current program (input mapping)
    # we iterate through the input_mapping and per element we compar the bytecode with the bytecode per element from the
    # reference mapping 
    for input_elem in input_fb_mapping:
        # let's use a variable so we don't have to access data structures in nested loops for performance
        input_bytecode = input_fb_mapping[input_elem]
        for reference_elem in reference_fb_mapping:
            reference_bytecode = reference_fb_mapping[reference_elem]
            # The library functions bytecode is slightly different if relocation has not happened yet (or sometimes differently relocated)
            # this could miss a match even though its functionally the same, so as a solution we neutralize all
            # instructions that do some branching. Now we only support bl, later also other ones
            # check for bl instruction in both reference and input bytecode
            if ((len(re.findall(r"\s[\da-f]{2}\sf[0-7]\s[\da-f]{2}\s[f|d][\da-f]", reference_bytecode)) > 0) and (len(re.findall(r"\s[\da-f]{2}\sf[0-7]\s[\da-f]{2}\s[f|d][\da-f]", input_bytecode)) > 0)):
                # by assigning the neutralized instruction we don't change the original bytecode 
                input_bytecode = elf_utils.neutralizeBlInstruction(file_handle, input_bytecode)
                reference_bytecode = elf_utils.neutralizeBlInstruction(file_handle, reference_bytecode)

            if (input_bytecode == reference_bytecode):
                # we found a match, so we add the id from reference mapping in ou matchedFunctionsIdSet and 
                # go to the next element. We could also stop searching here since it doesn't matter how many
                # functions from the same library are found if we only include the header.
                # however, for later reporting purposes (or maybe even source code matching) it is interesting
                # to record multiple matches and we continue the search. 
                # We can later add an optimized quick search that will skip this
                matchedFunctionsId.add(reference_elem)
                file_handle.write("\n In matchByteSequencesFromInputs(): Found a match in the bytecode!")

    # set of the symbolIds that were matched
    return matchedFunctionsId