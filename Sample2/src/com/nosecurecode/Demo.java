/*
  PROGRAM : Coding Ghidra - Sample 1
  AUTHOR  : NADER SHALLABI <nader@nosecurecode.com>

  This sample code is free for use, redistribution and/or
  modification without any explicit permission from the author.

  This sample code is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY, implied or explicit.
*/

package com.nosecurecode;

import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import com.nosecurecode.libghidra.*;
import ghidra.program.model.symbol.ExternalReference;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

import javafx.util.Pair;
import java.util.*;

/**
 * Dump program external functions
 */
public class Demo implements LibProgramHandler {
    public static void main(String args[]) throws Exception {

        // Option 1 to call headless analyzer using a full command
        String headlessCmd = "/Users/nadershallabi/Desktop/OutputPad Sample2 -import /Users/nadershallabi/Desktop/BinaryCollection -overwrite";

        // We need an instance of this class to pass the analyzed program handler
        Demo ghidraLibraryDemo = new Demo();

        // This will kickoff the analysis
        LibGhidra.runHeadlessCmd(headlessCmd, ghidraLibraryDemo);
    }

    /**
     * Sample based on https://www.somersetrecon.com/blog/2019/ghidra-plugin-development-for-vulnerability-research-part-1
     * @param program
     */
    @Override
    public void PostProcessHandler(Program program) {

        System.out.println("================================");
        System.out.println("PROCESSING PROGRAM : " + program.getName());
        System.out.println("================================");

        String [] sinks_array = new String[] {
                "strcpy",
                "memcpy",
                "gets",
                "memmove",
                "scanf",
                "strcpyA",
                "strcpyW",
                "wcscpy",
                "_tcscpy",
                "_mbscpy",
                "StrCpy",
                "StrCpyA",
                "StrCpyW",
                "lstrcpy",
                "lstrcpyA",
                "lstrcpyW",
                "lstrcpynA"
        };

        List<String> sinks = Arrays.asList(sinks_array);

        Hashtable<String, Vector<Pair<String, String>>> sink_dic = new Hashtable<String, Vector<Pair<String, String>>>();
        ArrayList<String> duplicate = new ArrayList<String>();

        Listing listing = program.getListing();
        InstructionIterator ins_list = listing.getInstructions(true);

        // iterate over each instruction
        while (ins_list.hasNext()) {
            Instruction ins = ins_list.next();
            String mnemonic = ins.getMnemonicString();
            Object[] ops = ins.getOpObjects(0);
            if (mnemonic.equals("CALL")) {
                Object target_addr = ops[0];
                String func_name = null;

                ExternalReference ref = null;
                if (target_addr instanceof Address) {
                    CodeUnit code_unit = listing.getCodeUnitAt((Address) target_addr);
                    if (code_unit != null)
                        ref = code_unit.getExternalReference(0);
                    if (ref != null)
                        func_name = ref.getLabel();
                    else {
                        Function func = listing.getFunctionAt((Address) target_addr);
                        func_name = func.getName();
                    }
                }

                // check if function name is in our sinks list
                if (sinks.contains(func_name) && !duplicate.contains(func_name)) {
                    duplicate.add(func_name);
                    ReferenceIterator references = program.getReferenceManager().getReferencesTo((Address) target_addr);

                    for (Reference ref_var : references) {
                        Address call_addr = ref_var.getFromAddress();
                        Object sink_addr = ops[0];
                        String parent_func_name = new FlatProgramAPI(program).getFunctionBefore(call_addr).getName();

                        // check sink dictionary for parent function name
                        if (!sink_dic.containsKey(parent_func_name)) {
                            Vector<Pair<String, String>> function_address_pair = new Vector<Pair<String, String>>();
                            function_address_pair.add(new Pair<String, String>(func_name, call_addr.toString()));
                            sink_dic.put(parent_func_name, function_address_pair);
                        }
                        else {
                            sink_dic.get(parent_func_name).add(new Pair<String, String>(func_name, call_addr.toString()));
                        }
                    }
                }
            }
        }

        printDiscoveredFunctions(sink_dic);

        System.out.println("~===============================");
        System.out.println("~ END OF PROCESSING PROGRAM : " + program.getName());
        System.out.println("~===============================");
    }

    /**
     * Prints functions list (findings)
     * @param sink_dic
     */
    private void printDiscoveredFunctions(Hashtable<String, Vector<Pair<String, String>>> sink_dic) {
        for (String parent_func_name : sink_dic.keySet()) {
            Vector<Pair<String, String>> item = sink_dic.get(parent_func_name);
            for (int i = 0; i < item.size(); i++) {
                Pair<String, String> item2 = item.get(i);
                String func_name = item2.getKey();
                String call_addr = item2.getValue();
                System.out.println("[" + parent_func_name + "]>-----" + call_addr + "----->[" + func_name + "]");
            }
        }
    }
}
