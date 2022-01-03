/*
  PROGRAM : Coding Ghidra - Sample 1
  AUTHOR  : NADER SHALLABI <nader@nosecurecode.com>

  This sample code is free for use, redistribution and/or
  modification without any explicit permission from the author.

  This sample code is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY, implied or explicit.
*/

package com.nosecurecode;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import com.nosecurecode.libghidra.*;

/**
 * Demo: Dump program external functions, this program demonstrates basic usage of the Coding-Ghidra library
 *       The sample demonstrates looking for commonly used anti-debugging APIs, such as "IsDebuggerPresent" API function
 */
public class Demo implements LibProgramHandler {
    public static void main(String args[]) throws Exception {

        // Option 1 to call headless analyzer using a full command
        String headlessCmd = "/Users/nadershallabi/ghidra/projects Project1 -import /Users/nadershallabi/Downloads/1.exe -overwrite";

        // We need an instance of this class to pass the analyzed program handler
        Demo ghidraLibraryDemo = new Demo();

        // This will kickoff the analysis
        LibGhidra.runHeadlessCmd(headlessCmd, ghidraLibraryDemo);

        // Option 2 would be to call the analyzer passing command arguments:
        // LibGhidra.runHeadlessCmd(args, ghidraLibraryDemo);
    }

    /**
     * Use the passed Program instance to dump program imports
     * The code highlights the IsDebuggerPresent function
     * @param program
     */
    @Override
    public void PostProcessHandler(Program program) {

        // Get a list of external functions used
        FunctionIterator externalFunctions = program.getListing().getExternalFunctions();

        System.out.println("\033[1;33m");
        System.out.println("================");
        System.out.println("PROGRAM IMPORTS:");
        System.out.println("================");

        // Print all functions in the program: [return type] [calling convention] [function name]
        // Highlight the IsDebuggerPresent() API function

        System.out.println("\033[0;33m");

        while (externalFunctions.hasNext()) {
            Function function = externalFunctions.next();
            if (function.getName().equals("IsDebuggerPresent")) {
                System.out.print("\033[1;31m");
            } else {
                System.out.print("\033[0;33m");
            }
            System.out.println(
                    function.getReturnType() + " " + function.getCallingConvention() + " " + function.getName()
            );
        }
    }
}
