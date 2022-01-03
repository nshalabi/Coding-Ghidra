/*
  This interface implements the callback functionality, for any feedback, contact NADER SHALLABI at nader@nosecurecode.com
*/


package com.nosecurecode.libghidra;

import ghidra.program.model.listing.Program;

/**
 * Implement this interface in the class that need to have a callback after Ghidra processing
 */
public interface LibProgramHandler {
    public void PostProcessHandler(Program program);
}
