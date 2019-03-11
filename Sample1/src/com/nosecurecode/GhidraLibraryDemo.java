package com.nosecurecode;

import java.io.*;

import ghidra.GhidraJarApplicationLayout;
import ghidra.framework.ApplicationConfiguration;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.test.TestProgramManager;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.base.project.GhidraProject;
import ghidra.framework.Application;
import ghidra.program.model.listing.Program;
import ghidra.util.*;
import ghidra.util.exception.*;
import ghidra.util.task.*;

public class GhidraLibraryDemo {

    public static void main(String args[]) throws
            IOException, VersionException, CancelledException, DuplicateNameException, InvalidNameException {

        // Adjust the following
        String projectDirectoryName = "C:\\Demo";
        String projectName = "Demo1";
        String programName = "C:\\Windows\\Notepad.exe";

        // Define Ghidra components
        GhidraProject ghidraProject;
        Program program;
        TestProgramManager programManager = new TestProgramManager();

        // Initialize application
        if (!Application.isInitialized()) {
            ApplicationConfiguration configuration = new HeadlessGhidraApplicationConfiguration();
            configuration.setInitializeLogging(false);
            Application.initializeApplication(new GhidraJarApplicationLayout(), configuration);
        }

        // Create a Ghidra project
        ghidraProject = GhidraProject.createProject(projectDirectoryName, projectName, true);

        // Load binary file
        File file = new File(programName);
        if (file == null || !file.exists()) {
            throw new FileNotFoundException("Can not find program: " + programName);
        }

        program = ghidraProject.importProgram(file);

        // Display the Processor used by Ghidra
        System.out.println("Processor used : " + program.getLanguage().getProcessor().toString());

        // Analyze the loaded binary file
        int txId = program.startTransaction("Analysis");
        AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
        mgr.initializeOptions();
        mgr.reAnalyzeAll(null);

        // The analysis will take sometime.
        System.out.println("Analyzing...");
        mgr.startAnalysis(TaskMonitor.DUMMY);

        // Marked as analyzed
        GhidraProgramUtilities.setAnalyzedFlag(program, true);

        // Now to do something useful
        // Get a list of external functions used
        FunctionIterator externalFunctions = program.getListing().getExternalFunctions();

        // Print all functions
        while (externalFunctions.hasNext()) {
            Function function = externalFunctions.next();
            System.out.println(function.getName());
        }

        // Release Program
        programManager.release(program);

        // Close project without saving
        ghidraProject.setDeleteOnClose(true);
        ghidraProject.close();
    }
}
