# Coding Ghidra - Library and Samples

Ghidra Java code can be bundled in a **Java Archive** file (**JAR**), this makes it easy to use Ghidra as a library for more advanced reverse engineering tasks, in this repository you will find samples to demonstrate how to use Ghidra as a disassembler library.

## Prerequisites

The projects in this repository were created using IntelliJ IDEA, a Community Edition is available for free at [www.jetbrains.com](www.jetbrains.com), additionally, the samples need to be bundled with Ghidra JAR file, you will need to build this file yourself, run `buildGhidraJar.bat` batch file located in Ghidera archive under the `support` folder, then copy the generated ghidra.jar to projects lib file, for example, Sample1\src\lib.

**UPDATE**: With Ghidra 10.1.1 there were many breaking changes in code tha was fixed, however, for building the JAR file, an additional step is needed: 

Before building the JAR file, edit the file `{GHIDRA_FOLDER}/Ghidra/Features/ByteViewer/Module.manifest` and **delete** the line (the only line) in the file **"EXCLUDE FROM GHIDRA JAR: true"**, then run the JAR build sxcript, if this step is missing, the headless analzer will fail to load due to a class loading error (since the mentioned library is missing from the JAR archive).

Please note that the JAR file does not include all of Ghidra modules, if you want to include all modules, then adjust the manifest of each library as previously suggested and customize the `{GHIDRA_FOLDER}/Ghidra/Features/Base/ghidra_scripts/BuildGhidraJarScript.java` by removing the comment next to the **"addAllModules()"** call and then run the JAR build script.

## Library Design

Ghidra supports a headless analysis mode that can be used to automate many of Ghidra's functionality, this mode can also be used with Ghidra plugins. The **GhidraLib** is a Java wrapper to Ghidra headless mode, most of the code is a copy from the existing Ghidra headless code branch with modifications to help hook the analysis process using a callback interface to enable access to analysis data, the headless analysis process can be started with two methods:

```
public static void runHeadlessCmd(String headlessCmd, LibProgramHandler handler)

public static void runHeadlessCmd(String [] headlessCmdArgs, LibProgramHandler handler
```

Both methods are identical, the only difference is in the way the headless command is passed. The first method uses a command line in precisely the same format of the headless analyzer, for example, the following command string imports a binary /binaries/binary1.exe to a local Ghidra Project named Project1. Analysis is on by default.

`/Users/user/ghidra/projects Project1 -import /binaries/binary1.exe`

The second format uses string tokens instead, for example:

`{"/Users/user/ghidra/projects", "-import", "/binaries/binary1.exe"}`

The second argument is the callback (handler), this handler is an instance of an object that implements the **LibProgramHandler** interface and it's only method:

```
public interface LibProgramHandler {
    public void PostProcessHandler(Program program);
}
```

When invoking headless analysis using any of the previous methods, the analysis code will pass an instance of **ghidra.program.model.listing.Program** object immediately after the binary analysis is done, but before it fully returns to invoking code (if handler parameter is not null), this object is the outcome of the headless analysis. As an example, the following code uses this object to dump all program imports:

```
// Get a list of external functions used
FunctionIterator externalFunctions = program.getListing().getExternalFunctions();

// Print all functions in the program: [return type] [calling convention] [function name]
while (externalFunctions.hasNext()) {

    Function function = externalFunctions.next();

    System.out.println( function.getReturnType() + " " + function.getCallingConvention() + " " + function.getName() );
}
```

## Objective

The headless mode combined with Ghidra plugins, are powerful automation tools, the GhidraLibrary inherits all those features and allows for it to be easily embedded in your own, standalone applications or integration layer with other applications/solutions.

## Roadmap

1. Add more samples and use cases.
2. Add more event handlers (for example, PreProcessHandler, Pre/PostScriptRunHandler).
 
More samples will be added in the future, and all are welcome to contribute.

---

## Sample 1

Demonstrates basic usage of library initialization, loading a binary file for analysis and listing all external functions

![Sample1](https://github.com/nshalabi/Coding-Ghidra/blob/master/Media/Sample1.PNG "Sample1")

## Sample 2

Using Ghidra in Vulnerability Research, based on the [Ghidra Plugin Development for Vulnerability Research - Part-1](https://www.somersetrecon.com/blog/2019/ghidra-plugin-development-for-vulnerability-research-part-1) article. The code demonstrates using cross references to identify code units calling external functions.

**Sample output**

[Function]>-----Address of calling function----->[External Function]

`[FUN_00403ed2]>-----00403ee7----->[lstrcpynA]`

`[FUN_00405a0c]>-----00405a19----->[lstrcpynA]`
