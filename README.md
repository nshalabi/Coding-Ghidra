# Coding Ghidra

Ghidra Java code can be bundled in a **Java Archive** file (**JAR**), this makes it easy to use Ghidra as a library for more advanced reverse engineering tasks, in this repository you will find samples to demonstrate how to use Ghidra as a RE library.

The projects in this repository were created using IntelliJ IDEA, a Community Edition is available for free at [www.jetbrains.com](www.jetbrains.com), additionally, the projects need to be bundled with Ghidra JAR file, you will need to build this file yourself, run `buildGhidraJar.bat` batch file located in Ghidera archive under the `support` folder, then copy the generated ghidra.jar to projects lib file, for example, Sample1\src\lib.

The code has comments to explain what it does. Additionally, the Ghidra code itself is well documented and can be referenced directly from code or documentation.
 
More samples will be added in the future, and all are welcome to contribute.

## Sample 1

Demonstrates basic usage of library initialization, loading a binary file for analysis (Notepad) and listing all external functions
