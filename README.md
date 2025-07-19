# dump-iat

**dump-iat** is a lightweight command-line tool for inspecting and dumping the Import Address Table (IAT) of Windows processes and modules. It allows you to analyze which external functions a process or module imports and show the addresses at runtime.

---

## Features

- List imported functions of a target process or module
- Specify target by process name or process ID
- Dump IAT of a specific module inside a process
- Filter imports from a particular module within the target process
- Simple command-line interface with helpful usage information
- ~~Check if the IAT got hooked.~~

---

## Usage

```bash
dump-iat [options]

Options

Flag                            Description
-p <process>                    Specify target process by name
-pid <pid>                      Specify target process by process ID
-m <module>                     Dump IAT of a specific module inside the process (default: executable)
-M <module>                     Show imports only from this specific module loaded in the process
-h, --help                      Show this help message
-b                              Show the module load base alongside it's name when showing imports from it
 --check-iat-integrity          Attempts to check if the IAT entries were hooked. - Not implemented yet.
```

---

## Example

Dump the IAT of the notepad.exe process:

`dump-iat -p notepad.exe`

Dump the IAT of the module kernel32.dll loaded in the process with PID 1234:

`dump-iat -pid 1234 -m kernel32.dll`

---

## Building

Compile with your preferred C/C++ compiler on Windows. Requires linking against Kernel32.lib and your default CRT for Windows API calls and CRT functions.

---

## License

This project is licensed under the MIT License. See the LICENSE file for details.

---

## Contributing

Feel free to open issues or submit pull requests to improve functionality, fix bugs, or add features.
