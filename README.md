# Ghidra Hook Generator

Ghidra plugin (in Python/Jython) that automates creating C/C++ hooking code for a selected function:
- Extracts function details (name, address, return type, parameters, calling convention, etc.) from Ghidra,
- Generates ready-to-compile hooking projects for:
  - **Windows** (using [MinHook](https://github.com/TsudaKageyu/minhook)),
  - **Linux** (inline patch with a trampoline).

## Features
- Automatic function signature extraction (using Ghidra API + decompiler).
- Choice between MinHook or inline patch hooking.
- Generates minimal C/C++ code and a CMakeLists.txt.

## Installation
1. Copy `ghidra_hook_generator/` into your Ghidra scripts directory (e.g., `~/ghidra_scripts/`).
2. In Ghidra, open **Script Manager** and run `GhidraHookPlugin.py`.

## Usage
1. Open a binary in Ghidra and let it analyze.
2. Select (or specify) the function to hook.
3. Run `GhidraHookPlugin.py` from the Script Manager.
4. Pick the hooking method and choose an output directory.
5. Build the generated project with CMake.

Use responsibly—happy reverse engineering!