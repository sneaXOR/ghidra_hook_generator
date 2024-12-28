# HookCodeGenerator.py
# -*- coding: utf-8 -*-

import os
from ghidra_hook_generator.core.HookingUtils import (
    generate_minhook_code,
    generate_inline_patch_code
)

class HookCodeGenerator:
    """
    Generates the hooking project (CPP code, headers, CMake).
    """

    def generate_hook_project(self, output_path, func_sig_data, hooking_method):
        """
        Creates all necessary files in 'output_path' to hook the specified function.
        :param output_path: target directory
        :param func_sig_data: dict (from FunctionSignatureExtractor)
        :param hooking_method: "MinHook (Windows)" or "Inline Patch (Linux)"
        """
        if not os.path.exists(output_path):
            os.makedirs(output_path)

        # Generate hooking code
        if hooking_method == "MinHook (Windows)":
            code_cpp, header_cpp = generate_minhook_code(func_sig_data)
        else:
            code_cpp, header_cpp = generate_inline_patch_code(func_sig_data)

        # Write main CPP
        main_cpp_path = os.path.join(output_path, "hook_main.cpp")
        with open(main_cpp_path, "w", encoding="utf-8") as f:
            f.write(code_cpp)

        # Write header
        header_path = os.path.join(output_path, "hook_main.h")
        with open(header_path, "w", encoding="utf-8") as f:
            f.write(header_cpp)

        # Write minimal CMakeLists
        cmake_path = os.path.join(output_path, "CMakeLists.txt")
        with open(cmake_path, "w", encoding="utf-8") as f:
            f.write(self._generate_cmake_lists(func_sig_data, hooking_method))

    def _generate_cmake_lists(self, func_sig_data, hooking_method):
        project_name = "HookProject_" + func_sig_data["name"]
        is_windows = (hooking_method == "MinHook (Windows)")

        lines = []
        lines.append("cmake_minimum_required(VERSION 3.0)")
        lines.append("project({})".format(project_name))

        if is_windows:
            lines.append("add_definitions(-D_WIN32_WINNT=0x0601)")
            lines.append("set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)")
            lines.append("add_library({} SHARED hook_main.cpp)".format(project_name))
            lines.append("# For MinHook, include or link the library here.")
        else:
            lines.append("set(CMAKE_CXX_STANDARD 11)")
            lines.append("add_executable({} hook_main.cpp)".format(project_name))
            lines.append("# For inline patch, you'll get a normal executable.")

        return "\n".join(lines) + "\n"
