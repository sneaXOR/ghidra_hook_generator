# HookPluginUI.py
# -*- coding: utf-8 -*-

from ghidra.app.script import GhidraScript
from ghidra_hook_generator.core.FunctionSignatureExtractor import FunctionSignatureExtractor
from ghidra_hook_generator.core.HookCodeGenerator import HookCodeGenerator

class HookPluginUI:
    """
    Handles user interaction for selecting the target function,
    choosing the hooking method, and specifying the output folder.
    """

    def __init__(self, script):
        """
        :param script: GhidraScript instance
        """
        self.script = script

    def show_dialog(self):
        """
        1. Prompt user for function selection (current or by address).
        2. Ask hooking method.
        3. Ask output folder.
        4. Extract signature.
        5. Generate hooking project.
        """
        # 1) Choose how to select the function
        choice = self.script.askChoice(
            "Function Selection",
            "How do you want to pick the function?",
            ["Use the current function (currentFunction)", "Specify an address manually"]
        )

        if choice == "Use the current function (currentFunction)":
            target_function = self.script.getCurrentFunction()
            if target_function is None:
                self.script.popup("No current function selected!", "Error")
                return
        else:
            addr_input = self.script.askString("Function Address", "Enter the address (e.g. 0x00401000):")
            if not addr_input:
                self.script.popup("Invalid address input.", "Error")
                return

            try:
                addr = self.script.toAddr(addr_input)
                target_function = self.script.getFunctionAt(addr)
                if target_function is None:
                    self.script.popup("No function found at that address.", "Error")
                    return
            except Exception as ex:
                self.script.popup("Invalid address: {}".format(str(ex)), "Error")
                return

        # 2) Ask hooking method
        hooking_choice = self.script.askChoice(
            "Hooking Method",
            "Select a hooking method:",
            ["MinHook (Windows)", "Inline Patch (Linux)"]
        )

        # 3) Ask output directory
        output_dir = self.script.askDirectory("Output Directory", "Select folder for generated hooking code")
        if not output_dir:
            self.script.popup("No directory selected. Aborting.", "Error")
            return

        # 4) Extract the function signature
        extractor = FunctionSignatureExtractor(self.script)
        func_sig_data = extractor.extract_signature(target_function)

        # 5) Generate the hooking project
        generator = HookCodeGenerator()
        generator.generate_hook_project(
            output_path=str(output_dir.absolutePath),
            func_sig_data=func_sig_data,
            hooking_method=hooking_choice
        )

        # 6) Confirmation
        self.script.popup("Hook project generation completed!\nCheck folder:\n{}".format(output_dir), "Success")
