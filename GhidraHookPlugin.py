# GhidraHookPlugin.py
# -*- coding: utf-8 -*-

import sys
from ghidra.app.script import GhidraScript

# Import custom UI
from ghidra_hook_generator.plugin.HookPluginUI import HookPluginUI

class GhidraHookPlugin(GhidraScript):
    """
    Main Ghidra plugin script to initialize the hooking UI.
    Inherits GhidraScript to get access to currentProgram, currentSelection, etc.
    """

    def run(self):
        """
        This method is invoked when running this script in Ghidra.
        """
        try:
            ui = HookPluginUI(script=self)
            ui.show_dialog()
        except Exception as e:
            print("[Error] GhidraHookPlugin execution failed:", str(e))
            sys.print_exc()
