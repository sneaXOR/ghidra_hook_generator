# FunctionSignatureExtractor.py
# -*- coding: utf-8 -*-

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

class FunctionSignatureExtractor:
    """
    Retrieves function signature (name, address, return type, parameters,
    calling convention) via Ghidra analysis and the decompiler.
    """

    def __init__(self, script):
        self.script = script
        self.decomp_iface = None
        self._init_decompiler()

    def _init_decompiler(self):
        self.decomp_iface = DecompInterface()
        self.decomp_iface.openProgram(self.script.getCurrentProgram())

    def extract_signature(self, func):
        """
        :param func: ghidra.program.model.listing.Function
        :return: dict with signature info
        """
        sig_data = {
            "name": func.getName(),
            "entry_point": func.getEntryPoint().getOffset(),  # Long offset
            "calling_convention": func.getCallingConvention(),
            "return_type": str(func.getReturnType().getDisplayName()),
            "params": [],
            "is_64bit": (
                self.script.getCurrentProgram()
                           .getLanguage()
                           .getAddressFactory()
                           .getDefaultAddressSpace()
                           .getSize() == 64
            )
        }

        # Collect parameters
        for p in func.getParameters():
            param_info = {
                "name": p.getName(),
                "type": p.getDataType().getDisplayName()
            }
            sig_data["params"].append(param_info)

        # Attempt decompilation to get more details
        try:
            results = self.decomp_iface.decompileFunction(func, 30, ConsoleTaskMonitor())
            if results and results.getDecompiledFunction():
                dec_func = results.getDecompiledFunction()
                sig_data["decompiled_signature"] = dec_func.getSignature()
            else:
                sig_data["decompiled_signature"] = None
        except:
            sig_data["decompiled_signature"] = None

        return sig_data
