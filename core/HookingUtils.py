# HookingUtils.py
# -*- coding: utf-8 -*-

def generate_minhook_code(func_sig_data):
    """
    Generates real hooking code using MinHook on Windows:
    - A DLL with DllMain, hooking initialization, and the hooked function.
    """
    func_name = func_sig_data["name"]
    calling_convention = func_sig_data["calling_convention"] or "__cdecl"
    return_type = func_sig_data["return_type"]
    params = func_sig_data["params"]
    address = func_sig_data["entry_point"]  # numeric offset

    # Build parameter list
    cpp_params_decl = []
    for p in params:
        cpp_params_decl.append("{} {}".format(p["type"], p["name"]))
    cpp_params_decl_str = ", ".join(cpp_params_decl)

    # Typedef
    typedef_line = "typedef {rt} ({cc} *{name}_t)({params});".format(
        rt=return_type,
        cc=calling_convention,
        name=func_name,
        params=cpp_params_decl_str
    )

    # .cpp content
    main_cpp = r'''#include <Windows.h>
#include <cstdio>
#include "hook_main.h"
#include "MinHook.h"

{typedef_line}
static {func_name}_t original_{func_name} = nullptr;

{return_type} {calling_convention} Hook_{func_name}({cpp_params_decl})
{{
    printf("[Hooked] {func_name} called!\n");
'''.format(
        typedef_line=typedef_line,
        func_name=func_name,
        return_type=return_type,
        calling_convention=calling_convention,
        cpp_params_decl=cpp_params_decl_str
    )

    # Original call
    call_params_str = ", ".join([p["name"] for p in params])
    if return_type.lower() != "void":
        main_cpp += "    {0} ret = original_{1}({2});\n".format(return_type, func_name, call_params_str)
        if return_type.lower() == "int":
            main_cpp += "    printf(\"[Hooked] Return = %d\\n\", ret);\n"
        main_cpp += "    return ret;\n"
    else:
        main_cpp += "    original_{0}({1});\n".format(func_name, call_params_str)
        main_cpp += "    return;\n"
    main_cpp += "}\n\n"

    # DllMain
    main_cpp += r'''
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        MH_Initialize();
        MH_CreateHook(
            (LPVOID)0x{address:X},
            &Hook_{func_name},
            reinterpret_cast<LPVOID*>(&original_{func_name})
        );
        MH_EnableHook((LPVOID)0x{address:X});
        break;

    case DLL_PROCESS_DETACH:
        MH_DisableHook((LPVOID)0x{address:X});
        MH_Uninitialize();
        break;
    }
    return TRUE;
}
'''.format(address=address, func_name=func_name)

    # Header
    header_cpp = '''#pragma once

{typedef_line}
{return_type} {calling_convention} Hook_{func_name}({cpp_params_decl});
'''.format(
        typedef_line=typedef_line,
        return_type=return_type,
        calling_convention=calling_convention,
        func_name=func_name,
        cpp_params_decl=cpp_params_decl_str
    )

    return main_cpp, header_cpp


def generate_inline_patch_code(func_sig_data):
    """
    Generates an inline patch hooking approach for Linux:
    - Patches the target function's bytes,
    - Sets up a trampoline to call the original code.
    """
    func_name = func_sig_data["name"]
    calling_convention = func_sig_data["calling_convention"] or "__attribute__((cdecl))"
    return_type = func_sig_data["return_type"]
    params = func_sig_data["params"]
    address = func_sig_data["entry_point"]

    cpp_params_decl = []
    for p in params:
        cpp_params_decl.append("{} {}".format(p["type"], p["name"]))
    cpp_params_decl_str = ", ".join(cpp_params_decl)

    typedef_line = "typedef {rt} (*{name}_t)({params});".format(
        rt=return_type,
        name=func_name,
        params=cpp_params_decl_str
    )

    main_cpp = r'''#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <dlfcn.h>
#include "hook_main.h"

static void* g_original_bytes = NULL;
static const size_t g_patch_size = 12; 
static void* g_target_addr = (void*)0x{address:X};
static {func_name}_t original_{func_name} = NULL;

{typedef_line}

{return_type} Hook_{func_name}({cpp_params_decl})
{{
    printf("[InlinePatch] {func_name} called!\n");
'''.format(
        func_name=func_name,
        address=address,
        return_type=return_type,
        cpp_params_decl=cpp_params_decl_str,
        typedef_line=typedef_line
    )

    call_params_str = ", ".join([p["name"] for p in params])
    if return_type.lower() != "void":
        main_cpp += "    {} ret = original_{}({});\n".format(return_type, func_name, call_params_str)
        if return_type.lower() == "int":
            main_cpp += '    printf("[InlinePatch] {0} returns %d\\n", ret);\n'.format(func_name)
        main_cpp += "    return ret;\n"
    else:
        main_cpp += "    original_{}({});\n".format(func_name, call_params_str)
        main_cpp += "    return;\n"

    main_cpp += r'''
}

void patch_inline()
{
    uintptr_t page_size = sysconf(_SC_PAGE_SIZE);
    uintptr_t addr_page = (uintptr_t)g_target_addr & ~(page_size - 1);
    mprotect((void*)addr_page, page_size, PROT_READ | PROT_WRITE | PROT_EXEC);

    g_original_bytes = malloc(g_patch_size);
    memcpy(g_original_bytes, g_target_addr, g_patch_size);

    void* hook_addr = (void*)&Hook_{func_name};
    intptr_t rel_addr = (intptr_t)hook_addr - ((intptr_t)g_target_addr + 5);

    uint8_t patch[12];
    patch[0] = 0xE9; 
    *(int32_t*)(patch + 1) = (int32_t)rel_addr;
    for (int i = 5; i < g_patch_size; i++) patch[i] = 0x90;

    memcpy(g_target_addr, patch, g_patch_size);

    void* tramp = mmap(NULL, page_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (tramp == MAP_FAILED) {
        printf("[InlinePatch] Failed to mmap trampoline.\n");
        return;
    }
    memcpy(tramp, g_original_bytes, g_patch_size);

    uint8_t* tramp_bytes = (uint8_t*)tramp;
    tramp_bytes += g_patch_size;
    tramp_bytes[0] = 0xE9;
    intptr_t rel_addr2 = ((intptr_t)g_target_addr + g_patch_size) - ((intptr_t)tramp + g_patch_size + 5);
    *(int32_t*)(tramp_bytes + 1) = (int32_t)rel_addr2;

    original_{func_name} = ({func_name}_t)tramp;
}

int main(int argc, char* argv[])
{
    printf("[InlinePatch] Installing patch...\n");
    patch_inline();
    printf("[InlinePatch] Patch installed.\n");
    return 0;
}
'''

    header_cpp = '''#pragma once

{typedef_line}
{return_type} Hook_{func_name}({cpp_params_decl});
void patch_inline();
'''.format(
        typedef_line=typedef_line,
        return_type=return_type,
        func_name=func_name,
        cpp_params_decl=cpp_params_decl_str
    )

    return main_cpp, header_cpp
