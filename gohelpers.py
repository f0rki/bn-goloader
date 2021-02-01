#!/usr/bin/env python
"""
A binaryninja plugin to assist loading go binaries

Copyright (c) 2017 Michael Rodler
Licensed under MIT License, see LICENCE.
"""

import re
import struct

import binaryninja as bn
from binaryninja.log import log_alert, log_debug, log_info, log_warn

_RE_REPLACE_UNDERSCORE = re.compile("[^a-zA-Z0-9\.]")
_RE_COMPRESS_UNDERSCORE = re.compile("__+")

GOFUNC_PREFIX = "go."

# log_debug = log_info


def santize_gofunc_name(name):
    name = name.replace(" ", "")
    # name = name.replace(";", "_")
    # name = name.replace(",", "_")
    return name


def sanitize_var_name(name):
    varname = _RE_REPLACE_UNDERSCORE.sub("_", name)
    varname = _RE_COMPRESS_UNDERSCORE.sub("_", varname)
    return varname


class GoHelper(bn.plugin.BackgroundTaskThread):
    def __init__(self, bv):
        bn.plugin.BackgroundTaskThread.__init__(self, "Go Loader Helper", True)
        self.bv = bv
        self.br = bn.binaryview.BinaryReader(bv)
        self.ptr_size = bv.platform.arch.address_size

    def get_section_by_name(self, section_name):
        if section_name in self.bv.sections:
            return self.bv.sections[section_name]
        else:
            return None

    def get_pointer_at_virt(self, addr, size=None):
        x = self.bv.read(addr, self.ptr_size)
        if len(x) == 8:
            return struct.unpack("Q", x)[0]
        elif len(x) == 4:
            return struct.unpack("I", x)[0]
        else:
            raise ValueError("Invalid size {} for pointer; data: {!r}"
                             .format(len(x), x))

    def get_pointer_at(self, at_addr, size=None):
        self.br.seek(at_addr)
        if size is None:
            size = self.ptr_size

        if size == 8:
            return self.br.read64()
        elif size == 4:
            return self.br.read32()
        else:
            raise ValueError("Unsupported ptr_size: {!r}".format(size))

    def get_function_around(self, addr):
        bbl = self.bv.get_basic_blocks_at(addr)
        if not bbl:
            return None
        bb = bbl[0]
        if not bb:
            return None
        return bb.function


class FunctionRenamer(GoHelper):
    def rename_functions(self):
        renamed = 0
        log_info("renaming functions based on .gopclntab section")

        gopclntab = self.get_section_by_name(".gopclntab")

        if gopclntab is None:
            pattern = "\xfb\xff\xff\xff\x00\x00"
            base_addr = self.bv.find_next_data(0, pattern)

            if base_addr is None:
                log_alert("Failed to find section '.gopclntab'")
                return
        else:
            base_addr = gopclntab.start

        size_addr = base_addr + 8
        size = self.get_pointer_at(size_addr)

        log_info("found .gopclntab section at 0x{:x} with {} entries"
                 .format(base_addr, size / (self.ptr_size * 2)))

        start_addr = size_addr + self.ptr_size
        end_addr = base_addr + (size * self.ptr_size * 2)

        for addr in range(start_addr, end_addr, (2 * self.ptr_size)):
            log_debug("analyzing at 0x{:x}".format(addr))
            func_addr = self.get_pointer_at(addr)
            entry_offset = self.get_pointer_at(addr + self.ptr_size)

            log_debug("func_addr 0x{:x}, entry offset 0x{:x}"
                      .format(func_addr, entry_offset))

            name_str_offset = self.get_pointer_at(
                base_addr + entry_offset + self.ptr_size, 4)
            name_addr = base_addr + name_str_offset

            name = self.bv.get_ascii_string_at(name_addr)
            if not name:
                continue
            name=name.value

            log_debug("found name '{}' for address 0x{:x}"
                      .format(name, func_addr))

            func = self.bv.get_function_at(func_addr)
            if not func:
                func = self.bv.create_user_function(func_addr)

            if name and len(name) > 2:
                name = GOFUNC_PREFIX + santize_gofunc_name(name)
                sym = bn.types.Symbol('FunctionSymbol', func_addr, name, name)
                self.bv.define_user_symbol(sym)
                renamed += 1
            else:
                log_warn(("not using function name {!r} for function at 0x{:x}"
                          " in .gopclntab addr 0x{:x} name addr 0x{:x}")
                         .format(name, func_addr, addr, name_addr))

        log_info("renamed {} go functions".format(renamed))

    def run(self):
        self.rename_functions()


def rename_functions(bv):
    helper = FunctionRenamer(bv)
    helper.start()


# FIXME: this one doesn't work as expected... :S
class NewProcRenamer(GoHelper):
    def rename(self):
        renamed = 0
        newprocfn = self.bv.get_symbol_by_raw_name("go.runtime.newproc")
        xrefs = self.bv.get_code_refs(newprocfn.address)
        for xref in xrefs:
            log_info("found xref at 0x{:x}".format(xref.address))
            addr = xref.address
            fn = self.get_function_around(addr)
            callinst = fn.get_low_level_il_at(addr)
            if callinst.operation != bn.LowLevelILOperation.LLIL_CALL:
                log_debug("not a call instruction {!r}".format(callinst))
                continue
            params = []
            # FIXME: this is such a dirty hack
            # get the previous two LIL instruction
            j = 1
            while len(params) < 2:
                for i in range(1, 7):
                    try:
                        j += 1
                        inst = fn.get_low_level_il_at(addr - j)
                        log_debug("instruction: -{} {!r}".format(j, inst))
                        break
                    except IndexError:
                        continue
                params.append(inst)

            # FIXME: does this work on non-x86?
            # check if 2 push instructions
            skip = True
            for inst in params:
                if inst.operation != bn.LowLevelILOperation.LLIL_PUSH:
                    skip = True
            if skip:
                continue

            # get the address of the function pointer, which should be the
            # second push instruction
            inst = params[1]
            fptr = inst.src.value.value
            log_info("found call to newproc {!r} with fptr {!r}"
                     .format(callinst, fptr))

            if fptr and not self.bv.get_symbol_at(fptr):
                a = self.get_pointer_at_virt(fptr)
                # target function
                tfn = self.bv.get_function_at(a)
                if tfn:
                    varname = "fptr_"
                    varname += sanitize_var_name(tfn.name)
                    t = self.bv.parse_type_string("void*")
                    self.bv.define_user_data_var(a, t[0])
                    sym = bn.types.Symbol('DataSymbol', a, varname, varname)
                    self.bv.define_user_symbol(sym)
                    renamed += 1

        log_info("renamed {} function pointers, passed to newproc"
                 .format(renamed))

    def run(self):
        self.rename()


def rename_newproc_fptrs(bv):
    helper = NewProcRenamer(bv)
    helper.start()


# def create_runtime_morestack():
#     log.info("Attempting to find 'runtime.morestack' function")
#     text_seg = get_section_by_name('.text')
#     # text_vaddr = text_seg['vaddr']

#     # This code string appears to work for ELF32 and ELF64 AFAIK
#     s = "mov qword [0x1003], 0"
#     res = cmdj("/aj " + s, text_seg)
#     if not res:
#         # let's search for the assembled variant
#         if ARCH == "x86" and BITS == 64:
#             h = "48c704250310.c3"
#             res = cmdj("/xj " + h, text_seg)

#     if not res:
#         log.warning("Couldn't find morestack signature")
#         return None

#     if len(res) > 1:
#         log.warning("more than one signature match... trying first")

#     res = res[0]
#     runtime_ms = cmdj("afij", res["offset"])[0]

#     if not runtime_ms:
#         log.warning("undefined function at morestack...")
#         return None

#     offset = runtime_ms['offset']
#     log_debug("runtime.morestack begins at 0x{:x}"
#               .format(runtime_ms[offset]))

#     if "morestack" not in runtime_ms["name"]:
#         log_debug("renaming {} to 'runtime.morestack'"
#                   .format(runtime_ms["name"]))
#         cmd("afn {} {}".format("runtime.morestack", runtime_ms['offset']))

#     return runtime_ms
