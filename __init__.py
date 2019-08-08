from binaryninja import PluginCommand

from .gohelpers import rename_functions, rename_newproc_fptrs

PluginCommand.register(
    "golang - auto-rename functions",
    "Automatically rename go functions based on symbol table",
    rename_functions)

PluginCommand.register("golang - rename fptrs passed to newproc", "....",
                       rename_newproc_fptrs)
