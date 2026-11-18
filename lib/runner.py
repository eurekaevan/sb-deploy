"""Dispatch the shell's fixed module/action calls without consuming stdin."""

import importlib
import sys

module_name, action = sys.argv[1:3]
sys.argv = [module_name, *sys.argv[3:]]
module = importlib.import_module("sb_deploy." + module_name)
getattr(module, action)()
