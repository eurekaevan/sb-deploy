"""Dispatch the shell's fixed module/action calls after loading its context."""

import importlib
import sys

from sb_deploy.context import load

load()
module_name, action = sys.argv[1:3]
sys.argv = [module_name, *sys.argv[3:]]
module = importlib.import_module("sb_deploy." + module_name)
getattr(module, action)()
