"""Build a self-contained release from the editable shell and Python sources."""

import base64
import json
import sys
import zlib
from pathlib import Path

START = "# BEGIN PYTHON RUNNER\n"
END = "# END PYTHON RUNNER"
PACKED = "# BUNDLED PYTHON"


def bundle_script(source: str, modules: Path) -> str:
    """Keep customized defaults and embed modules; already bundled files copy unchanged."""
    if START not in source or PACKED in source:
        return source
    if source.count(START) != 1 or source.count(END) != 1:
        raise ValueError("Expected one Python runner block")
    sources = {path.stem: path.read_text() for path in sorted(modules.glob("*.py"))}
    if not sources:
        raise ValueError("No Python modules found")
    payload = base64.b85encode(zlib.compress(json.dumps(sources).encode(), 9)).decode()
    bootstrap = f"""import base64, json, sys, types, zlib
sources = json.loads(zlib.decompress(base64.b85decode({payload!r})))
package = types.ModuleType("sb_deploy")
package.__path__ = []
sys.modules["sb_deploy"] = package
context_module = types.ModuleType("sb_deploy.context")
exec(compile(sources["context"], "context.py", "exec"), context_module.__dict__)
sys.modules["sb_deploy.context"] = context_module
package.context = context_module
context_module.load()
name, action = sys.argv[1:3]
sys.argv = [name, *sys.argv[3:]]
module = types.ModuleType("sb_deploy." + name)
exec(compile(sources[name], name + ".py", "exec"), module.__dict__)
setattr(package, name, module)
getattr(module, action)()
"""
    delimiter = "SB_PYTHON_BUNDLE_END"
    if delimiter in bootstrap:
        raise ValueError("Python bundle delimiter appears in the payload")
    runner = (
        START
        + PACKED
        + "\npython_module() {\n"
        + "  # The module travels on fd 3 and operation context on fd 4; stdin stays free.\n"
        + f"  python3 /dev/fd/3 \"$@\" 4< <(python_context) 3<<'{delimiter}'\n"
        + bootstrap
        + delimiter
        + "\n}\n"
        + END
    )
    before, rest = source.split(START)
    _, after = rest.split(END)
    return (before + runner + after).replace('PYTHON_ROOT="${SCRIPT_PATH%/*}/lib"\n', "")


def build():
    source, output = map(Path, sys.argv[1:3])
    text = source.read_text()
    # An installed manager can copy itself without needing the source modules.
    if START in text and PACKED not in text:
        text = bundle_script(text, Path(__file__).parent)
    output.write_text(text)
    output.chmod(0o700)
