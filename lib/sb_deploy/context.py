"""Versioned shell-to-Python context passed on a dedicated file descriptor.

Protocol (version 1), written by ``python_context`` in the shell:

    SBD_CONTEXT\\0 1\\0 KEY\\0VALUE\\0 ... READY\\0

The shell sends this stream on fd 4 so credentials never enter argv, the
environment, or stdin (which remains available for data).  Python code reads the
mapping through this module instead of depending on an implicit set of
environment variables.  A mismatched protocol version fails closed; update the
shell and Python code together.  Direct module tests can install the same
mapping with ``use`` or ``temporary``.
"""

import contextlib
import os
import re
import sys
from collections.abc import Mapping

CONTEXT_FD = 4
PROTOCOL = b"SBD_CONTEXT"
VERSION = b"1"
_KEY = re.compile(r"[A-Z][A-Z0-9_]*")
_context = None


class Context(Mapping):
    """Read-only view of the operation context loaded from the shell."""

    def __getitem__(self, key):
        return load()[key]

    def __iter__(self):
        return iter(load())

    def __len__(self):
        return len(load())

    def get(self, key, default=None):
        return load().get(key, default)

    def require(self, key):
        try:
            return load()[key]
        except KeyError:
            sys.exit("缺少 Python 运行上下文：" + key)


context = Context()


def _parse(raw):
    records = raw.split(b"\0")
    if records and records[-1] == b"":
        records.pop()
    if (
        len(records) < 3
        or records[0] != PROTOCOL
        or records[1] != VERSION
        or records[-1] != b"READY"
    ):
        sys.exit("Python 运行上下文格式或版本不匹配；请使用配套的 shell 脚本。")
    fields = records[2:-1]
    if len(fields) % 2:
        sys.exit("Python 运行上下文缺少值。")
    values = {}
    for key, value in zip(fields[::2], fields[1::2], strict=True):
        try:
            name = key.decode("ascii")
            text = value.decode("utf-8")
        except UnicodeError:
            sys.exit("Python 运行上下文编码无效。")
        if not _KEY.fullmatch(name) or name in values:
            sys.exit("Python 运行上下文包含无效或重复的键。")
        values[name] = text
    return values


def load(fd=CONTEXT_FD):
    """Read and validate the context once; an already installed mapping wins."""
    global _context
    if _context is not None:
        return _context
    chunks = []
    try:
        while chunk := os.read(fd, 65536):
            chunks.append(chunk)
    except OSError as error:
        sys.exit("无法读取 Python 运行上下文：" + str(error))
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
    _context = _parse(b"".join(chunks))
    return _context


def use(values):
    """Install a mapping for direct tests or embedded callers."""
    global _context
    _context = {str(key): str(value) for key, value in values.items() if value is not None}
    return _context


@contextlib.contextmanager
def temporary(values):
    """Temporarily install a context mapping and restore the previous one."""
    global _context
    previous = _context
    use(values)
    try:
        yield
    finally:
        _context = previous
