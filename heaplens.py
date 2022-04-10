from multiprocessing.sharedctypes import Value
from unicodedata import name
from xml.dom.minidom import Identified
import gdb
import re
import argparse
import json

"""
Commands
heaplens
heaplens-dump
heaplens-chunks
heaplens-clear
heaplens-list-env
"""

DIVIDER = "-" * 100
# maintains info from `heap chunks` and `heap bins`.
__chunks_log__ = {'free': {}, 'chunks': {}}
# maintains real-time info about heap layout.
__heaplens_log__ = {}

# ========================================== UTILS


def escape_ansi(line):
    ansi_escape = re.compile(r'(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', line)


def stoi(s):
    # might be broken
    # this is a program intended for 64-bit machines so pointer sizes are 64 bits
    r = int(s) & 0xffffffffffffffff
    return r


def read_register(register):
    val = gdb.parse_and_eval("${}".format(register))
    return stoi(val)


def clear_chunks_log(args):
    global __chunks_log__
    if args and args.verbose:
        len_key = len(__chunks_log__['chunks'].keys())
        print(f"Clearing {len_key} chunk records...")
    __chunks_log__ = {'free': {}, 'chunks': {}}


def clear_heaplens_log(args):
    global __heaplens_log__
    if args and args.verbose:
        len_key = len(__heaplens_log__.keys())
        print(f"Clearing {len_key} backtrace records...")
    __heaplens_log__ = {}


def record_updated_chunks():
    global __chunks_log__
    # 64-bit only
    addr_re = r'\(addr=(.{14})'
    bins = gdb.execute("heap bins", to_string=True)
    for bin in bins.splitlines():
        # Example: Chunk(addr=0x56206612bd30, size=0x12d0, flags=PREV_INUSE)
        # address length is 14
        addr = "".join(re.findall(addr_re, bin))
        if addr:
            __chunks_log__['free'][addr] = {}
    chunks = gdb.execute("heap chunks", to_string=True)
    # look ahead regex to keep delimiter
    for chunk in re.split(r'.(?=\])', chunks):
        addr = "".join(re.findall(addr_re, chunk))
        if addr in __chunks_log__['free'].keys():
            __chunks_log__['chunks'][addr] = re.sub(
                "\)\n", ")\033[0;34m  ←  free chunk\033[0m\n", chunk)
        else:
            __chunks_log__['chunks'][addr] = chunk


# ========================================== HEAPLENS


class HeaplensCommand(gdb.Command):
    """Class to provide common methods. Not to be instantiated."""

    def cleanup(self, bkps, tag=""):
        print("Removing breakpoints" +
              (f' from {tag}...' if tag != '' else '...'))
        for bp in bkps:
            bp.delete()


class HeaplensListEnv(HeaplensCommand):
    """List environment variables that might affect the heap layout."""

    def __init__(self):
        super(HeaplensListEnv, self).__init__(
            "heaplens-list-env", gdb.COMMAND_USER)

    class GetEnvBreakpoint(gdb.Breakpoint):
        """Log environment variable name at breakpoint."""

        def __init__(self, name, log, *args, **kwargs):
            super().__init__(name, gdb.BP_BREAKPOINT, internal=False)
            # self.silent = False
            self.log = log

        def stop(self):
            # arg = gdb.selected_frame().read_register("$rdi")
            # arg = gef.arch.register("$rdi")
            env = gdb.execute("x/s $rdi", to_string=True)
            match = re.search(r'".+"', env)
            if match:
                var_name = match.group(0)[1:-1]
                if var_name not in self.log['env']:
                    self.log['env'].append(var_name)
            return False

    class FreeBreakpoint(gdb.Breakpoint):
        """Log environment variable that contains 'FuzzMe{number}' at breakpoint."""

        def __init__(self, name, log, cmd_args, *args, **kwargs):
            super().__init__(name, gdb.BP_BREAKPOINT, internal=False)
            self.log = log
            self.args = cmd_args

        def stop(self):
            # arg = gdb.selected_frame().read_register("$rdi")
            # arg = gef.arch.register("$rdi")
            env = gdb.execute("x/s $rdi", to_string=True)
            match = re.search(r'".+"', env)
            if match:
                value = match.group(0)[1:-1]

                if 'FuzzMe' in value:
                    if self.args and self.args.verbose:
                        print(f"\tFound {value}")
                    identifiers = re.findall(r'FuzzMe\d+', value)
                    for i in identifiers:
                        self.log['fuzzable'].append(self.log['env_value'][i])
            return False

    def parse_args(self, args):
        parser = argparse.ArgumentParser(
            description="List environment variables that might affect the heap layout.")
        parser.add_argument("-v", "--verbose", action="store_true",
                            help="increase output verbosity")
        parser.add_argument("--prefix", type=str,
                            help="environment variable value prefix")
        parser.add_argument("--suffix", type=str,
                            help="environment variable value suffix")
        parser.add_argument("-b", "--breakpoint", type=str,
                            help="stop the executions here (execute br {breakpoint} in gdb)")
        parser.add_argument("-s", "--skip", type=str,
                            help="skip this environment variable")

        if not args:
            return None, None
        elif ' -- ' in args:  # both run args and args
            args, run_args = args.split(' -- ')
            args = parser.parse_args(args.strip().split(" "))
            return run_args, args
        elif args.startswith('-- '):  # run args only
            return args[3:], None
        else:  # args only
            args = parser.parse_args(args.strip().split(" "))
            return None, args

    def invoke(self, arg, from_tty):
        # Parse arguments
        run_args, args = self.parse_args(arg)
        run_cmd = f"r {run_args}" if run_args else "r"
        if args and args.verbose:
            print(DIVIDER)
            print(f" args: {args}\n run_args: {run_args}")
            print(DIVIDER)

        # Disable gef output
        gdb.execute(f"gef config context.enable False", to_string=True)

        self.log = {'env': [], 'fuzzable': [], 'env_value': {}}

        # 1st execution: Get environment variables used
        self.getenv_bkps = []
        self.getenv_bkps.append(
            self.GetEnvBreakpoint(name="getenv", log=self.log))

        # Run and print result
        gdb.execute(run_cmd)
        print(DIVIDER)
        print("1st execution. Found following environment variable:")
        print(self.log['env'])
        print(DIVIDER)
        self.cleanup(self.getenv_bkps)

        # 2nd execution: Filter environment variables appears in heap
        # set all env variable to recongizeable string
        skips = args.skip.split(",") if args and args.skip else []
        print(f"Skipping environment variable: {skips}")
        for i, var_name in enumerate(self.log['env']):
            if var_name in skips:
                continue
            value = f"FuzzMe{i}"
            if args and args.prefix:
                value = args.prefix + value
            if args and args.suffix:
                value += args.suffix
            gdb.execute(f"set environment {var_name} {value}")
            self.log['env_value'][f"FuzzMe{i}"] = var_name
        # print(self.log)

        self.free_bkps = []
        self.free_bkps.append(self.FreeBreakpoint(
            name="free", log=self.log, cmd_args=args))
        if args and args.breakpoint:
            gdb.execute(f"br {args.breakpoint}")

        # Run and print result
        gdb.execute(run_cmd)
        print(DIVIDER)
        print("2nd execution. Possible environment variables for heap grooming:")
        print(list(set(self.log['fuzzable'])))
        print(DIVIDER)
        self.cleanup(self.free_bkps)

        # Re-enable gef output
        gdb.execute(f"gef config context.enable True", to_string=True)


# Instantiates the class (register the command)
HeaplensListEnv()


class GetRetBreakpoint(gdb.Breakpoint):
    def __init__(self, name, fname, alloc, verbose):
        super().__init__(
            name, gdb.BP_BREAKPOINT, internal=True, temporary=True)
        self.name = name
        self.fname = fname
        self.trigger = False
        self.alloc_size = alloc
        self.verbose = verbose

    def stop(self):
        global __heaplens_log__
        ret_address = read_register("rax")
        if self.verbose:
            print(f"{self.fname} returns {hex(ret_address)}")

        bt = gdb.execute("bt", to_string=True)

        __heaplens_log__[ret_address] = {
            "source": self.fname,
            "backtrace": bt,
            "size": self.alloc_size
        }

        if self.verbose:
            gdb.execute("bt 15")
            print("\n" + DIVIDER)

        self.trigger = True
        return False

    def executed(self):
        return self.trigger


class Heaplens(HeaplensCommand):
    """A generic Heaplens command that collects heap info from memory (de)allocation functions."""

    def __init__(self):
        super().__init__("heaplens", gdb.COMMAND_USER)

    class GetMainBreakpoint(gdb.Breakpoint):
        """A dummy breakpoint for the first execution to ensure free/alloc functions can be hooked."""

        def __init__(self, name):
            super().__init__(name, gdb.BP_BREAKPOINT, internal=False, temporary=True)

        def stop(self):
            # do not interfere
            return False

    class GetCustomBreakpoint(gdb.Breakpoint):
        """Stop at a specific breakpoint and update log."""

        def __init__(self, name):
            super().__init__(name, gdb.BP_BREAKPOINT, internal=False)

        def stop(self):
            record_updated_chunks()
            return True

    class GetAllocBreakpoint(gdb.Breakpoint):
        """Stop at allocation functions and update log."""

        def __init__(self, name, verbose):
            super().__init__(name, gdb.BP_BREAKPOINT, internal=False)
            self.name = name
            self.prev_bp = None
            self.return_value_bp_list = []
            self.verbose = verbose

        def stop(self):
            global __heaplens_log__
            if self.prev_bp != None:
                self.prev_bp.delete()

            to_delete = []

            for bp in self.return_value_bp_list:
                if bp.executed():
                    to_delete.append(bp)

            for bp in to_delete:
                bp.delete()
                self.return_value_bp_list.remove(bp)

            size = 0
            if self.name == "malloc":
                size = read_register("rdi")
            elif self.name == "calloc":  # allocates an array so tot size = num objs * size of obj
                size = read_register("rdi") * read_register("rsi")
            elif self.name == "realloc":
                ptr = read_register("rdi")
                size = read_register("rsi")
                if ptr in __heaplens_log__:
                    del __heaplens_log__[ptr]

            current_frame = gdb.selected_frame()
            caller = current_frame.older().pc()

            if self.verbose:
                print(f"{self.name} size = {hex(size)}, caller = {hex(caller)}")

            bp = GetRetBreakpoint(name=f"*{hex(caller)}", fname=self.name,
                                  alloc=size, verbose=self.verbose)
            self.return_value_bp_list.append(bp)

            return False

    class GetFreeBreakpoint(gdb.Breakpoint):
        """Stop at free function and update log."""

        def __init__(self, name, verbose):
            super().__init__(
                name, gdb.BP_BREAKPOINT, internal=False)
            self.name = name
            self.verbose = verbose

        def stop(self):
            global __heaplens__log
            global __chunks_log__

            addr = read_register("rdi")
            bt = gdb.execute("bt 15", to_string=True)

            __chunks_log__['free'][addr] = {
                "source": self.name,
                "backtrace": bt,
                "size": None,
            }

            if addr in __heaplens_log__:
                if self.verbose:
                    print(f"Freeing {hex(addr)}")
                    print(bt)
                del __heaplens_log__[addr]

            return False

    def parse_args(self, args):
        parser = argparse.ArgumentParser(description="Collect heap info from memory (de)allocation functions.",
                                         formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        parser.add_argument("-b", "--breakpoint", type=str, action="append",
                            help="stop the executions here (execute br {breakpoint} in gdb)")
        parser.add_argument("-v", "--verbose", action="store_true",
                            help="increase output verbosity")
        if not args:
            args = parser.parse_args([])
            return None, args
        elif ' -- ' in args:  # both run args and args
            args, run_args = args.split(' -- ')
            args = parser.parse_args(args.strip().split(" "))
            return run_args, args
        elif args.startswith('-- '):  # run args only
            default_args = parser.parse_args([])
            return args[3:], default_args
        else:  # args only
            args = parser.parse_args(args.strip().split(" "))
            return None, args

    def invoke(self, arg, from_tty):
        # Parse arguments
        run_args, args = self.parse_args(arg)
        print(DIVIDER)

        global __heaplens_log__
        print("Initializing Heaplens")
        print(DIVIDER)

        # Disable gef output
        gdb.execute("gef config context.enable False")

        # Break at main and run with no command once to make sure free/alloc can be hooked
        main_bkp = self.GetMainBreakpoint(name="main")
        gdb.execute("r")
        main_bkp.delete()

        # Add custom breakpoints & memory-allocation-related breakpoints
        self.custom_bkps = []
        self.mem_bkps = []

        if args.breakpoint:
            for bkp in args.breakpoint:
                print(f"Setting breakpoint at {bkp}...")
                self.custom_bkps.append(
                    self.GetCustomBreakpoint(name=f"{bkp}"))

        print(f"Hooking free function...")
        self.mem_bkps.append(
            self.GetFreeBreakpoint(name="free", verbose=args.verbose))

        for func in ["malloc", "realloc", "calloc"]:
            print(f"Hooking {func} function...")
            self.mem_bkps.append(
                self.GetAllocBreakpoint(name=func, verbose=args.verbose))

        print(f"Running {run_args}..." if run_args else "Running...")
        gdb.execute(f"r {run_args}" if run_args else "r")

        self.cleanup(self.mem_bkps, tag="mem_bkps")

        gdb.execute("gef config context.enable True")


# Instantiates the class (register the command)
Heaplens()


class HeaplensClear(HeaplensCommand):
    """Clear Heaplens logs."""

    def __init__(self):
        super().__init__("heaplens-clear", gdb.COMMAND_USER)

    def parse_args(self, args):
        parser = argparse.ArgumentParser(
            description="Clear Heaplens logs.")
        parser.add_argument("-v", "--verbose", action="store_true",
                            help="increase output verbosity")
        if args:
            return parser.parse_args(args.strip().split(" "))
        else:
            return parser.parse_args([])

    def invoke(self, arg, from_tty):
        args = self.parse_args(arg)

        answer = ""
        while answer not in ["Y", "N"]:
            answer = input("Clear Heaplens log [Y/N]? ").upper()
        if answer == "Y":
            clear_chunks_log(args)
            clear_heaplens_log(args)
            print("Heaplens logs cleared")


# Instantiates the class (register the command)
HeaplensClear()


class HeaplensChunks(HeaplensCommand):
    """An extended `heap chunks` that integrates info about free chunks from `heap bins`"""

    def __init__(self):
        super().__init__("heaplens-chunks", gdb.COMMAND_USER)

    def parse_args(self, args):
        parser = argparse.ArgumentParser(
            description="A modified `heap chunks` with info about free chunks.")
        parser.add_argument('--nocolor', action="store_true",
                            help="disable ANSI color codes")
        if args:
            return parser.parse_args(args.strip().split(" "))
        else:
            return parser.parse_args([])

    def invoke(self, arg, from_tty):
        args = self.parse_args(arg)

        global __chunks_log__
        record_updated_chunks()

        print("Showing current heap info with freed chunks:")
        try:
            for _, chunk in __chunks_log__['chunks'].items():
                if args and args.nocolor:
                    chunk = escape_ansi(chunk)
                print(chunk, end="")
        except KeyError:
            print("Nothing to print")


# Instantiates the class (register the command)
HeaplensChunks()


class HeaplensDump(HeaplensCommand):
    """Dump Heaplens logs."""

    def __init__(self):
        super().__init__("heaplens-dump", gdb.COMMAND_USER)

    def __get_dump_content__(self, args):
        global __chunks_log__
        global __heaplens_log__
        merged = {**__chunks_log__['free'], **__heaplens_log__}
        mlist = list(merged.items())
        content = ""
        if args.sort:
            mlist.sort(key=lambda x: x[0])
        for i, (addr, info) in enumerate(mlist):
            if not info:
                break
            size = hex(info['size']) if info['size'] else "-"
            content += f"[{info['source']}] Chunk {i} @ {hex(addr)} | size {size}\n"
            content += f"Trace:\n{info['backtrace']}\n"
        return content

    def parse_args(self, args):
        parser = argparse.ArgumentParser(
            description="Dump Heaplens logs. Writes to stdout by default.",
            formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        parser.add_argument("-o", "--output", type=str,
                            help="write to file at path {output}")
        parser.add_argument("--json", action="store_true",
                            help="dump in json")
        parser.add_argument("-s", "--sort", action="store_true",
                            help="sort the chunks by their addresses")

        if args:
            return parser.parse_args(args.strip().split(" "))
        else:
            return parser.parse_args([])

    def invoke(self, arg, from_tty):
        global __heaplens_log__
        global __chunks_log__

        # Parse arguments
        args = {}
        try:
            args = self.parse_args(arg)
        except RuntimeWarning:
            pass

        if args and args.output:
            print("Dumping to file...")
            try:
                with open(args.output, "w") as fo:
                    if args.json:
                        fo.write(json.dumps(__heaplens_log__))
                    else:
                        fo.write(self.__get_dump_content__(args))
            except (IOError, FileNotFoundError):
                print("Failed to write to a file. Please try again.")
            print("Dump complete.")
        elif args:
            print(DIVIDER)
            print("Dumping...")
            print(DIVIDER)
            print(self.__get_dump_content__(args))
            print("Dump complete.")
            print(DIVIDER)


# Instantiates the class (register the command)
HeaplensDump()


# Debug: auto run command on gdb startup
cmds = [
    "file sudoedit",
    # "heaplens-list-env -s LC_ALL -b set_cmnd --prefix C.UTF-8@ -- -s '\\' AAAAAAAAAAAAAAAAAAAAAAAAAAA",

    # "file tests/env-in-heap",
    # "heaplens-list-env -b breakme",
    "heaplens -b set_cmnd -- -s '\\' $(python3 -c 'print(\"A\"*65535)')",
    # "heaplens -- -s '\\' $(python3 -c 'print(\"A\"*65535)')",
    # "q",
]
for cmd in cmds:
    gdb.execute(cmd)
