from multiprocessing.sharedctypes import Value
from unicodedata import name
from xml.dom.minidom import Identified
import gdb
import binascii
import re
import argparse
import json
import sys
import pathlib

# custom imports in the heaplens dir
heaplens_path = str(pathlib.Path(__file__).parent.resolve())
sys.path.append(heaplens_path + "/utils")

from utils import *


"""
Commands
list-env-in-heap
heaplens
heaplens-clear
heaplens-write
heaplens-addr
heaplens-dump

"""


DIVIDER = "-" * 100

heaplens_details = {}


class HelloWorld(gdb.Command):
    """Greet the whole world."""

    def __init__(self):
        super().__init__("hello-world", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        result = gdb.execute("disas main", to_string=True)
        print("Writing from python:\n" + result[0:70])
        print("Hello, World!")
        # gdb.execute


# Instantiates the class (register the command)
HelloWorld()


class HeaplensCommand(gdb.Command):
    """Class to provide common methods. Not to be instantiated."""

    def cleanup(self, bkps, tag=""):
        print("Removing breakpoints" +
              (f'from {tag}...' if tag != '' else '...'))
        for bp in bkps:
            bp.delete()


class ListEnvInHeap(HeaplensCommand):
    """List environment variables that might affect the heap layout."""

    def __init__(self):
        super(ListEnvInHeap, self).__init__(
            "list-env-in-heap", gdb.COMMAND_USER)

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
ListEnvInHeap()

__heaplens_log__ = {'bins': [], 'chunks': []}


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
        global heaplens_details
        ret_address = read_register("rax")
        if self.verbose:
            print(f"{self.fname} returns {hex(ret_address)}")

        bt = gdb.execute("bt", to_string=True)

        heaplens_details[ret_address] = {}
        heaplens_details[ret_address]['backtrace'] = bt
        heaplens_details[ret_address]['size'] = self.alloc_size

        if self.verbose:
            gdb.execute("bt 15")
            print("\n" + DIVIDER)

        self.trigger = True
        return False

    def executed(self):
        return self.trigger


class Heaplens(HeaplensCommand):
    """A generic Heaplens command that collect heap info from memory (de)allocation functions."""

    def __init__(self):
        super().__init__("heaplens", gdb.COMMAND_USER)

    class GetMainBreakpoint(gdb.Breakpoint):
        """A dummy breakpoint for the first execution to ensure free/alloc functions can be hooked."""

        def __init__(self, name):
            super().__init__(name, gdb.BP_BREAKPOINT, internal=False, temporary=True)

        def stop(self):
            return False

    class GetCustomBreakpoint(gdb.Breakpoint):
        """Stop at a specific breakpoint and update log."""

        def __init__(self, name):
            super().__init__(name, gdb.BP_BREAKPOINT, internal=False)

        def stop(self):
            global __heaplens_log__
            record_updated_chunks(__heaplens_log__)
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
            global heaplens_details
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
                if ptr in heaplens_details:
                    del heaplens_details[ptr]

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

        global __heaplens__log
        global heaplens_details

        def __init__(self, name, verbose):
            super().__init__(
                name, gdb.BP_BREAKPOINT, internal=False)
            self.verbose = verbose

        def stop(self):
            rdi = read_register("rdi")

            if rdi in heaplens_details:
                if self.verbose:
                    print(f"Freeing {hex(rdi)}")
                    gdb.execute("bt 15")
                del heaplens_details[rdi]

            return False

    def parse_args(self, args):
        parser = argparse.ArgumentParser(description="Collect heap info from memory (de)allocation functions.",
                                         formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        # parser.add_argument("-v", "--verbose", action="store_true",
        #                     help="increase output verbosity")
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
            return args[3:], None
        else:  # args only
            args = parser.parse_args(args.strip().split(" "))
            return None, args

    def invoke(self, arg, from_tty):
        # Parse arguments
        run_args, args = self.parse_args(arg)
        print(DIVIDER)

        global __heaplens_log__
        global heaplens_details
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

        print(f"Hooking free function free...")
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
    """Clear heaplens logs."""

    def __init__(self):
        super().__init__("heaplens-clear", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        global __heaplens_log__
        answer = ""
        while answer not in ["Y", "N"]:
            answer = input("Clear Heaplens log [Y/N]? ").upper()
        if answer == "Y":
            __heaplens_log__ = {'bins': [], 'chunks': []}
            print("Heaplens logs cleared")


# Instantiates the class (register the command)
HeaplensClear()


class HeaplensAddr(HeaplensCommand):
    """Print recorded addresses of free chunks."""

    def __init__(self):
        super().__init__("heaplens-addr", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        global __heaplens_log__
        print("Showing logged addresses of free chunks:")
        try:
            print("\n".join(__heaplens_log__['bins']))
        except KeyError:
            print("Nothing to print")


# Instantiates the class (register the command)
HeaplensAddr()


class HeaplensDump(HeaplensCommand):
    """Dump Heaplens logs."""

    def __init__(self):
        super().__init__("heaplens-dump", gdb.COMMAND_USER)

    def parse_args(self, args):
        parser = argparse.ArgumentParser(
            description="Dump Heaplens logs. Writes to stdout by default.", 
            formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        parser.add_argument("-o", "--output", type=str,
                            help="write to file at path {output}")

        if args:
            return parser.parse_args(args.strip().split(" "))
        else:
            return parser.parse_args([])

    def invoke(self, arg, from_tty):
       
        global __heaplens_log__
        global heaplens_details
        
        # Parse arguments
        args = {}
        try:
            args = self.parse_args(arg)
        except RuntimeWarning:
            pass

        try:
            if args.output:
                try:
                    print("Dumping to file...")
                    with open(args.output, "w") as fo:
                        fo.write(json.dumps(heaplens_details))
                    print("Dump complete.")
                except (IOError, FileNotFoundError):
                    print("Failed to write to a file. Please try again.")
            else:
                print(DIVIDER)
                print("Dumping...")
                print(DIVIDER)
                for i, (j, k) in enumerate(heaplens_details.items()):
                    print(f"Chunk {i} @ {hex(j)} | size {hex(k['size'])}")
                    print("Printing trace:\n", k['backtrace'])
                
                print("Dump complete.")
                print(DIVIDER)
                    
        except AttributeError:
            pass


# Instantiates the class (register the command)
HeaplensDump()


# Debug: auto run command on gdb startup
cmds = [
    "file sudoedit",
    # "list-env-in-heap -s LC_ALL -b set_cmnd --prefix C.UTF-8@ -- -s '\\' AAAAAAAAAAAAAAAAAAAAAAAAAAA",

    # "file tests/env-in-heap",
    # "list-env-in-heap -b breakme",
    "heaplens -b set_cmnd -- -s '\\' $(python3 -c 'print(\"A\"*65535)')",
    # "q",
]
for cmd in cmds:
    print(cmd)
    gdb.execute(cmd)
