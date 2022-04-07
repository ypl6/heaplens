from multiprocessing.sharedctypes import Value
from unicodedata import name
from xml.dom.minidom import Identified
import gdb
import binascii
import re
import argparse
import json
import sys
import os
sys.path.append(os.getcwd())

from utils import *

"""
Goal(?)
$ gdb sudoedit
set solib-search-path /lib/sudo

(gdb) list-env-in-heap
    ...
    ...
    Possible environment variables to fuzz:
        LC_ALL
        TZ
        ...
(gdb) heaplens output.txt
    Successfully write to output.txt
(gdb)

"""


"""
Commands
list-env-in-heap
heaplens
heaplens-crash-sudo
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

    def cleanup(self, bkps):
        print("Removing breakpoints")
        for bp in bkps:
            bp.delete()


# def int_to_string(n):
#     """Convert int to string. (Not used, not debug-ed)"""
#     # return str(binascii.unhexlify(hex(int(n))[2:]))
#     return bytes.fromhex(hex(int(n))[2:]).decode("ASCII")[::-1]


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


class Heaplens(HeaplensCommand):
    """A generic Heaplens command that collect heap info from memory (de)allocation functions."""

    def __init__(self):
        super().__init__("heaplens", gdb.COMMAND_USER)

    class GetMainBreakpoint(gdb.Breakpoint):
        """A dummy breakpoint for the first execution to ensure free/alloc functions can be hooked."""

        def __init__(self, name, *args, **kwargs):
            super().__init__(name, gdb.BP_BREAKPOINT, internal=False, temporary=True)

        def stop(self):
            return False

    class GetRetBreakpoint(gdb.Breakpoint):
        def __init__(self, name, fname, alloc, heaplens_details):
            super().__init__(name, gdb.BP_BREAKPOINT, internal=False, temporary=True)
            self.fname = fname
            self.trigger = False

            self.heap_trace_info = heaplens_details
            self.alloc_size = alloc

        def stop(self):
            ret_address = read_register("rax")
            print(f"{self.fname} returns {hex(ret_address)}")

            self.heaplens_details[ret_address] = {}
            self.heaplens_details[ret_address]['backtrace'] = gdb.execute(
                "bt", to_string=True)
            self.heaplens_details[ret_address]['size'] = self.alloc

            backtrace()

            self.trigger = True
            return False

        def executed(self):
            return self.trigger

    class GetAllocBreakpoint(gdb.Breakpoint):
        """TODO: add description"""

        # def stop(self):
        #     global __heaplens_log__
        #     # TODO
        #     return False

        def __init__(self, name, fname, heaplens_details):
            super().__init__(name, gdb.BP_BREAKPOINT, internal=False)
            self.fname = fname
            self.prev_bp = None
            self.heaplens_details = heaplens_details
            self.return_value_bp_list = []

        def stop(self):
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
            if self.fname == "malloc":
                size = read_register("rdi")
            elif self.name == "calloc":  # allocates an array so tot size = num objs * size of obj
                size = read_register("rdi") * read_register("rsi")
            elif self.fname == "realloc":
                ptr = read_register("rdi")
                size = read_register("rsi")
                if ptr in self.heaplens_details:
                    del self.heaplens_details[ptr]

            current_frame = gdb.selected_frame()
            caller = current_frame.older().pc()

            print(f"{self.fname} size = {hex(size)}, caller = {hex(caller)}")
            bp = self.GetRetBreakpoint(
                f"{hex(caller)}", self.fname, size, self.healens_info)
            self.return_value_bp_list.append(bp)

            return False

    class GetFreeBreakpoint(gdb.Breakpoint):
        """TODO: add description"""

        def __init__(self, name, *args, **kwargs):
            super().__init__(name, gdb.BP_BREAKPOINT, internal=False)

        def stop(self):
            global __heaplens_log__
            # TODO
            return False

    def parse_args(self, args):
        parser = argparse.ArgumentParser(description="Collect heap info from memory (de)allocation functions.",
                                         formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        parser.add_argument("-b", "--breakpoint", type=str, action="append",
                            help="stop the executions here (execute br {breakpoint} in gdb)")

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
        print("Initializing Heaplens")
        print(f"Setting breakpoints at {args.breakpoint}...")
        print(f"Running {run_args}")
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

        self.mem_bkps.append(
            self.GetFreeBreakpoint(name="free", log=__heaplens_log__))
        self.mem_bkps.append(
            self.GetAllocBreakpoint(name="malloc", log=__heaplens_log__))
        self.mem_bkps.append(
            self.GetAllocBreakpoint(name="calloc", log=__heaplens_log__))
        self.mem_bkps.append(
            self.GetAllocBreakpoint(name="realloc", log=__heaplens_log__))

        gdb.execute(f"break {args.breakpoint}")
        gdb.execute(f"r {run_args}" if run_args else "r")

        # self.cleanup(self.mem_bkps)

        gdb.execute("gef config context.enable True")

    print("TODO")


# Instantiates the class (register the command)
Heaplens()


class HeaplensCrashSudo(HeaplensCommand):
    """Examine vulnerable sudo's set_cmnd()."""

    def __init__(self):
        super().__init__("heaplens-crash-sudo", gdb.COMMAND_USER)

    class GetSetCmndBreakpoint(gdb.Breakpoint):
        """Print chunk info at the vulnerable set_cmnd() function"""

        def __init__(self, name, log, *args, **kwargs):
            super().__init__(name, gdb.BP_BREAKPOINT, internal=False)
            self.log = log

        def stop(self):
            record_updated_chunks(self.log)
            return True

    def parse_args(self, args):
        parser = argparse.ArgumentParser(
            description="A tailored command to examine vulnerable sudo's set_cmnd().",
            formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        parser.add_argument("-s", "--string", type=str, default="A",
                            help="the string to send as NewArgv[2]")
        parser.add_argument("-r", "--repeat", type=int, default=65535,
                            help="repeat the payload string for {repeat} times")

        if args:
            return parser.parse_args(args.strip().split(" "))
        else:
            return parser.parse_args([])

    def invoke(self, arg, from_tty):
        # Parse arguments aake sure current file is sudoedit
        try:
            args = self.parse_args(arg)
            gdb.execute("file sudoedit")
        except gdb.error:
            print(
                "Warning: sudoedit is not found. This command is only for sudoedit.")
            return

        global __heaplens_log__
        print("Initializing Heaplens for sudoedit")

        # # Disable gef output
        # gdb.execute("gef config context.enable False")

        # # 1st execution: Make it crash and add breakpoint
        # # Code is loaded dynamically, the breakpoint in sudoers.c can be
        # # retrieved only if we crash the program
        # crash_payload = f"-s '\\' $(python3 -c 'print(\"{args.string}\"*{args.repeat})')"

        # # enable batch mode silently to suppress the vim process as inferior
        # gdb.execute(f"r {crash_payload}")

        # print(DIVIDER)
        # print("Setting breakpoints")
        # self.vul_bkps = []
        # self.vul_bkps.append(
        #     self.GetSetCmndBreakpoint(name="set_cmnd", log=__heaplens_log__))

        # print(DIVIDER)
        # print("Collecting chunk information")
        # # 2nd execution: Inspect.
        # gdb.execute(f"r {crash_payload}")

        # self.cleanup(self.vul_bkps)

        # # Re-enable gef output
        # gdb.execute("gef config context.enable True")


# Instantiates the class (register the command)
HeaplensCrashSudo()


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
            description="Dump Heaplens logs.", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        parser.add_argument("-o", "--output", type=str,
                            help="write to file at path {output}")

        args = parser.parse_args(args.strip().split(" "))
        return args

    def invoke(self, arg, from_tty):
        # Parse arguments
        args = self.parse_args(arg)
        print(DIVIDER)

        global __heaplens_log__
        args = arg.split(" ")

        if args.output:
            print("TODO!")
        else:
            print("TODO!")

        #

        if len(args) == 0:
            print("Usage: heaplens [print] [out outputfilepath]")
            return

        elif len(args) > 2:
            print("Too many arguments")
            return

        if args[0] == "print":
            print(DIVIDER)
            print("Dumping log...")

            for i, (j, k) in enumerate(heaplens_details.items()):
                print(f"Chunk {i} @ {hex(j)} | size {hex(k['size'])}")
                print("Printing trace:\n", k['backtrace'])

            return

        elif args[0] == "out":
            with open(args[2], "w") as fo:
                fo.write(json.dumps(heaplens_details))

        else:
            print("Invalid arguments")
            return


# Instantiates the class (register the command)
HeaplensDump()


# Debug: auto run command on gdb startup
cmds = [
    "file sudoedit",
    # "list-env-in-heap -s LC_ALL -b set_cmnd --prefix C.UTF-8@ -- -s '\\' AAAAAAAAAAAAAAAAAAAAAAAAAAA",

    # "file tests/env-in-heap",
    # "list-env-in-heap -b breakme",
    # "heaplens-crash-sudo -s A -r 65535",

    # "heaplens test.txt",
    # "q",
]
for cmd in cmds:
    gdb.execute(cmd)
