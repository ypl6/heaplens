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
(gdb) heaptrace output.txt
    Successfully write to output.txt
(gdb)

"""

class HelloWorld(gdb.Command):
    """Greet the whole world."""

    def __init__ (self):
        super().__init__ ("hello-world", gdb.COMMAND_USER)

    def invoke (self, arg, from_tty):
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
    def __init__ (self):
        super(ListEnvInHeap, self).__init__ ("list-env-in-heap", gdb.COMMAND_USER)
    
    class GetEnvBreakpoint(gdb.Breakpoint):
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
        def __init__(self, name, log, *args, **kwargs):
            super().__init__(name, gdb.BP_BREAKPOINT, internal=False)
            # self.silent = False
            self.log = log

        def stop(self):
            # arg = gdb.selected_frame().read_register("$rdi")
            # arg = gef.arch.register("$rdi")
            env = gdb.execute("x/s $rdi", to_string=True)
            if 'LC_CTYPE' in env:
                print(env)
            match = re.search(r'".+"', env)
            if match:
                value = match.group(0)[1:-1]
                
                if 'FuzzMe' in value:
                    print(f"\tFound {value}")
                    identifiers = re.findall(r'FuzzMe\d+', value)
                    for i in identifiers:
                        self.log['fuzzable'].append(self.log['env_value'][i])
            return False
        
    def invoke (self, arg, from_tty):
        self.log = {'env': [], 'fuzzable': [], 'env_value': {}}

        # 1st execution: Get envirnoment variables used
        self.getenv_bkps = []
        self.getenv_bkps.append(self.GetEnvBreakpoint(name="getenv", log=self.log))
        gdb.execute(f"r {arg}")
        print("1st execution. Found following envirnoment varible:")
        print(self.log['env'])
        self.cleanup(self.getenv_bkps)

        # 2nd execution:
        # set all env variable to recongizeable string
        for i, var_name in enumerate(self.log['env']):
            gdb.execute(f"set environment {var_name} FuzzMe{i}")
            self.log['env_value'][f'FuzzMe{i}'] = var_name
        # print(self.log)

        self.free_bkps = []
        self.free_bkps.append(self.FreeBreakpoint(name="free", log=self.log))
        gdb.execute(f"r {arg}")
        print("2rd execution. Possible envirnoment variables for heap grooming:")
        print(list(set(self.log['fuzzable'])))
        self.cleanup(self.free_bkps)

    def cleanup(self, bkps):
        print("Removing breakpoints")
        for bp in bkps:
            bp.delete()

# Instantiates the class (register the command)
ListEnvInHeap()


class Heaptrace(gdb.Command):

    def __init__ (self):
        super().__init__ ("heaptrace", gdb.COMMAND_USER)

    def invoke (self, arg, from_tty):
        print(f"Running heaptrace: {arg}")
        args = arg.split(" ")

        with open(args[0], "w+") as f:
            f.write("HEAPTRACE")
        print("TODO!")


# Instantiates the class (register the command)
Heaptrace()


# Debug: auto run command on gdb startup
# cmds = [
#     "file sudoedit",
#     "list-env-in-heap -s '\\' AAAAAAAAAAAAAAAAAAAAAAAAAAA",
#     # "q",
# ]
# for cmd in cmds:
#     gdb.execute(cmd)
