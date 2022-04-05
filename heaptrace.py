import gdb

"""
Goal(?)
$ gdb sudoedit
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
        super(HelloWorld, self).__init__ ("hello-world", gdb.COMMAND_USER)

    def invoke (self, arg, from_tty):
        result = gdb.execute("disas main", to_string=True)
        print("Writing from python:\n" + result[0:70])
        print("Hello, World!")
        # gdb.execute

# Instantiates the class (register the command)
HelloWorld()


class ListEnvInHeap(gdb.Command):

    def __init__ (self):
        super(ListEnvInHeap, self).__init__ ("list-env-in-heap", gdb.COMMAND_USER)

    def invoke (self, arg, from_tty):
        print("TODO!")

# Instantiates the class (register the command)
ListEnvInHeap()


class Heaptrace(gdb.Command):

    def __init__ (self):
        super(Heaptrace, self).__init__ ("heaptrace", gdb.COMMAND_USER)

    def invoke (self, arg, from_tty):
        print(f"Running heaptrace: {arg}")
        args = arg.split(" ")
        
        with open(args[0], "w") as f:
            f.write("HEAPTRACE")
        print("TODO!")


# Instantiates the class (register the command)
Heaptrace()