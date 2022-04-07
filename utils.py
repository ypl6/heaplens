import re
import gdb


def escape_ansi(line):
    ansi_escape = re.compile(r'(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', line)

# might be broken


def stoi(s):
    # this is a program intended for 64-bit machines so pointer sizes are 64 bits
    r = int(s) & 0xffffffffffffffff
    return r


def read_register(register):
    val = gdb.parse_and_eval("${}".format(register))
    s_val = stoi(val)
    return s_val


def backtrace():
    gdb.execute("bt 15")
    print("\n", DIVIDER)


def record_updated_chunks(log, show_bt=False):
    addr_re = r'.*addr=(.{14})'
    bins = gdb.execute("heap bins", to_string=True)
    for bin in bins.splitlines():
        # Example: Chunk(addr=0x56206612bd30, size=0x12d0, flags=PREV_INUSE)
        # address length is 14
        addr = "".join(re.findall(addr_re, bin))
        if addr:
            log['bins'].append(addr)
    chunks = gdb.execute("heap chunks", to_string=True)
    for chunk in chunks.splitlines():
        addr = "".join(re.findall(addr_re, chunk))
        if addr in log['bins']:
            log['chunks'].append(
                chunk + "  ←  free chunk")
        else:
            log['chunks'].append(chunk)
