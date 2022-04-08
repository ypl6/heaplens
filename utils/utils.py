import re
import gdb


def escape_ansi(line):
    ansi_escape = re.compile(r'(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', line)

# def int_to_string(n):
#     """Convert int to string. (Not used, not debug-ed)"""
#     # return str(binascii.unhexlify(hex(int(n))[2:]))
#     return bytes.fromhex(hex(int(n))[2:]).decode("ASCII")[::-1]


def stoi(s):
    # might be broken
    # this is a program intended for 64-bit machines so pointer sizes are 64 bits
    r = int(s) & 0xffffffffffffffff
    return r


def read_register(register):
    val = gdb.parse_and_eval("${}".format(register))
    s_val = stoi(val)
    return s_val


def record_updated_chunks(log):
    addr_re = r'.*addr=(.{14})'
    bins = gdb.execute("heap bins", to_string=True)
    for bin in bins.splitlines():
        # Example: Chunk(addr=0x56206612bd30, size=0x12d0, flags=PREV_INUSE)
        # address length is 14
        addr = "".join(re.findall(addr_re, bin))
        if addr:
            log['free'][addr] = {}
    chunks = gdb.execute("heap chunks", to_string=True)
    for chunk in chunks.splitlines():
        addr = "".join(re.findall(addr_re, chunk))
        if addr in log['free'].keys():
            log['chunks'][addr] = chunk + \
                "\033[0;34m  ←  free chunk\033[0m"
        else:
            log['chunks'][addr] = chunk
