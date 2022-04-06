import re
import gdb


def escape_ansi(line):
    ansi_escape = re.compile(r'(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', line)


def record_updated_chunks():
    global __heaplens_log__

    addr_re = r'.*addr=(.{14})'
    bins = gdb.execute("heap bins", to_string=True)
    for bin in bins.splitlines():
        # Example: Chunk(addr=0x56206612bd30, size=0x12d0, flags=PREV_INUSE)
        # address length is 14
        addr = "".join(re.findall(addr_re, bin))
        if addr:
            __heaplens_log__['bins'].append(addr)
    chunks = gdb.execute("heap chunks", to_string=True)
    for chunk in chunks.splitlines():
        addr = "".join(re.findall(addr_re, chunk))
        if addr in __heaplens_log__['bins']:
            __heaplens_log__['chunks'].append(
                chunk + "  ←  free chunk")
        else:
            __heaplens_log__['chunks'].append(chunk)
