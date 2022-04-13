![heaplens](heaplens.png)

# 🔎 Heaplens
CMPT733 Cybersecurity Lab II Project

## 📂 Repo Structure

```
.
├── README.md
├── heaplens.png
├── heaplens.py
├── logs
│   ├── sudoedit-#.txt
│   └── ...
└── tests
    ├── Makefile
    ├── env-in-heap
    └── ...
```

- `README.md`: right here!
- `heaplens.py`: the main script
- `logs/`: contains some sample logs we captured during development and testing
- `tests/`: contains some binaries (and their source codes) for testing

## 📦 Environment

Here is a list of things (and versions) we used to test the exploit. They should already be installed in the VM. In case anything is missing, follow the instruction below.

### Dependencies

- Ubuntu 20.04.4 (64-bit)
- `python` 3.8.10
- `glibc` 2.34
- `gdb` 9.2
- `gef` 2022.01
  - If `gef` is not enabled under root, take a look at `/root/.gdbinit`
  - If the file is empty, just copy what you have in `~/.gdbinit`

### `sudo` dependencies (for running `heaplens` on `sudo`)

A binary of `sudo` with debugging enabled is required. A pre-built binary with debug symbols has been installed in the VM.

```bash
cyberlab@ubuntu:~$ which sudo
/usr/local/bin/sudo

cyberlab@ubuntu:~$ sudo --version
Sudo version 1.8.31
Sudoers policy plugin version 1.8.31
Sudoers file grammar version 46
Sudoers I/O plugin version 1.8.31

cyberlab@ubuntu:~$ sudoedit -s /
sudoedit: /: not a regular file # sudo is vulnerable
```

## 📝 Loading the Plugin

This has been done in the VM. In case the configuration is erroneous, you can follow the instructions here to load Heaplens.

#### Option 1
Start `gef` and edit config:
```
gef➤ gef config gef.extra_plugins_dir <path to>/heaplens
gef➤ gef save
gef➤ q
```

This should update the file `~/.gef.rc` or `/root/.gef.rc` (under root).

#### Option 2
Add this line in `~/.gdbinit` or `/root/.gdbinit`:
```
source <path to>/heaplens/heaplens.py
```

## 💡 Usage

It is suggested to run `gdb` under root when debugging privileged programs:

```shell
$ sudo su
# gdb
```

Help messages are provided for all commands. You can access them via `<command> -h` in GDB.

### `heaplens`

Collects heap info from memory allocation and deallocation functions, including `malloc`, `realloc`, `calloc`, and `free`. 

The high-level idea is that by hooking these functions, we can automate the process of checking and updating the call stack as well as the return address of the memory allocation. By inspecting the traces, we can see which chunk is allocated by `foo()` in some C files, and we can investigate further, say by checking the adjacent chunks, to find suitable targets for heap exploitation.

It also supports adding custom breakpoints in between if the user is interested in an intermediate heap layout. 

The command itself is not very verbose and you will need to use `heaplens-dump` to print the results.

```
heaplens -h
usage: [-h] [-b BREAKPOINT] [-v]

Collect heap info from memory (de)allocation functions.

optional arguments:
  -h, --help            show this help message and exit
  -b BREAKPOINT, --breakpoint BREAKPOINT
                        stop the executions here (execute br {breakpoint} in gdb) (default: None)
  -v, --verbose         increase output verbosity (default: False)
```

Example output:

```
gef➤  file sudoedit
gef➤  heaplens -b set_cmnd -- -s '\\' $(python3 -c 'print("A"*65535)')
----------------------------
Initializing Heaplens
----------------------------
Temporary breakpoint 1 at 0x5840: file ../../src/src/sudo.c, line 136.
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
usage: sudoedit [-AknS] [-C num] [-g group] [-h host] [-p prompt] [-T timeout] [-u user] file ...
[Inferior 1 (process 82934) exited with code 01]
Setting breakpoint at set_cmnd...
Function "set_cmnd" not defined.
Breakpoint 2 (set_cmnd) pending.
Hooking free function...
Breakpoint 3 at 0x7f25cc163700: free. (2 locations)
Hooking malloc function...
Breakpoint 4 at 0x7f25cc163110: malloc. (2 locations)
Hooking realloc function...
Breakpoint 5 at 0x7f25cc163eb0: realloc. (2 locations)
Hooking calloc function...
Breakpoint 6 at 0x7f25cc164b40: calloc. (2 locations)
Running -s '\' $(python3 -c 'print("A"*65535)')...
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 2, set_cmnd () at ../../../src/plugins/sudoers/sudoers.c:804
804	../../../src/plugins/sudoers/sudoers.c: No such file or directory.
Removing breakpoints from mem_bkps...
```

### `heaplens-dump`

Dumps Heaplens logs. We provide options to write the results to a file, output using the JSON format, and sort the chunks by their addresses. In the dump, each chunk would have its address, size, backtrace and related memory allocation function recorded in a more readable way. 

```
heaplens-dump -h
usage: [-h] [-o OUTPUT] [--json] [-s]

Dump Heaplens logs. Writes to stdout by default.

optional arguments:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        write to file at path {output} (default: None)
  --json                dump in json (default: False)
  -s, --sort            sort the chunks by their addresses (default: False)
```

Example output:

```
gef➤  heaplens-dump
----------------------------
Dumping...
----------------------------

...

[malloc] Chunk 3 @ 0x55f3908ed2a0 | size 0xc
Trace:
#0  __GI___strdup (s=0x7fff6fb3b8dc "en_US.UTF-8") at strdup.c:44
#1  0x00007f285df363c5 in _nl_load_locale_from_archive (category=category@entry=0xc, namep=namep@entry=0x7fff6fb29f50) at loadarchive.c:464
#2  0x00007f285df351fe in _nl_find_locale (locale_path=0x0, locale_path_len=0x0, category=category@entry=0xc, name=name@entry=0x7fff6fb29f50) at findlocale.c:152
#3  0x00007f285df34925 in __GI_setlocale (locale=<optimized out>, category=<optimized out>) at setlocale.c:337
#4  __GI_setlocale (category=<optimized out>, locale=<optimized out>) at setlocale.c:217
#5  0x000055f3901d5965 in main (argc=0x4, argv=0x7fff6fb2a298, envp=0x7fff6fb2a2c0) at ../../src/src/sudo.c:1430

...

Dump complete.
```

### `heaplens-chunks`
Outputs a slightly modified version of `heap chunks` from `gef`.

This extends GEF’s `heap chunks` (which shows chunks’ addresses,  flags, sizes and metadata) by integrating information about free chunks from `heap bins` (which lists formerly allocated and freed chunks from glibc bins). GEF provides features that help heap inspection like the two we mentioned, but it is tedious to combine the two. On a high level, this command collects addresses of free chunks from the latter, and labels them in the former’s result.

```
heaplens-chunks -h
usage: [-h] [--nocolor]

A modified `heap chunks` with info about free chunks.

optional arguments:
  -h, --help  show this help message and exit
  --nocolor   disable ANSI color codes
```

Example output:

```
gef➤  heaplens-chunks
Showing current heap info with freed chunks:

...

Chunk(addr=0x55dd7f91ddb0, size=0xed0, flags=PREV_INUSE)  ←  free chunk
    [0x000055dd7f91ddb0     e0 fb ba e1 f8 7f 00 00 e0 fb ba e1 f8 7f 00 00    ...............]
Chunk(addr=0x55dd7f91ec80, size=0x50, flags=! PREV_INUSE)
    [0x000055dd7f91ec80     2f 75 73 72 2f 6c 6f 63 61 6c 2f 73 62 69 6e 3a    /usr/local/sbin]
Chunk(addr=0x55dd7f91ecd0, size=0x4010, flags=PREV_INUSE)  ←  free chunk
    [0x000055dd7f91ecd0     f0 02 bb e1 f8 7f 00 00 f0 02 bb e1 f8 7f 00 00    ...............]
Chunk(addr=0x55dd7f922ce0, size=0x50, flags=! PREV_INUSE)
    [0x000055dd7f922ce0     90 02 91 7f dd 55 00 00 00 00 00 00 00 00 00 00    .....U.........]
Chunk(addr=0x55dd7f922d30, size=0x2da0, flags=PREV_INUSE)  ←  free chunk
    [0x000055dd7f922d30     d0 02 bb e1 f8 7f 00 00 d0 02 bb e1 f8 7f 00 00    ...............]
Chunk(addr=0x55dd7f925ad0, size=0x110, flags=! PREV_INUSE)  ←  free chunk
    [0x000055dd7f925ad0     00 00 00 00 00 00 00 00 10 f0 90 7f dd 55 00 00    .............U.]
Chunk(addr=0x55dd7f925be0, size=0x30, flags=PREV_INUSE)
    [0x000055dd7f925be0     00 00 00 00 00 00 00 00 d2 78 b7 7e dd 55 00 00    .........x.~.U.]
Chunk(addr=0x55dd7f925c10, size=0x20, flags=PREV_INUSE)
    [0x000055dd7f925c10     65 6e 5f 55 53 2e 55 54 46 2d 38 00 00 00 00 00    en_US.UTF-8....]
Chunk(addr=0x55dd7f925c30, size=0xa3e0, flags=PREV_INUSE)  ←  top chunk
```

### `heaplens-clear`
Clear all internal logs / data collected and used by `heaplens`.

```
heaplens-clear -h
usage: [-h] [-v]

Clear Heaplens logs.

optional arguments:
  -h, --help     show this help message and exit
  -v, --verbose  increase output verbosity
```

### `heaplens-list-env`
List environment variables that are stored and freed in the heap. It is particularly useful when you want to perform heap grooming as these variables might affect the heap layout.

```
heaplens-list-env -h
usage: [-h] [-v] [--prefix PREFIX] [--suffix SUFFIX] [-b BREAKPOINT] [-s SKIP]

List environment variables that might affect the heap layout.

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         increase output verbosity
  --prefix PREFIX       environment variable value prefix
  --suffix SUFFIX       environment variable value suffix
  -b BREAKPOINT, --breakpoint BREAKPOINT
                        stop the executions here (execute br {breakpoint} in gdb)
  -s SKIP, --skip SKIP  skip this environment variable
```

Example output:

```
gef➤  file sudoedit
Reading symbols from sudoedit...
gef➤  heaplens-list-env -s LC_ALL -b set_cmnd --prefix C.UTF-8@ -- -s \\ AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

...

1st execution. Found following environment variable:
['LOCPATH', 'LC_ALL', 'LC_IDENTIFICATION', 'LANG', 'LC_MEASUREMENT', 'LC_TELEPHONE', 'LC_ADDRESS', 'LC_NAME', 'LC_PAPER', 'LC_MESSAGES', 'LC_MONETARY', 'LC_COLLATE', 'LC_TIME', 'LC_NUMERIC', 'LC_CTYPE', 'TZ', 'SHELL', 'LANGUAGE']
  
...

2nd execution. Possible environment variables for heap grooming:
['LC_IDENTIFICATION', 'LC_COLLATE', 'TZ', 'LC_TIME', 'LANGUAGE', 'LC_NAME', 'LOCPATH', 'LC_MESSAGES', 'LC_NUMERIC', 'LC_ADDRESS', 'LC_TELEPHONE', 'LC_MONETARY', 'LC_MEASUREMENT', 'LC_CTYPE', 'LC_PAPER']
```

## 🛠 Test Cases

To bulid the test case scripts (built in the VM)

```bash
$ cd tests
$ make all
```

### Dump `tests/heap-dump` heap layout

```
gef➤  file tests/heap-dump
gef➤  heaplens -b breakme
gef➤  heaplens-dump
```

### Dump `sudoedit` heap layout to output.txt

```
gef➤  file sudoedit
gef➤  heaplens -b set_cmnd -- -s \\ AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
gef➤  heaplens-dump -o output.txt
```

output.txt

```
[heap dump]
```

### List environment variables for heap grooming in `tests/env-in-heap`

```
gef➤  file tests/env-in-heap
gef➤  heaplens-list-env

...

----------------------------
2nd execution. Possible environment variables for heap grooming:
['ENV_IN_HEAP']
----------------------------
```

### List environment variables for heap grooming in `sudoedit`

```
gef➤  file sudoedit
gef➤  heaplens-list-env -s LC_ALL -b set_cmnd --prefix C.UTF-8@ -- -s \\ AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

...

----------------------------
1st execution. Found following environment variable:
['LOCPATH', 'LC_ALL', 'LC_IDENTIFICATION', 'LANG', 'LC_MEASUREMENT', 'LC_TELEPHONE', 'LC_ADDRESS', 'LC_NAME', 'LC_PAPER', 'LC_MESSAGES', 'LC_MONETARY', 'LC_COLLATE', 'LC_TIME', 'LC_NUMERIC', 'LC_CTYPE', 'TZ', 'SHELL', 'LANGUAGE']    
----------------------------

...

----------------------------
2nd execution. Possible environment variables for heap grooming:
['LC_CTYPE', 'LC_PAPER', 'LC_MONETARY', 'TZ', 'LC_ADDRESS', 'LC_MEASUREMENT', 'LC_IDENTIFICATION', 'LC_COLLATE', 'LC_NUMERIC', 'LC_MESSAGES', 'LC_TIME', 'LANGUAGE', 'LC_NAME', 'LOCPATH', 'LC_TELEPHONE']
---------------------------- 
```

## 🚨 Known Issues

Please refer to the [Issues](https://github.com/ypl6/heaplens/issues) page for more details.
