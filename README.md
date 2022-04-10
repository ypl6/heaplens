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

Here is a list of things (and versions) we used to test the exploit. **They should already be installed in the VM.** In case anything is missing, follow the instruction below.

### Dependencies

- Ubuntu 20.04.4 (64-bit)
- `python` 3.8.10
- `glibc` 2.34
- `gdb` 9.2
- `gef` 2022.01
  - If `gef` is not enabled under root, take a look at `/root/.gdbinit`
  - If the file is empty, just copy what you have in `~/.gdbinit`

### `sudo` Dependencies (for running heaplens on `sudo`)

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

It is suggested to run `gdb` under root privileges:

```shell
$ sudo su
# gdb
```

Help messages are provided for all commands. You can access them via `<command> -h` in GDB.

### `heaplens`
::TODO::


```shell
heaplens -h
usage: [-h] [-b BREAKPOINT] [-v]

Collect heap info from memory (de)allocation functions.

optional arguments:
  -h, --help            show this help message and exit
  -b BREAKPOINT, --breakpoint BREAKPOINT
                        stop the executions here (execute br {breakpoint} in gdb) (default: None)
  -v, --verbose         increase output verbosity (default: False)
```

### `heaplens-dump`


```shell
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

### `heaplens-list-env`
List environment variables that are stored and freed in the heap. It is particularly useful when you want to perform heap grooming as these variables might affect the heap layout.

```shell
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

### `heaplens-chunks`
Outputs a slightly modified version of `heap chunks` from `gef`, that integrates info from `heap bins` about free chunks.

```shell
heaplens-chunks -h
usage: [-h] [--nocolor]

A modified `heap chunks` with info about free chunks.

optional arguments:
  -h, --help  show this help message and exit
  --nocolor   disable ANSI color codes
```

### `heaplens-clear`
Clear all internal logs / data collected and used by `heaplens`.

```shell
heaplens-clear -h
usage: [-h] [-v]

Clear Heaplens logs.

optional arguments:
  -h, --help     show this help message and exit
  -v, --verbose  increase output verbosity
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
gef➤  heaplens-dumps
```

### Dump `sudoedit` heap layout to output.txt

```
gef➤  file sudoedit
gef➤  heaplens -b set_cmnd -- -s \\ AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
gef➤  heaplens-dumps output.txt
```

output.txt

```
[heap dump]
```


### List envirnoment variables for heap grooming in `tests/env-in-heap`

```
gef➤  file tests/env-in-heap
gef➤  heaplens-list-env

...

----------------------------------------------------------------------------------------------------
2nd execution. Possible environment variables for heap grooming:
['ENV_IN_HEAP']
----------------------------------------------------------------------------------------------------
```

### List envirnoment variables for heap grooming in `sudoedit`

```
gef➤  file sudoedit
gef➤  heaplens-list-env -s LC_ALL -b set_cmnd --prefix C.UTF-8@ -- -s \\ AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

...

----------------------------------------------------------------------------------------------------
1st execution. Found following environment variable:
['LOCPATH', 'LC_ALL', 'LC_IDENTIFICATION', 'LANG', 'LC_MEASUREMENT', 'LC_TELEPHONE', 'LC_ADDRESS', 'LC_NAME', 'LC_PAPER', 'LC_MESSAGES', 'LC_MONETARY', 'LC_COLLATE', 'LC_TIME', 'LC_NUMERIC', 'LC_CTYPE', 'TZ', 'SHELL', 'LANGUAGE']    
----------------------------------------------------------------------------------------------------

...

----------------------------------------------------------------------------------------------------
2nd execution. Possible environment variables for heap grooming:
['LC_CTYPE', 'LC_PAPER', 'LC_MONETARY', 'TZ', 'LC_ADDRESS', 'LC_MEASUREMENT', 'LC_IDENTIFICATION', 'LC_COLLATE', 'LC_NUMERIC', 'LC_MESSAGES', 'LC_TIME', 'LANGUAGE', 'LC_NAME', 'LOCPATH', 'LC_TELEPHONE']
---------------------------------------------------------------------------------------------------- 
```

## 🚨 Known Issues

Please refer to the [Issues](https://github.com/ypl6/heaplens/issues) page for more details.