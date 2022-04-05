# Fix
Error in gdb: `__GI_raise (sig=sig@entry=0x6) at ../sysdeps/unix/sysv/linux/raise.c:50`

The fix will be included in the VM when we submit

```bash
# replace content of `/etc/apt/sources.list` with `source.list` in this repo
$ sudo cp -f source.list /etc/apt/sources.list`

$ sudo apt update
# ... a long wait

$ sudo mkdir /opt/src
$ cd /opt/src

$ sudo apt source libc6
# ... another long wait

$ find $PWD -maxdepth 1 -type d -name 'glibc*'
# should return `/opt/src/glibc-2.31`

$ sudo gdb
gef➤  set substitute-path /build/glibc-sMfBJT/glibc-2.31 /opt/src/glibc-2.31

# restart gdb
```

Expected output from `gdb`:

```
Reading symbols from sudoedit...
gef➤  list-env-in-heap -s '\' AAAAA
Breakpoint 1 at 0x7d10: file ../../src/src/env_hooks.c, line 70.
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[Detaching after fork from child process 49210]
2 files to edit
sudoedit: \ unchanged
sudoedit: AAAAA unchanged
[Inferior 1 (process 49206) exited normally]
----------------------------------------------------------------------------------------------------
1st execution. Found following envirnoment varible:
['LOCPATH', 'LC_ALL', 'LC_IDENTIFICATION', 'LANG', 'LC_MEASUREMENT', 'LC_TELEPHONE', 'LC_ADDRESS', 'LC_NAME', 'LC_PAPER', 'LC_MESSAGES', 'LC_MONETARY', 'LC_COLLATE', 'LC_TIME', 'LC_NUMERIC', 'LC_CTYPE', 'TZ', 'SHELL', 'LANGUAGE', 'SUDO_EDITOR', 'VISUAL', 'EDITOR', 'PATH']
----------------------------------------------------------------------------------------------------
Removing breakpoints
Breakpoint 2 at 0x7f8d01d3a700: free. (2 locations)
/bin/bash: warning: setlocale: LC_ALL: cannot change locale (FuzzMe1)
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
	Found FuzzMe0:/usr/lib/locale/FuzzMe1/LC_IDENTIFICATION
	Found FuzzMe0
	Found /usr/share/zoneinfo/FuzzMe15
	Found /usr/share/zoneinfo/FuzzMe15
	Found FuzzMe18
	Found FuzzMe19
	Found FuzzMe20
[Detaching after fork from child process 49212]
2 files to edit
sudoedit: \ unchanged
sudoedit: AAAAA unchanged
[Inferior 1 (process 49211) exited normally]
----------------------------------------------------------------------------------------------------
2nd execution. Possible envirnoment variables for heap grooming:
['VISUAL', 'EDITOR', 'TZ', 'SUDO_EDITOR', 'LOCPATH', 'LC_ALL']
----------------------------------------------------------------------------------------------------
Removing breakpoints
```