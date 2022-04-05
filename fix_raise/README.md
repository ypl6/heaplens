# Fix 
__GI_raise (sig=sig@entry=0x6) at ../sysdeps/unix/sysv/linux/raise.c:50


The fix will be included in the VM when we submit

```
#replace content of `/etc/apt/sources.list` with `source.list` in this repo
$ sudo cp -f source.list /etc/apt/sources.list`

$ sudo apt update

$ sudo mkdir /opt/src

$ cd /opt/src

$ sudo apt source libc6

$ find $PWD -maxdepth 1 -type d -name 'glibc*'

# should return `/opt/src/glibc-2.31`

$ sudo gdb

gef➤  set substitute-path /build/glibc-sMfBJT/glibc-2.31 /opt/src/glibc-2.31

# restart gdb
```

