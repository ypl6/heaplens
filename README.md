# 🔎 Heaplens
CMPT733 Cybersecurity Lab II Project
## 📂 Repo Structure

::TODO::

## 📦 Environment

Here is a list of things (and versions) we used to test the exploit. **They should already be installed in the VM.** In case anything is missing, follow the instruction below.

### `sudo`

A binary of the vulnerable `sudo` with debugging enabled is required. A pre-built binary with debug symbols has been installed in the VM.

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
### Other Dependencies

- Ubuntu 20.04.4 (64-bit)
- `python` 3.8.10
- `glibc` 2.34
- `gcc` 9.4.0
- `gdb` 9.2
- `gef` 2022.01
  - If `gef` is not enabled under root, take a look at `/root/.gdbinit`
  - If the file is empty, just copy what you have in `~/.gdbinit`

## 💡 Usage
### How to Enable the Plugin

#### Option 1
Start gef
```
gef➤ gef config gef.extra_plugins_dir <path to>/heaplens
gef➤ gef save
gef➤ q
```

This should update the file `~/.gef.rc` or `/root/.gef.rc` (under root).
#### Option 2
Add this in `.gdbinit`:
```
source <path to>/heaplens/heaplens.py
```

### Using the Plugin

## 🛠 Test Cases

## 🚨 Known Issues

