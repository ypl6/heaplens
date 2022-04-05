# cmpt733-proj-sudo-vuln
CVE-2021-3156

## How to enable the plugin

### Option 1
Start gef
```
gef➤ gef config gef.extra_plugins_dir <path to>/cmpt733-proj-sudo
gef➤ gef save
gef➤ q
```

### Option 2
Add this in `.gdbinit`:
```
source <path to>/heaptrace.py
```


