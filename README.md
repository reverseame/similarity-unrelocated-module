# Similarity Unrelocated Module - Volatility Plugin

`sum` for Volatility 2.6 undoes modifications done by relocation process on modules (namely, processes of .exe and .dll files) contained in memory dumps. Then it yields a Similarity Digest for each memory page of unrelocated modules.

This plugin implements two de-relocation methods: 
- **Guided De-relocation** uses the `.reloc` section, when it is recoverable from the module dump, to identify the bytes affected by relocation and then de-relocate them.
- **Linear Sweep De-relocation** first identifies the fields in the PE header and well-known patterns of structures. Then it uses a linear sweep disassembler to find instructions affected by relocation and de-relocate all affected bytes.

A Similarity Digest Algorithm (also known as approximate matching algorithm) identifies similarities between digital artifacts. In particular, the algorithm outputs a digest that can then be compared with other digests, obtaining a similarity score (which normally ranges from 0 to 100).

At the moment of this writing, the algorithms included in this plugin are `dcfldd`, `ssdeep`, `SDhash`, and `TLSH`

## Installation

You can install all dependencies with [installdeps.sh](installdeps.sh):

- System: `ssdeep libfuzzy-dev`, `git`, `cmake`, `libffi-dev`, `libssl1.0.0`, `build-essential`
- Python 2.7: `pycrypto`, `distorm3`, `ssdeep`, `fuzzyhashlib`, `capstone`

## Usage

```
SUM (Similarity Unrelocated Module)

Undoes modifications done by relocation process on modules in memory dumps. Then it yields a Similarity Digest for each page of unrelocated modules.

Options:
    -p: Process PID(s). Will hash given processes PIDs.
        (-p 252 | -p 252,452,2852)

    -n REGEX, --name REGEX: Process expression. Will hash processes that contain REGEX.
        (-E svchost | -E winlogon,explorer)
        
    -r REGEX, --module-name REGEX: Module expression. Will hash modules that contain REGEX.
        (-D ntdll | -D kernel,advapi)

    -A: Algorithm to use. Available: ssdeep, sdhash, tlsh, dcfldd. Default: ssdeep
        (-A ssdeep | -A SSDeep | -A SSDEEP,sdHash,TLSH,dcfldd)

    -S: Section to hash
        PE section (-S .text | -S .data,.rsrc)
        PE header (-S header | -S .data,header,.rsrc)
        All PE sections including main executable module (-S all)

    -s: Hash ASCII strings instead of binary data.

    -c: Compare given hash against generated hashes.
        (E.g. -c '3:elHLlltXluBGqMLWvl:6HRlOBVrl')
    -C: Compare given hashes' file against generated hashes.
        (E.g. -C /tmp/hashfile.txt)

    -H: Human readable values (Create Time)
    -t: Show computation time

    -D DIR, --dump-dir=DIR: Temp folder to write all data

    --output-file=<file>: Plugin output will be writen to given file.
    --output=<format>: Output formatting. [text, dot, html, json, sqlite, quick, xlsx]

    --list-sections: Show PE sections

    --json: Json output formatting.

    --guided-derelocation: De-relocate modules guided by .reloc section when it is found

    --linear-sweep-derelocation: De-relocate modules by sweep linear disassembling, recognizing table patterns and de-relocating IAT

    --derelocation: De-relocate modules using guided pre-processing when it is posible, else use linear sweep de-relocation

    --log-memory-pages LOGNAME: Log pages which are in memory to LOGNAME

Note:
    - Hashes' file given with -C must contain one hash per line.
    - Params -c and -C can be given multiple times (E.g. vol.py (...) -c <hash1> -c <hash2>)

```
You need to provide the path to the plugin as [first parameter to Volatility](https://github.com/volatilityfoundation/volatility/wiki/Volatility-Usage#specifying-additional-plugin-directories):

```
vol.py --plugins /path/to/sum  --profile WinProfile --f /path/to/memory.dump sum 
Volatility Foundation Volatility Framework 2.6.1
Process                   Pid  PPid Create Time                  Module Base Module End Module Name                       File Version   Product Version Section            Section Offset Section Size Algorithm Generated Hash                                                                                       Path                                           Num Page Num Valid Page
------------------------- ---- ---- ---------------------------- ----------- ---------- --------------------------------- -------------- --------------- ------------------ -------------- ------------ --------- ---------------------------------------------------------------------------------------------------- ---------------------------------------------- -------- --------------
smss.exe                   216    4 1537396716                    0x482e0000 0x482f3000 smss.exe                                                         PE                            0x0      0x13000 SSDeep    6:idquvVg3F+X32kGjSW8c3ge7+vcjelik+gSX+2C6aAat5GX...2amkKYl9l7zsYcf6Zjw:VCOvB3lL9Ip8RpJlIr7vl7vQ;*;* \SystemRoot\System32\smss.exe                  19       17            
smss.exe                   216    4 1537396716                    0x77620000 0x7775c000 ntdll.dll                                                        PE                            0x0     0x13c000 SSDeep    12:ev1GSGAqLM+dNlslQ+JNlJHElKL//coclzC4oa12O:ev1G...;*;*;*;*;*;*;*;*;*;*;*;*;*;*;*;*;*;*;*;*;*;*;*;* C:\Windows\SYSTEM32\ntdll.dll                  316      112           
csrss.exe                  288  280 1537396719                    0x49950000 0x49955000 csrss.exe                         6.1.7600.16385 6.1.7600.16385  PE                            0x0       0x5000 SSDeep    6:idquvVg3F+X322XJZI3w8ERM9+4tav/2ro/uK4/hGIvBj:e...LF+bT4UBstQIZWWIqV955WwaO0E:PDJvkM/HHEW5s9nWw3;* C:\Windows\system32\csrss.exe                  5        4             
csrss.exe                  288  280 1537396719                    0x77620000 0x7775c000 ntdll.dll                                                        PE                            0x0     0x13c000 SSDeep    12:ev1GSGAqLM+dNlslQ+JNlJHElKL//coclzC4oa12O:ev1G...;*;*;*;*;*;*;*;*;*;*;*;*;*;*;*;*;*;*;*;*;*;*;*;* C:\Windows\SYSTEM32\ntdll.dll                  316      102           

[... redacted ...]
```


## License

Licensed under the [GNU GPLv3](LICENSE) license.
