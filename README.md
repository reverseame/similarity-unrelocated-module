# Similarity Unrelocated Module - SUM

`SUM` undoes modifications done by relocation process on modules (namely, processes of .exe and .dll files). Then it yields a Similarity Digest for each memory page of unrelocated modules.

This tool implements two de-relocation methods: 
- **Guided De-relocation** uses the `.reloc` section, when it is given by the user, to identify the bytes affected by relocation and then de-relocate them.
- **Linear Sweep De-relocation** first identifies the fields in the PE header and well-known patterns of structures. Then it uses a linear sweep disassembler to find instructions affected by relocation and de-relocate all affected bytes.

A Similarity Digest Algorithm (also known as approximate matching algorithm) identifies similarities between digital artifacts. In particular, the algorithm outputs a digest that can then be compared with other digests, obtaining a similarity score (which normally ranges from 0 to 100).

At the moment of this writing, the algorithms included in this plugin are `ssdeep`, `SDhash`, and `TLSH`
`dfcldd` has been discarded because it is a weak algorithm

## Installation

You can install all dependencies with [installdeps.sh](installdeps.sh):

- System: `ssdeep libfuzzy-dev`, `git`, `libffi-dev`, `libssl1.0.0`, `build-essential`
- Python 2.7: `pycrypto`, `distorm3`, `ssdeep`, `fuzzyhashlib`, `capstone`

## Usage

```
SUM (Similarity Unrelocated Module)

Undoes modifications done by relocation process on modules in memory dumps. Then it yields a Similarity Digest for each page of unrelocated modules.

usage: sum.py [-h] [--base-address BASE_ADDRESS] [--reloc RELOC]
              [--virtual-layout] [--section SECTION]
              [--algorithms {ssdeep,sdhash,tlsh}] [--architecture {32,64}]
              [--compare-hash COMPARE_HASH] [--compare-file COMPARE_FILE]
              [--human-readable] [--time] [--dump-dir DUMP_DIR]
              [--list-sections] [--json] [--output]
              [--derelocation {best,guide,linear,raw}]
              [--log-memory-pages LOG_MEMORY_PAGES]
              file

positional arguments:
  file                  File that contains the module

optional arguments:
  -h, --help            show this help message and exit
  --base-address BASE_ADDRESS, -b BASE_ADDRESS
                        Base address where was loaded the module
  --reloc RELOC, -r RELOC
                        A file with the .reloc section of the module
  --virtual-layout, -v  Module with virtual layout structure
  --section SECTION, -s SECTION
                        PE section to hash (e.g. -s PE,.data,header,.rsrc)
  --algorithms {ssdeep,sdhash,tlsh}, -A {ssdeep,sdhash,tlsh}
                        Hash algorithms (e.g. -a ssdeep -a sdhash -a tlsh)
  --architecture {32,64}, -a {32,64}
                        Code architecture
  --compare-hash COMPARE_HASH, -c COMPARE_HASH
                        Compare to given hash
  --compare-file COMPARE_FILE, -C COMPARE_FILE
                        Compare to hashes' file
  --time, -t            Print computation time
  --dump-dir DUMP_DIR, -D DUMP_DIR
                        Directory in which to dump files
  --list-sections       Show PE sections
  --json                Print JSON output
  --output, -o          ToDo
  --derelocation {best,guide,linear,raw}, -d {best,guide,linear,raw}
                        De-relocate modules pre-processing method.
  --log-memory-pages LOG_MEMORY_PAGES
                        Log pages which are in memory to FILE

Note:
    - Hashes' file given with -C must contain one hash per line.
    - Param -c can be given multiple times (e.g. -c <hash1> -c <hash2>)"""

Constructor:
    SUM(self, data, options=None, algorithms=['tlsh'], base_address=None, compare_file=None, compare_hash=None, derelocation='best', dump_dir=None, file=None, json=False, list_sections=False, log_memory_pages=None, reloc=None, section='PE', strings=False, time=False, virtual_layout=False, architecture=None)

List of viable algorithms:
    SUM.list_algorithms()
        Return a list of viable algorithms

Execution:
    SUM.calculation()
        Return a generator of dictionaries

Json output dictionary:

    valid_pages: boolean vector with True for the resident pages (not all zeros)
    num_valid_pages: Amount of valid pages
    base_address: Base address of the module from the PE or the input
    size: Size of section
    derelocation_time: Time of the derelocation process
    num_pages: Total amount of pages
    algorithm: Digesting algorithm
    section: Section that is digested. When there are not PE header, it is impossible identified the sections and all the input is considered as a unique section 'dump'
    pe_time: Time of parsing the PE structure
    digest: Vector of digest, one per page
    mod_name: Name of the module obtained form the PE structure
    preprocess: Preprocessing method
    digesting_time: Time to calculate the digest of each page
    virtual_address: Virtual address of the section. If  base_address is 0, then virtual_address is the offset.

    similarity: Similarity score between compared_digest and sub_digest
    compared_digest: Digest provided by the user
    sub_digest: Page digest considered in the comparison
    compared_page: Index of the page digest
    comparison_time: Time of comparison


```
Tool examples:
```
python sum.py -v -s all -A sdhash -A tlsh out.dmp -D outFolder2 
Name            Section Virtual Address Size    Pre-processing  Algorithm       Digest
----            ------- --------------- ----    --------------  ---------       ------
KERNEL32.dll    .text   0x7ff927071000  0x7e000 Linear          SDHash          sdbf:03:0::4096:sha1...AAAAwAAAAAQAAAAAAg==
KERNEL32.dll    .text   0x7ff927071000  0x7e000 Linear          TLSH            4681F987E599D1A4EA69...A8E6BF0886BE5C97CE00
KERNEL32.dll    .rdata  0x7ff9270ef000  0x33000 Linear          SDHash          sdbf:03:0::4096:sha1...TAQAAAAAQCAAQBSMAQ==
KERNEL32.dll    .rdata  0x7ff9270ef000  0x33000 Linear          TLSH            E281D0E2F3503D01D062...9877C10E0DBA4B7733F6
KERNEL32.dll    .data   0x7ff927122000  0x2000  Linear          SDHash          sdbf:03:0::4096:sha1...SAEAAAABAAAAAIAA==;*
KERNEL32.dll    .data   0x7ff927122000  0x2000  Linear          TLSH            8E81AF8A73E25D01C586...B52A9FE525C1B84945;*
...
KERNEL32.dll    header  0x7ff927070000  0x1000  Linear          SDHash          sdbf:03:0::4096:sha1...AAAAAAAAAAAAAAAAAA==
KERNEL32.dll    header  0x7ff927070000  0x1000  Linear          TLSH            1F81C06D97CDFCF2C77C...8024246ABB2843C41B09

python sum.py -v -s all -A ssdeep -A sdhash -A tlsh -D outFolder -r ntdll.reloc ntdll.dll 
Name            Section Virtual Address Size    Pre-processing  Algorithm       Digest
----            ------- --------------- ----    --------------  ---------       ------
ntdll.dll       .text   0x77671000      0xd5000 Guide           SSDeep          96:DbYegaJ6kL++yYUTx...;*;*;*;*;*;*;*;*;*;*
ntdll.dll       .text   0x77671000      0xd5000 Guide           SDHash          sdbf:03:0::4096:sha1...;*;*;*;*;*;*;*;*;*;*
ntdll.dll       .text   0x77671000      0xd5000 Guide           TLSH            D081F921978780A06CD9...;*;*;*;*;*;*;*;*;*;*
...
ntdll.dll       .data   0x77747000      0x9000  Guide           SSDeep          12:MeDzb1vSYauCI7thh...t:pducncbwRSkCN6;*;*
ntdll.dll       .data   0x77747000      0x9000  Guide           SDHash          sdbf:03:0::4096:sha1...AQCgAAAAIAAEAA==;*;*
ntdll.dll       .data   0x77747000      0x9000  Guide           TLSH            0C81D803FB42E0B3D740...2E577824E6106F8E;*;*
...
ntdll.dll       header  0x77670000      0x1000  Guide           SSDeep          12:ev1GSGAqLM+dNlslW...ev1GSnqL3lsy31MKLHBS
ntdll.dll       header  0x77670000      0x1000  Guide           SDHash          sdbf:03:0::4096:sha1...AAABAAAAAAAAAAAACA==
ntdll.dll       header  0x77670000      0x1000  Guide           TLSH            CA812B2FF75F6CF1EC28...E9516A74115585596D0C

```


## License

Licensed under the [GNU GPLv3](LICENSE) license.
