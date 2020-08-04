import os
import re
import json
import time
import hashlib

import pefile
import volatility.obj as obj
import volatility.debug as debug
import volatility.utils as utils
import volatility.win32.tasks as tasks
import volatility.constants as constants
import volatility.exceptions as exceptions
import volatility.win32.modules as modules
from volatility.plugins.common import AbstractWindowsCommand
import volatility.conf as conf

from pememory import PeMemory, machine_types
from peobject import PEObject
from dllobject import DLLObject
from pe_section import PESection
from driverobject import DriverObject
from compareobject import CompareObject
from derelocation import  acquire_sys_file_handlers, get_reloc_section, guided_derelocation, linear_sweep_derelocation
from hashengine import HashEngine, InvalidAlgorithm

PE_HEADERS = ['dos_header', 'nt_headers', 'file_header', 'optional_header', 'header']

MODE_32 = '32bit'
MODE_64 = '64bit'
PAGE_SIZE = 4096

class sum(AbstractWindowsCommand):
    """SUM (Similarity Unrelocated Module)

        Undoes modifications done by relocation process on modules in memory dumps. Then it yields a Similarity Digest for each page of unrelocated modules.

        Options:
          -p: Process PID(s). Will hash given processes PIDs.
                (-P 252 | -P 252,452,2852)

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
          - Params -c and -C can be given multiple times (E.g. vol.py (...) -c <hash1> -c <hash2>)"""

    def __init__(self, config, *args, **kwargs):
        AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        self._config.add_option('PID', short_option='p', help='Process ID', action='store',type='str')
        self._config.add_option('NAME', short_option='n', help='Expression containing process name', action='store', type='str')
        self._config.add_option('MODULE-NAME', short_option='r', help='Modules matching MODULE-NAME', action='store', type='str')
        self._config.add_option('ALGORITHM', short_option='A', default='ssdeep', help='Hash algorithm', action='store', type='str')
        self._config.add_option('SECTION', short_option='S', help='PE section to hash', action='store', type='str')
        self._config.add_option('COMPARE-HASH', short_option='c', help='Compare to given hash', action='append', type='str')
        self._config.add_option('COMPARE-FILE', short_option='C', help='Compare to hashes\' file', action='append', type='str')
        self._config.add_option('HUMAN-READABLE', short_option='H', help='Show human readable values', action='store_true')
        self._config.add_option('TIME', short_option='t', help='Print computation time', action='store_true')
        self._config.add_option('STRINGS', short_option='s', help='Hash strings contained in binary data', action='store_true')
        self._config.add_option('DUMP-DIR', short_option='D', help='Directory in which to dump files', action='store', type='str')
        self._config.add_option('LIST-SECTIONS', help='Show PE sections', action='store_true')
        self._config.add_option('JSON', help='Print JSON output', action='store_true')
        self._config.add_option('GUIDED-DERELOCATION', help='De-relocate modules guided by .reloc section when it is found', action='store_true')
        self._config.add_option('LINEAR-SWEEP-DERELOCATION', help='De-relocate modules by sweep linear disassembling, recognizing table patterns and de-relocating IAT', action='store_true')
        self._config.add_option('DERELOCATION', short_option='u', help='De-relocate modules using guided pre-processing when it is posible, else use linear sweep de-relocation', action='store_true')
        self._config.add_option('LOG-MEMORY-PAGES', help='Log pages which are in memory to FILE', action='store', type='str')
        self.reloc_list = {}
        self.files_opened_in_system = {}

    def calculate(self):
        """Main volatility plugin function"""
        try:
            self.addr_space = utils.load_as(self._config)

            self.hash_engines = self.get_hash_engines()

            pids = self.get_processes()
            #if not pids:
            #    debug.error('{0}: Could not find any process with those options'.format(self.get_plugin_name()))

            # Show how many processes are running except for System (pid 4)
            #print(json.dumps({'n_processes': len([x for x in pids if int(x) != 4])}))

            # Get hashes to compare to
            hashes = []
            if self._config.COMPARE_HASH:
                hashes = self._config.COMPARE_HASH[0].split(',')
            elif self._config.COMPARE_FILE:
                hashes = self.read_hash_files(self._config.COMPARE_FILE[0].split(','))

            self._config.DUMP_DIR = self.prepare_working_dir()

            for dump in self.dll_dump(pids):
                if hashes:
                    for item in self.compare_hash(dump, hashes):
                        yield item
                else:
                    yield dump

        except KeyboardInterrupt:
            debug.error('KeyboardInterrupt')

    def get_hash_engines(self):
        ret = []

        algorithms = self._config.ALGORITHM.split(',')
        for alg in algorithms:
            try:
                ret += [HashEngine(alg, self._config.STRINGS)]
            except InvalidAlgorithm, reason:
                debug.error('{0}: \'{1}\': {2}'.format(self.get_plugin_name(), alg, reason))
        return ret

    def get_processes(self):
        """
        Return all processes id by either name, expresion or pids

        @returns a list containing all desired pids
        """

        pids = []

        if self._config.NAME:
            # Prepare all processes names as regular expresions
            names = '{0}'.format(self._config.NAME).split(',')
            pids = self.get_proc_by_name(names)
        else:
            pids = self.get_proc_by_pid(self._config.PID)

        return pids

    def get_proc_by_name(self, names):
        """
        Search all processes by process name

        @para names: a list with all names to search

        @returns a list of pids
        """
        ret = []

        for proc in tasks.pslist(self.addr_space):
            for name in names:
                mod = self.get_exe_module(proc)
                if mod:
                    if re.match(name+'$', str(mod.BaseDllName), flags=re.IGNORECASE):
                        ret += [proc.UniqueProcessId]
        return ret

    def get_exe_module(self, task):
        """
        Return main exe module

        @para task: process

        @returns exe module
        """
        for mod in task.get_load_modules():
            return mod

        return ''

    def get_proc_by_pid(self, pids):
        """
        Search all processes which its pid matches

        @para names: a list with all pids to search

        @returns a list of pids
        """

        ret = []

        if pids:
            pids = pids.split(',')
            for proc in tasks.pslist(self.addr_space):
                if not proc.ExitTime:
                    # Check if those pids exist in memory dump file
                    if str(proc.UniqueProcessId) in pids:
                        ret += [proc.UniqueProcessId]
        else:
            # Return all pids if none is provided
            for proc in tasks.pslist(self.addr_space):
                # Only return those which are currently running
                if not proc.ExitTime:
                    ret += [proc.UniqueProcessId]

        return ret

    def get_pe_sections(self, pe):
        """
        Return all section names from pe, deleting final zero bytes
        
        @param pe: PE structure 

        @returns a list containing all section names
        """
        ret = []
        for sec in pe.sections:
            ret += [sec.Name.translate(None, '\x00')]

        return ret

    def process_section(self, task, section_expr, pe):
        """
        Generate one dump file for every section

        @param task: process
        @param section: sections to dump
        @param dump_path: PE dump path to process

        @returns a list of dicts containing each section and dump path associated
        """
        if not section_expr:
            return [pe.sections[-1]]

        ret = []


        section_expr = section_expr.split(',')
        if 'all' in section_expr:
            return pe.sections
        else:
            for section in pe.sections:
                for expresion in section_expr:
                    if re.search(expresion, section.Name):
                        ret.append(section)
                        break
        return ret

    def process_pe_header(self, pe, header):
        """
        Retrieve desired PE header

        @param pe: PE object
        @param header: PE header to search

        @return a dict containing header and dump file associated
        """

        try:
            if header == 'header':
                data = pe.__getattribute__(header)
            else:
                # Try to get specified PE header
                data = pe.__getattribute__(header.upper()).__pack__()
            return {'section': header, 'data': data, 'offset': 0, 'size': len(data)}
        except AttributeError:
            debug.error(
                '{0}: \'{1}\': Bad header option (DOS_HEADER, NT_HEADERS, FILE_HEADER, OPTIONAL_HEADER or header)'.format(
                    self.get_plugin_name(), header.split(':')[-1]))

    def process_pe_section(self, pe, section):
        """
        Retrieve all PE section

        @param dump_path: PE dump file
        @param pe: PE object
        @param header: PE section to search

        @return a dict containing section and dump file associated
        """

        search_header = re.search(r'^(.+)(:header)$', section)

        # Iterate through all existing PE sections
        for index, sec in enumerate(pe.sections):
            if search_header and search_header.group(1) == sec.Name.translate(None, '\x00'):
                # Get section header
                return {'section': section, 'data': sec.__pack__(), 'offset': 0, 'size': len(sec.__pack__())}

            elif section == sec.Name.translate(None, '\x00'):
                # Get section data
                return {'section': sec.Name, 'data': sec.data, 'offset': sec.VirtualAddress,
                        'size': sec.SizeOfRawData}

        header = search_header.group(1) if search_header else section
        raise pefile.PEFormatError('Section {0} not found'.format(header))

    def dll_dump(self, pids):
        """
        Generate dump files containing all modules loaded by a process

        @param pids: pid list to dump

        @returns a list of DLLObject sorted by (pid, mod.BaseAddress)
        """
        if self._config.MODULE_NAME:
            dlls_expression = '{0}$'.format(self._config.MODULE_NAME.replace(',', '$|'))

        else:
            dlls_expression = None

        if self._config.DERELOCATION or self._config.GUIDED_DERELOCATION:
            # acquiring all dlls and exes that were opened in system
            acquire_sys_file_handlers(self, conf)
        
        if self._config.LOG_MEMORY_PAGES:
            if not self._config.SECTION or self._config.SECTION=='all' or 'PE' in self._config.SECTION:
                logfile = open(self._config.LOG_MEMORY_PAGES, "w")
            else:
                debug.warning('Warning: PE is not being dumped')

        for task in tasks.pslist(self.addr_space):
            if task.UniqueProcessId in pids:
                task_space = task.get_process_address_space()
                mods = dict((mod.DllBase.v(), mod) for mod in task.get_load_modules())
                for mod in mods.values():
                    mod_base = mod.DllBase.v()
                    mod_end = mod_base + mod.SizeOfImage
                    if task_space.is_valid_address(mod_base):
                        mod_name = mod.BaseDllName
                        if dlls_expression:
                            if not re.match(dlls_expression, str(mod_name), flags=re.IGNORECASE):
                                continue
                        valid_pages = [task_space.vtop(mod.DllBase+i) for i in range(0, mod.SizeOfImage, PAGE_SIZE)]
                        start = time.time()
                        pe = PeMemory(task_space.zread(mod.DllBase, mod.SizeOfImage), mod.DllBase, valid_pages)
                        end = time.time()

                        pe_memory_time = end - start

                        pe.__modul_name__ = mod_name
                        if self._config.LIST_SECTIONS:
                            yield PESection(mod_name, self.get_pe_sections(pe), task.UniqueProcessId, mod_base)
                        else:
                            reloc = None
                            pre_processing_time = None
                            if self._config.DERELOCATION or self._config.GUIDED_DERELOCATION:
                                # Retrieving reloc for module for text section
                                reloc = get_reloc_section(self, mod)
                                if reloc:
                                    start = time.time()
                                    guided_derelocation(pe, reloc)
                                    end = time.time()

                                    pre_processing_time = end - start
                                else:
                                    debug.warning('Warning: {0}\'s reloc section cannot be found.'.format(mod_name))
                                    if self._config.GUIDED_DERELOCATION:
                                        continue

                            if (self._config.DERELOCATION and not reloc) or self._config.LINEAR_SWEEP_DERELOCATION:
                                start = time.time()
                                linear_sweep_derelocation(pe)
                                end = time.time()

                                pre_processing_time = end - start

                            # Generate one dump Object for every section/header specified

                            # Set the list of sections that match with -S expression
                            sections = self.process_section(task, self._config.SECTION, pe)
                            for sec in sections:
                                for engine in self.hash_engines:
                                    vinfo = obj.Object("_IMAGE_DOS_HEADER", mod.DllBase, task_space).get_version_info()
                                    create_time = str(task.CreateTime) if self._config.HUMAN_READABLE else int(
                                        task.CreateTime)
                                    yield DLLObject(task, sec.data, engine, mod_base, mod_end, mod_name,
                                                    sec.Name, create_time,
                                                    vinfo.FileInfo.file_version() if vinfo else '',
                                                    vinfo.FileInfo.product_version() if vinfo else '',
                                                    mod.FullDllName, time=self._config.TIME and not (
                                                    self._config.COMPARE_HASH or self._config.COMPARE_FILE),
                                                    offset=sec.VirtualAddress, size=sec.real_size, pe_memory_time='{0:.20f}'.format(pe_memory_time), pre_processing_time='{0:.20f}'.format(pre_processing_time) if pre_processing_time else None)
                                    
                                    dump_path = os.path.join(self._config.DUMP_DIR,
                                                                 '{0}-{1}-{2}-{3}-{4:x}.dmp'.format(
                                                                     self.get_exe_module(task).BaseDllName,
                                                                     task.UniqueProcessId, mod_name,
                                                                     re.sub(r'\x00', r'', re.sub(r'\/', r'.', sec.Name)), mod_base))
                                    if self._config.DUMP_DIR:
                                        self.backup_file(dump_path, sec.data)
                                    if self._config.LOG_MEMORY_PAGES and sec.Name == 'PE':
                                        if not self._config.DUMP_DIR:
                                            debug.warning('Warning: Modules are not being dumped to file')
                                        logfile.write('{},{},{},{}:{}\n'.format(self._config.optparse_opts.location[7:], dump_path, hashlib.md5(pe.__data__[0:PAGE_SIZE]).hexdigest(), len(valid_pages), ', '.join([str(i) for i in range(0, len(valid_pages)) if valid_pages[i] ])))
        if 'logfile' in locals():
            logfile.close()

    def compare_hash(self, dump, hash_):
        """Compare hash for every dump Object"""

        for h in hash_:
            yield CompareObject(dump, h, self._config.TIME)

    def read_hash_files(self, paths):
        ret = []

        try:
            for path in paths:
                with open(path) as f:
                    ret += [x.strip() for x in f.readlines()]
        except IOError:
            debug.error('{0}: \'{1}\': Can not open file'.format(self.get_plugin_name(), path))

        return ret

    def backup_file(self, path, data):
        with open(path, 'wb') as f:
            return f.write(data)

    def prepare_working_dir(self):
        if self._config.DUMP_DIR:
            temp_path = os.path.realpath(self._config.DUMP_DIR)
            if not os.path.exists(temp_path):
                os.makedirs(temp_path)
            return temp_path
        else:
            return ''

    def render_text(self, outfd, data):
        first = True
        for item in data:
            if self._config.json:
                outfd.write('{0}\n'.format(item._json()))
            else:
                if first:
                    self.table_header(outfd, item.get_unified_output())
                    first = False
                # Transform list to arguments with * operator
                self.table_row(outfd, *item.get_generator())

    def get_plugin_name(self):
        return os.path.splitext(os.path.basename(__file__))[0]
