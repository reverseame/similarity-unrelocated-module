import os
import re
import json
import time
import hashlib
import sys
import argparse
import traceback

try:
    import volatility.debug as logging
except ImportError:
    import logging


from marked_pefile.marked_pefile import MarkedPE
from marked_pefile.pefile import pefile
from derelocation import  acquire_sys_file_handlers, get_reloc_section, guided_derelocation, linear_sweep_derelocation
from hashengine import HashEngine

#PE_HEADERS = ['dos_header', 'nt_headers', 'file_header', 'optional_header', 'header']

MODE_32 = '32bit'
MODE_64 = '64bit'
PAGE_SIZE = 4096

DERELOCATIONS = ['raw', 'guide', 'linear', 'best']

class SUM:
    """SumTool (Similarity Unrelocated Module Tool)

        Undoes modifications done by relocation process on modules in memory dumps. Then it yields a Similarity Digest for each page of unrelocated modules.

        Options:
          -A: Algorithm to use. Available: ssdeep, sdhash, tlsh. Default: tlsh
                (-A ssdeep | -A SSDeep | -A SSDEEP,sdHash,tlsh)

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

          --derelocation (default): De-relocate modules pre-processing method.
                Availabel: raw, guided, linear, best. Default: best
                    raw: Not derelocate modules
                    guide: Guided De-relocation method de-reclocates modules by .reloc section when received
                    linear: Linear Sweep derelocation method de-relocates modules by sweep linear disassembling, recognizing table patterns and de-relocating IAT
                    best: 

          --log-memory-pages LOGNAME: Log pages which are in memory to LOGNAME

        Note:
          - Hashes' file given with -C must contain one hash per line.
          - Params -c and -C can be given multiple times (E.g. vol.py (...) -c <hash1> -c <hash2>)"""

    def __init__(self, data, options=None, algorithms=['tlsh'], base_address=None, compare_file=None, compare_hash=None, derelocation='best', dump_dir=None, file=None, json=False, list_sections=False, log_memory_pages=None, reloc=None, section='PE', strings=False, time=False, virtual_layout=False, architecture=None):
        if options:
            self.config = options
        else:
            self.config= argparse.Namespace()
            self.config.algorithms=algorithms
            self.config.base_address=base_address
            self.config.compare_file=compare_file
            self.config.compare_hash=compare_hash
            self.config.derelocation=derelocation
            self.config.dump_dir=dump_dir
            self.config.file=file
            self.config.json=json
            self.config.list_sections=list_sections
            self.config.log_memory_pages=log_memory_pages
            self.config.reloc=reloc
            self.config.section=section
            self.config.strings=strings
            self.config.time=time
            self.config.virtual_layout=virtual_layout
            self.config.architecture=architecture
        self.data = data

        # Checking input data
        #####################

        # ArgumentParser does not delete the default option in aggregate action -> deleting the first (default) when there are more than one
        # In addition, deleted duplications
        if len(self.config.algorithms) > 1:
            self.config.algorithms = list(set(self.config.algorithms[1:]))

         
        # Base Address acquisition 
        try:
            pe = pefile.PE(data=data, fast_load=True)
            
            self.peFormat = True
            if not self.config.base_address:
                self.config.base_address = pe.OPTIONAL_HEADER.ImageBase
        except pefile.PEFormatError:
            self.peFormat = False
               

        if type(self.config.base_address) == str:
            if self.config.base_address[0:2] == '0x':
                self.config.base_address = int(self.config.base_address, 16)
            else:
                self.config.base_address = int(self.config.base_address)

        if self.config.derelocation == 'guide' and self.config.reloc == None :
            raise RuntimeError('The .reloc section is necessary to execute the Guided Derelocation method.')
        elif self.config.derelocation == 'linear' and self.config.base_address == None:
            raise RuntimeError('The base address where module was loaded is necessary to excute the Linear Sweep Derelocation method.')
        elif  self.config.reloc == None and self.config.base_address == None:
            self.config.derelocation = 'raw'


        if (self.config.compare_hash or self.config.compare_file) > len(self.config.algorithms) > 1:
            raise RuntimeError('Comparisons only accept one algorithm. {}'.format(self.config.algorithms))

    def calculate(self):
        """Main function"""

        self.hash_engines = self.get_hash_engines()

        # Get hashes to compare to
        hashes = []
        if self.config.compare_hash:
            hashes = self.config.compare_hash
        elif self.config.compare_file:
            for hash_file in self.config.compare_file:
                if os.path.isfile(hash_file):
                    hashes += self.read_hash_files(hash_file)
                else:
                  raise RuntimeError('{} is no a file'.format())  
        if self.config.dump_dir:
            self.config.dump_dir = self.prepare_working_dir()

        for digest in self.hashing():
            if hashes and not self.config.list_sections:
                for comparison in self.comparing_hash(digest, hashes):
                    yield comparison
            else:
                yield digest

    def read_hash_files(self, path):
        ret = []

        try:
            with open(path) as f:
                ret += [x.strip() for x in f.readlines()]
        except IOError:
            raise RuntimeError('\'{}\': Can not open file'.format(path))

        return ret

    def get_hash_engines(self):
        """ Return a list of initializes engines """

        ret = []

        for alg in self.config.algorithms:
            ret += [HashEngine(alg)]
            
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

    def process_section(self, section_expr, pe):
        """
        Generate one dump file for every section

        @param section: sections to dump
        @param dump_path: PE dump path to process

        @returns a list of dicts containing each section and dump path associated
        """
        if not self.peFormat:
            return pe.sections

        if not section_expr:
            return [pe.sections[-1]]

        ret = []

        section_expr = section_expr.split(',')
        if 'all' in section_expr:
            return pe.sections[:-1]
        else:
            for section in pe.sections:
                for expresion in section_expr:
                    if re.search(expresion, section.Name):
                        ret.append(section)
                        break
        return ret

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
        raise Error('Section {0} not found'.format(header))

    def valid_pages(self):
        array_valid_pages=[]
        for page in [self.data[i:i+PAGE_SIZE] for i in range(0, len(self.data), PAGE_SIZE)]:
            temp_valid_result =  False
            for byte in page:
                if ord(byte) != 0:
                    temp_valid_result = True
                    break
            array_valid_pages.append(temp_valid_result)

        return array_valid_pages

    def hashing(self):
        """
        Generate dump files containing all modules loaded by a process


        @returns a list of dictionaries
        """
        
        if self.config.log_memory_pages:
            if not self.config.SECTION or self.config.SECTION=='all' or 'PE' in self.config.SECTION:
                logfile = open(self.config.log_memory_pages, "w")
            else:
                debug.warning('Warning: PE is not being dumped')


        valid_page_array = self.valid_pages()
        
        pe_memory_time=None

        start = time.time()
        pe = MarkedPE(data=self.data, virtual_layout=self.config.virtual_layout, valid_pages=valid_page_array, base_address=self.config.base_address, architecture=self.config.architecture)
        end = time.time()


        pe_memory_time = end - start

        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            pe.module_name = pe.DIRECTORY_ENTRY_EXPORT.name #TODO: use pe
        else:
            pe.module_name = None


        preprocess = 'Raw'
        if self.config.list_sections:
            yield {'section': self.get_pe_sections(pe)}
        else:
            pre_processing_time = None
            if self.config.derelocation in ['best', 'guide']:
                # Retrieving reloc for module for text section
                if self.config.reloc:

                    start = time.time()
                    guided_derelocation(pe, self.config.reloc)
                    end = time.time()
                    
                    pre_processing_time = end - start
                    
                    preprocess = 'Guide'
                # TODO Depurar que si y solo si guided hay reloc

            if (self.config.derelocation == 'best' and not self.config.reloc) or self.config.derelocation == 'linear' :
                
                start = time.time()
                linear_sweep_derelocation(pe)
                end = time.time()

                pre_processing_time = end - start

                preprocess = 'Linear'

            # Generate one dump Object for every section/header specified

            # Set the list of sections that match with -S expression
            for sec in self.process_section(self.config.section, pe):
                data = sec.get_data()
                for engine in self.hash_engines:
                    num_pages, valid_pages, digesting_time, digest = engine.calculate(data=data, valid_pages=valid_page_array[sec.VirtualAddress/PAGE_SIZE: sec.VirtualAddress/PAGE_SIZE + sec.real_size/PAGE_SIZE ])
                    yield { 'digest':digest, 
                        'digesting_time':digesting_time, 
                        'base_address': self.config.base_address, 
                        'mod_name': pe.module_name,
                        'section': sec.Name,
                        'virtual_address': sec.VirtualAddress, 
                        'size': len(data), 
                        'algorithm': engine.get_algorithm(),
                        'num_pages': num_pages,
                        'num_valid_pages': valid_pages,
                        'pe_time': '{0:.20f}'.format(pe_memory_time), 
                        'derelocation_time': '{0:.20f}'.format(pre_processing_time) if pre_processing_time else None,
                        'valid_pages': valid_page_array[sec.VirtualAddress/PAGE_SIZE: sec.VirtualAddress/PAGE_SIZE + sec.real_size/PAGE_SIZE ], 
                        'preprocess': preprocess}
                    
                    if self.config.dump_dir:
                        dump_path = os.path.join(self.config.dump_dir, '{0}-{1}-{2:x}.dmp'.format(pe.module_name if pe.module_name else 'mod', re.sub(r'\x00', r'', re.sub(r'\/', r'.', sec.Name)), self.config.base_address))
                        self.backup_file(dump_path, data)
                    if self.config.log_memory_pages and sec.Name in ['PE', 'dump']:
                        if not self.config.dump_dir:
                            debug.warning('Warning: Modules are not being dumped to file')
                        logfile.write('{},{},{},{}:{}\n'.format(self.config.optparse_opts.location[7:], dump_path, hashlib.md5(pe.__data__[0:PAGE_SIZE]).hexdigest(), len(valid_pages), ', '.join([str(i) for i in range(0, len(valid_pages)) if valid_pages[i] ])))
                                
            del data
        if 'logfile' in locals():
            logfile.close()

    def prepare_working_dir(self):
        if self.config.dump_dir:
            temp_path = os.path.realpath(self.config.dump_dir)
            if not os.path.exists(temp_path):
                os.makedirs(temp_path)
            return temp_path
        else:
            return None

    def backup_file(self, path, data):
        with open(path, 'wb') as f:
            return f.write(data)

    def comparing_hash(self, digest, hash_):
        """Compare hash for every dump page"""
        for h in hash_:
            for (sub_digest, index, valid_page) in zip( digest['digest'].split(';'), range(0, digest['num_pages']), digest['valid_pages']):
                if valid_page:
                    start = time.time()
                    similarity = self.hash_engines[0].compare(sub_digest, h)
                    end = time.time()

                    digest['similarity'] = similarity
                    digest['compared_page'] = index
                    digest['comparison_time'] = end - start
                    digest['sub_digest'] = sub_digest
                    digest['compared_digest'] = h

                    yield digest

    @classmethod
    def list_algorithms(cls):
        return HashEngine.get_algorithms()

if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('--base-address', '-b', help='Base address where was loaded the module')
    parser.add_argument('--reloc', '-r', help='A file with the .reloc section of the module')
    parser.add_argument('--virtual-layout', '-v', help='Module with virtual layout structure', action='store_true')
    parser.add_argument('--section', '-s', default='PE', help='PE section to hash (e.g. -s PE,.data,header,.rsrc)')
    parser.add_argument('--algorithms', '-A', choices=HashEngine.get_algorithms(), help='Hash algorithms (e.g. -a {})'.format(' -a '.join(HashEngine.get_algorithms())), action='append', default=[HashEngine.default_algorithms]) 
    parser.add_argument('--architecture', '-a', choices=['32', '64'], help='Code architecture') 
    parser.add_argument('--compare-hash', '-c', help='Compare to given hash', action='append')
    parser.add_argument('--compare-file', '-C', help='Compare to hashes\' file', action='append')
    parser.add_argument('--time', '-t', help='Print computation time', action='store_true')
    parser.add_argument('--dump-dir', '-D', help='Directory in which to dump files')
    parser.add_argument('--list-sections', help='Show PE sections', action='store_true')
    parser.add_argument('--json', help='Print JSON output', action='store_true')
    parser.add_argument('--output', '-o', help='ToDo', action='store_true')
    parser.add_argument('--derelocation', '-d', default='best', choices=['best', 'guide', 'linear', 'raw'], help='De-relocate modules pre-processing method.')
    parser.add_argument('--log-memory-pages', help='Log pages which are in memory to FILE')
    parser.add_argument('file', help='File that contains the module')

    args = parser.parse_args()

    if not os.path.isfile(args.file):
        print('Error: File {} is invalid.'.format(args.file))
        exit(-1)
    file = open(args.file, 'r')


    if args.reloc:
        if not os.path.isfile(args.reloc): 
            print('Error: Reloc file {} is invalid.'.format(args.reloc))
            exit(-1)
        reloc = open(args.reloc, 'r')
        args.reloc = reloc.read()


    tool = SUM(file.read(), args)
    if args.json:
        if args.list_sections:
            for output in tool.calculate():
                print(output)
        else:
            for output in tool.calculate():
                output['base_address'] = hex(output.get('base_address')) if type(output.get('base_address')) == int else output.get('base_address')
                output['virtual_address'] = hex(output.get('virtual_address')) if type(output.get('virtual_address')) == int else output.get('virtual_address')

                print(output)
    else:
        try:
            if args.list_sections:
                print( 'List of sections in the module: {}'.format(', '.join(tool.calculate().next().get('section'))))
            elif args.compare_hash or args.compare_file:
                print( 'Name\t\tSection\tVirtual Address\tSize\tPre-processing\tAlgorithm\tSimilarity\tSub Digest\t\t\t\t\t\tCompared Digest')
                print( '----\t\t-------\t---------------\t----\t--------------\t---------\t----------\t----------\t\t\t\t\t\t----------------')
                for output in tool.calculate():
                    print('{}\t{}\t{}\t{}\t{}\t\t{}\t\t{}\t\t{}...\t{}...'.format(output.get('mod_name'), output.get('section'), hex(output.get('base_address') + output.get('virtual_address')) if output.get('base_address') else hex(0), hex(output.get('size')), output.get('preprocess'),output.get('algorithm'), output.get('similarity'), output.get('sub_digest')[:50], output.get('compared_digest')[:50] ))
            
            else:
                print( 'Name\t\tSection\tVirtual Address\tSize\tPre-processing\tAlgorithm\tDigest\t')
                print( '----\t\t-------\t---------------\t----\t--------------\t---------\t------\t')
                for output in tool.calculate():
                    print('{}\t{}\t{}\t{}\t{}\t\t{}\t\t{}...{}'.format(output.get('mod_name'), output.get('section'), hex(output.get('base_address') + output.get('virtual_address')) if output.get('base_address') else hex(0), hex(output.get('size')), output.get('preprocess'),output.get('algorithm'), output.get('digest')[:20], output.get('digest')[-20:] ))
        except Exception as e:
            traceback.print_exc()
