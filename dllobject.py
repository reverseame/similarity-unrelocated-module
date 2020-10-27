import json

from print_object import PrintObject

from volatility.renderers.basic import Address

class DLLObject(PrintObject):
    def __init__(self, task, data, hash_engine, mod_base, mod_end, mod_name, section, create_time,
                 file_version, product_version, path, time, offset, size, pe_memory_time, pre_processing_time, physical_addresses):
        PrintObject.__init__(self, data, hash_engine)
        self.process = self.get_filename(task)
        self.pid = task.UniqueProcessId
        self.ppid = task.InheritedFromUniqueProcessId
        self.mod_base = mod_base
        self.mod_end = mod_end
        self.mod_name = mod_name
        self.Wow64 = task.IsWow64
        self.section = section
        self.sec_off = offset
        self.sec_size = size
        self.create_time = create_time
        self.file_version = file_version
        self.product_version = product_version
        self.path = path
        self.print_time = time
        self.pe_memory_time = pe_memory_time
        self.pre_processing_time = pre_processing_time
        self.physical_addresses=physical_addresses


    def get_generator(self):
        if self.print_time:
            return [
                str(self.process),
                int(self.pid),
                int(self.ppid),
                str(self.create_time),
                Address(self.mod_base),
                Address(self.mod_end),
                str(self.mod_name),
                int(self.Wow64),
                str(self.file_version),
                str(self.product_version),
                str(self.section),
                Address(self.sec_off),
                Address(self.sec_size),
                str(self.get_algorithm()),
                str(self.get_hash()),
                str(self.path),
                str(self._num_page),
                str(self._num_valid_pages),
                str(self.get_hashing_time()),
                str(self.get_size()),
                str(self.pe_memory_time),
                str(self.pre_processing_time),
                str(';'.join([page if page else '*' for page in self.physical_addresses]))
            ]
        else:
            return [
                        str(self.process),
                        int(self.pid),
                        int(self.ppid),
                        str(self.create_time),
                        Address(self.mod_base),
                        Address(self.mod_end),
                        str(self.mod_name),
                        int(self.Wow64),
                        str(self.file_version),
                        str(self.product_version),
                        str(self.section),
                        Address(self.sec_off),
                        Address(self.sec_size),
                        str(self.get_algorithm()),
                        str(self.get_hash()),
                        str(self.path),
                        str(self._num_page),
                        str(self._num_valid_pages),
                        str(';'.join([str(page) if page else '*' for page in self.physical_addresses]))
                    ]

    def get_unified_output(self):
        if self.print_time:
            return [
                ('Process', '25'),
                ('Pid', '4'),
                ('PPid', '4'),
                ('Create Time', '28'),
                ('Module Base', '[addr]'),
                ('Module End', '[addr]'),
                ('Module Name', '33'),
                ('Wow64', '6'),
                ('File Version', '14'),
                ('Product Version', '10'),
                ('Section', '18'),
                ('Section Offset', '[addr]'),
                ('Section Size', '[addr]'),
                ('Algorithm', '6'),
                ('Generated Hash', '100'),
                ('Path', '46'),
                ('Num Page', '4'),
                ('Num Valid Page', '4'),
                ('Computation Time', '30'),
                ('Size', '30'),
                ('PE Memory Computation Time', '30'),
                ('Pre-processing Time', '30'),
                ('Physical pages', '30'),

            ]
        else:
            return [
                        ('Process', '25'),
                        ('Pid', '4'),
                        ('PPid', '4'),
                        ('Create Time', '28'),
                        ('Module Base', '[addr]'),
                        ('Module End', '[addr]'),
                        ('Module Name', '33'),
                        ('Wow64', '6'),
                        ('File Version', '14'),
                        ('Product Version', '10'),
                        ('Section', '18'),
                        ('Section Offset', '[addr]'),
                        ('Section Size', '[addr]'),
                        ('Algorithm', '6'),
                        ('Generated Hash', '100'),
                        ('Path', '46'),
                        ('Num Page', '4'),
                        ('Num Valid Page', '4'),
                        ('Physical pages', '30'),
                    ]

    def _json(self):
        return json.dumps(self._dict())

    def _dict(self):
        ret = {}

        ret['Process'] = str(self.process)
        ret['Pid'] = int(self.pid)
        ret['PPid'] = int(self.ppid)
        ret['Create Time'] = int(self.create_time)
        ret['Module Base'] = hex(self.mod_base)
        ret['Module End'] = hex(self.mod_end)
        ret['Module Name'] = str(self.mod_name)
        ret['Wow64'] = int(self.Wow64)
        ret['File Version'] = str(self.file_version)
        ret['Product Version'] = str(self.product_version)
        ret['Section'] = str(self.section)
        ret['Section Offset'] = hex(self.sec_off)
        ret['Section Size'] = int(self.sec_size)
        ret['Algorithm'] = str(self.get_algorithm())
        ret['Generated Hash'] = str(self.get_hash())
        ret['Path'] = str(self.path)
        ret['Num Page'] = str(self._num_page)
        ret['Num Valid Pages'] = str(self._num_valid_pages)
        ret['Physical pages'] = str(';'.join([str(page) if page else '*' for page in self.physical_addresses]))

        if self.print_time:
            ret['Computation Time'] = str(self.get_hashing_time())
            ret['Size'] = str(self.get_size())
            ret['PEMemory time'] = str(self.pe_memory_time)
            ret['Pre-processing Time'] = str(self.pre_processing_time)

        return ret
