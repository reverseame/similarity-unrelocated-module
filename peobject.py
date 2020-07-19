import json

from print_object import PrintObject

class PEObject(PrintObject):
    def __init__(self, task, data, hash_engine, create_time, section, file_version='', product_version='', time=None):
        PrintObject.__init__(self, data, hash_engine)
        self.process = self.get_filename(task)
        self.pid = task.UniqueProcessId
        self.ppid = task.InheritedFromUniqueProcessId
        self.create_time = create_time
        self.section = section
        self.file_version = file_version
        self.product_version = product_version
        self.print_time = time
    
    def get_generator(self):
        if self.print_time:
            return [
                str(self.process),
                int(self.pid),
                int(self.ppid),
                str(self.create_time),
                str(self.section or 'pe'),
                str(self.file_version),
                str(self.product_version),
                str(self.get_algorithm()),
                str(self.get_hash()),
                str(self.get_time()),
                str(self.get_size())
            ]

        else:
            return [
                        str(self.process),
                        int(self.pid),
                        int(self.ppid),
                        str(self.create_time),
                        str(self.section or 'pe'),
                        str(self.file_version),
                        str(self.product_version),
                        str(self.get_algorithm()),
                        str(self.get_hash())
                    ]

    def get_unified_output(self):
        if self.print_time:
            return [
                ('Process', '25'),
                ('Pid', '4'),
                ('PPid', '4'),
                ('Create Time', '28'),
                ('Section', '15'),
                ('File Version', '14'),
                ('Product Version', '10'),
                ('Algorithm', '6'),
                ('Generated Hash', '100'),
                ('Computation Time', '20'),
                ('Size', '30')
            ]
        else:
            return [
                        ('Process', '25'),
                        ('Pid', '4'),
                        ('PPid', '4'),
                        ('Create Time', '28'),
                        ('Section', '15'),
                        ('File Version', '14'),
                        ('Product Version', '10'),
                        ('Algorithm', '6'),
                        ('Generated Hash', '100')
                    ]

    def _json(self):
        return json.dumps(self._dict())

    def _dict(self):
        ret = {}

        ret['Process'] = str(self.process)
        ret['Pid'] = int(self.pid)
        ret['PPid'] = int(self.ppid)
        ret['Create Time'] = str(self.create_time)
        ret['Section'] = str(self.section or 'pe')
        ret['File Version'] = str(self.file_version)
        ret['Product Version'] = str(self.product_version)
        ret['Algorithm'] = str(self.get_algorithm())
        ret['Generated Hash'] = str(self.get_hash())
        if self.print_time:
            ret['Computation Time'] = str(self.get_time())
            ret['Size'] = str(self.get_size())

        return ret
