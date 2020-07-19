import json

from print_object import PrintObject

from volatility.renderers.basic import Address

class DriverObject(PrintObject):
    def __init__(self, data, mod_base, mod_end, name, hash_engine, section, file_version, product_version, time):
        PrintObject.__init__(self, data, hash_engine)
        self.mod_base = mod_base
        self.mod_end = mod_end
        self.name = name
        self.section = section
        self.file_version = file_version
        self.product_version = product_version
        self.print_time = time

    def get_generator(self):
        if self.print_time:
            return [
                    Address(self.mod_base),
                    Address(self.mod_end),
                    str(self.name),
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
                Address(self.mod_base),
                Address(self.mod_end),
                str(self.name),
                str(self.section or 'pe'),
                str(self.file_version),
                str(self.product_version),
                str(self.get_algorithm()),
                str(self.get_hash())
            ]

    def get_unified_output(self):
        if self.print_time:
            return [
                ('Module Base', '[addr]'),
                ('Module End', '[addr]'),
                ('Module Path', '46'),
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
                ('Module Base', '[addr]'),
                ('Module End', '[addr]'),
                ('Module Path', '46'),
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

        ret['Module Base'] = hex(self.mod_base)
        ret['Module End'] = hex(self.mod_end)
        ret['Module Path'] = str(self.name)
        ret['Section'] = str(self.section or 'pe')
        ret['File Version'] = str(self.file_version)
        ret['Product Version'] = str(self.product_version)
        ret['Algorithm'] = str(self.get_algorithm())
        ret['Generated Hash'] = str(self.get_hash())
        if self.print_time:
            ret['Computation Time'] = str(self.get_time())
            ret['Size'] = str(self.get_size())

        return ret
