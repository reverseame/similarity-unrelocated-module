import json

class CompareObject(object):
    def __init__(self, object_, main_hash, time):
        super(CompareObject, self).__init__()
        self.object = object_
        self.main_hash = main_hash
        self.print_time = time
    
    def get_generator(self):
        if self.print_time:
            return self.object.get_generator() + [
                        str(self.main_hash),
                        str(self.object.compare_hash(self.main_hash, self.object.get_hash())),
                        str(self.object.get_time())
                    ]
        else:
            return self.object.get_generator() + [
                str(self.main_hash),
                str(self.object.compare_hash(self.main_hash, self.object.get_hash()))
            ]

    def get_unified_output(self):
        if self.print_time:
            return self.object.get_unified_output() + [
                        ('Hash', '100'),
                        ('Rate', '9'),
                        ('Computation Time', '30')
                    ]
        else:
            return self.object.get_unified_output() + [
                ('Hash', '100'),
                ('Rate', '9')
            ]

    def _json(self):
        return json.dumps(self._dict())

    def _dict(self):
        ret = self.object._dict()

        ret['Hash'] = str(self.main_hash)
        ret['Rate'] = str(self.object.compare_hash(self.main_hash, self.object.get_hash()))
        if self.print_time:
            ret['Computation Time'] = str(self.object.get_time())

        return ret
