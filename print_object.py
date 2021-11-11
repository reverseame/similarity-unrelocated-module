import time


class PrintObject(object):
    def __init__(self, data, hash_engine):
        super(PrintObject, self).__init__()
        self.data = data
        self.hash_engine = hash_engine
        self._hash = None
        self._hashing_time = None
        self._comparing_time = None
        self._size = None
        self._num_page = None
        self._num_valid_pages = None

    def get_filename(self, task):
        for mod in task.get_load_modules():
            return mod.BaseDllName

    def get_hash(self):
        if not self._hash:
            self._num_page, self._num_valid_pages, self._hashing_time, self._hash = self.hash_engine.calculate(
                data=self.data)
            self._size = len(self.data)

        return self._hash

    def get_hashing_time(self):
        return self._hashing_time

    def get_comparing_time(self):
        return '{0:.20f}'.format(self._comparing_time)

    def get_size(self):
        return self._size

    def get_algorithm(self):
        return self.hash_engine.get_algorithm()

    def compare_hash(self, hash1, hash2):
        start = time.time()
        similarity = self.hash_engine.compare(hash1, hash2)
        end = time.time()

        self._comparing_time = end - start

        return similarity
