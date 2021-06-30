import string
import time

import ssdeep
import fuzzyhashlib
import re

PAGE_SIZE = 4096


def valid_page(page):
    for byte in page:
        if ord(byte) != 0:
            return True
    return False


class SSDeep:
        
    def get_algorithm(self):
        return 'SSDeep'

    def calculate(self, data):
        result = ssdeep.hash(data)
        return '-' if result == '3::' else result

    def compare(self, hash1, hash2):
        if hash1 == '-' or hash2 == '-':
            return '-'
        try:
            return ssdeep.compare(hash1, hash2)
        except ssdeep.InternalError, reason:
            return '-'

class SDHash:
    
    def get_algorithm(self):
        return 'SDHash'

    def calculate(self, data):
        try:
            return fuzzyhashlib.sdhash(data).hexdigest().strip()
        except ValueError, reason:
            return '-'

    def compare(self, hash1, hash2):
        if hash1 == '-' or hash2 == '-':
            return '-'
        return fuzzyhashlib.sdhash(hash=hash1) - fuzzyhashlib.sdhash(hash=hash2)
         

class TLSH:
        
    def get_algorithm(self):
        return 'TLSH'

    def calculate(self, data):
        try:
            return fuzzyhashlib.tlsh(data).hexdigest().strip()
        except ValueError, reason:
            return '-'
        

    def compare(self, hash1, hash2):
        if hash1 == '-' or hash2 == '-':
            return '-'

        return fuzzyhashlib.tlsh(hash=hash1) - fuzzyhashlib.tlsh(hash=hash2)

class HashEngine:
    algorithms = {'ssdeep': SSDeep, 'sdhash': SDHash, 'tlsh': TLSH}
    default_algorithms = 'tlsh'

    def __init__(self, algorithm):
        self.engine = self.resolve_engine(algorithm.lower())

    def resolve_engine(self, algorithm):

        engine = self.algorithms.get(algorithm)()
        if engine:
            return engine
        raise RuntimeError('Invalid Similarity Digest Algorithm: {}'.format(algorithm))

    def get_algorithm(self):
        return self.engine.get_algorithm()

    @classmethod
    def get_algorithms(cls):
        return HashEngine.algorithms.keys()

    def calculate(self, file=None, data=None, valid_pages=None):
        if file:
            with open(file) as f:
                data = f.read()


        hash = ''

        hashing_time = ''

        num_pages = 0
        num_valid_pages = 0
        
        if valid_pages is None:
            valid_pages = [ valid_page(data[page_index:page_index + PAGE_SIZE]) for page_index in range(0, len(data), PAGE_SIZE)]
        
        for page_index, valid in zip(range(0, len(data), PAGE_SIZE), valid_pages):
            num_pages += 1
            if valid:
                start = time.time()
                hash += self.engine.calculate(data[page_index:page_index + PAGE_SIZE]) + ';'
                end = time.time()
                num_valid_pages += 1

                hashing_time += '{0:.20f};'.format(end - start)
            else:
                hash += '*;'
                hashing_time += '*;'

        return num_pages, num_valid_pages, hashing_time[:-1], hash[:-1]

    def compare(self, hash1, hash2):
        return self.engine.compare(hash1, hash2)




