import string
import time

import ssdeep
import fuzzyhashlib
import re
import tlsh
import dcfldd

TLSH_MAX_SIMILARITY = 150
PAGE_SIZE = 4096


def valid_page(page):
    for byte in page:
        if ord(byte) != 0:
            return True
    return False

class HashEngine(object):
    def __init__(self, algorithm, strings=False):
        super(HashEngine, self).__init__()
        self.engine = self.resolve_engine(algorithm.lower())
        self.strings = strings

    def resolve_engine(self, algorithm):
        if algorithm == 'ssdeep':
            return SSDeep()
        elif algorithm == 'sdhash':
            return SDHash()
        elif algorithm == 'tlsh':
            return TLSH()
        elif algorithm == 'dcfldd':
            return Dcfldd()

        raise InvalidAlgorithm('Invalid fuzzy hash algorithm')

    def get_algorithm(self):
        return self.engine.get_algorithm()

    def calculate(self, file=None, data=None):
        if file:
            with open(file) as f:
                data = f.read()

        if self.strings:
            """Get all ASCII strings from binary data"""
            data = '\n'.join(get_strings(data))

        hash = ''

        hashing_time = ''

        num_pages = 0
        num_valid_pages = 0

        for page_index in range(0, len(data), PAGE_SIZE):
            num_pages += 1
            if valid_page(data[page_index:page_index + PAGE_SIZE]):
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

class SSDeep(object):
    def __init__(self):
        super(SSDeep, self).__init__()
    
    def get_algorithm(self):
        return 'SSDeep'

    def calculate(self, data):
        result = ssdeep.hash(data)
        return '-' if result == '3::' else result

    def compare(self, hash1, hash2):
        if hash1 == '-' or hash2 == '-':
            return '-'
        try:
            distance = ssdeep.compare(hash1, hash2)
            return distance # if distance > 0 else '-'
        except ssdeep.InternalError, reason:
            return '-'

class SDHash(object):
    def __init__(self):
        super(SDHash, self).__init__()

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

        # Bad hash comparation
        distance = fuzzyhashlib.sdhash(hash=hash1) - fuzzyhashlib.sdhash(hash=hash2)
        return distance #if distance > 0 else '-'


class TLSH(object):
    def __init__(self):
        super(TLSH, self).__init__()
    
    def get_algorithm(self):
        return 'TLSH'

    def calculate(self, data):
        if len(data) < 50:
            return '-'

        fingerprint = tlsh.hash(data)

        return fingerprint if fingerprint else '-'

    def compare(self, hash1, hash2):
        if hash1 == '-' or hash2 == '-':
            return '-'
        distance = tlsh.diffxlen(hash1, hash2)
        #if distance > TLSH_MAX_SIMILARITY:
        #    return '-'
        return distance


class Dcfldd(object):
    def __init__(self):
        super(Dcfldd, self).__init__()
    
    def get_algorithm(self):
        return 'dcfldd'

    def calculate(self, data):
        if len(data) == 0:
            return '-'
        try:
            return dcfldd.hash(data, 100, dcfldd.MD5)
        except dcfldd.InvalidDcflddHashFunc, reason:
            return '-'

    def compare(self, hash1, hash2):
        if hash1 == '-' or hash2 == '-':
            return '-'
        try:
            distance = dcfldd.compare(str(hash1), str(hash2))
            return distance #if distance > 0 else '-'
        except dcfldd.InvalidDcflddComparison, reason:
            return '-'

class InvalidAlgorithm(Exception):
    pass

def get_strings(data, min=4):
    """
    Get all strings of a given data

    @param data: binary data
    @param min: minimum string length

    @returns a generator with all strings
    """
    stream = ''

    for char in data:
        if char in string.printable:
            stream += char
            continue
        if len(stream) >= min:
            yield stream
        stream = ''
    # Catch result at EOF
    if len(stream) >= min:
        yield stream


