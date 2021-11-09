import string
import time
import pdb
# import ssdeep
# import fuzzyhashlib
import re
import subprocess

PAGE_SIZE = 4096

temporal_windows_filename = r'windows_dependencies\SDAs\temporal_windows_file.dmp'
# temporal_windows_filename = r'temporal_windows_file.dmp'

def valid_page(page):
    for byte in page:
        if ord(byte) != 0:
            return True
    return False

def write_page_contents_to_temporal_windows_file(data):
    temporal_windows_file = open(temporal_windows_filename, 'wb')
    temporal_windows_file.write(data)
    temporal_windows_file.close()


class SSDeep:
        
    def get_algorithm(self):
        return 'SSDeep'

    def calculate(self, data):
        write_page_contents_to_temporal_windows_file(data)
        ssdeep_command = [r'windows_dependencies\SDAs\ssdeep\ssdeep.exe', temporal_windows_filename]
        process = subprocess.Popen(ssdeep_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = process.communicate()
        return_code = process.returncode
        if return_code == 0:
            if output == '':
                return 'SSDEEP_DIGEST_COULD_NOT_BE_CALCULATED_DESPITE_SUCCESS'
            else:
                return unicode(output.split(b'\n')[1].split(b',')[0]) # Unicode in order to match the Linux output
        else:
            # print('Error: There was an error with the calculation of an ssdeep digest. {}'.format(error))
            return 'ERROR_SSDEEP_DIGEST_COULD_NOT_BE_CALCULATED'

    def compare(self, hash1, hash2):
        return '-' # Not supported in Windows at the moment


class SDHash:
    
    def get_algorithm(self):
        return 'SDHash'

    def calculate(self, data):
        write_page_contents_to_temporal_windows_file(data)
        sdhash_command = [r'windows_dependencies\SDAs\sdhash\sdhash.exe', temporal_windows_filename]
        process = subprocess.Popen(sdhash_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = process.communicate()
        return_code = process.returncode
        if return_code == 0:
            if output == '':
                return 'SDHASH_DIGEST_COULD_NOT_BE_CALCULATED_DESPITE_SUCCESS'
            else:
                return re.sub(r'^sdbf:03:\d+:.+:4096:sha1:', r'sdbf:03:0::4096:sha1:', output.rstrip()) # To make the hash be the same as when SUM is run on Linux
        else:
            # print('Error: There was an error with the calculation of an sdhash digest. {}'.format(error))
            return 'ERROR_SDHASH_DIGEST_COULD_NOT_BE_CALCULATED'

    def compare(self, hash1, hash2):
        return '-' # Not supported in Windows at the moment
         
class TLSH:
        
    def get_algorithm(self):
        return 'TLSH'

    def calculate(self, data):
        write_page_contents_to_temporal_windows_file(data)
        python3_file = r'windows_dependencies\SDAs\tlsh\tlsh_algorithm.py'
        python3_command = ['py', '-3', python3_file]
        process = subprocess.Popen(' '.join(python3_command), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = process.communicate()
        return_code = process.returncode
        if return_code == 0:
            if output == '':
                return 'TLSH_DIGEST_COULD_NOT_BE_CALCULATED_DESPITE_SUCCESS'
            else:
                return output.rstrip()
        else:
            # print('Error: There was an error with the calculation of a tlsh digest. {}'.format(error))
            return 'ERROR_TLSH_DIGEST_COULD_NOT_BE_CALCULATED'

    def compare(self, hash1, hash2):
        return '-' # Not supported in Windows at the moment


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


        hash = [] 

        hashing_time = []

        num_pages = 0
        num_valid_pages = 0
        
        if valid_pages is None:
            valid_pages = [ valid_page(data[page_index:page_index + PAGE_SIZE]) for page_index in range(0, len(data), PAGE_SIZE)]
        
        for page_index, valid in zip(range(0, len(data), PAGE_SIZE), valid_pages):
            num_pages += 1
            if valid:
                start = time.time()
                hash.append(self.engine.calculate(data[page_index:page_index + PAGE_SIZE]))
                end = time.time()
                num_valid_pages += 1

                hashing_time.append('{0:.20f}'.format(end - start))
            else:
                hash.append('*')
                hashing_time.append('*')

        return num_pages, num_valid_pages, hashing_time, hash

    def compare(self, hash1, hash2):
        return self.engine.compare(hash1, hash2)
