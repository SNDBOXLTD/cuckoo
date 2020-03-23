import sys
import os
import hashlib


class MemdumpDuplicatesRemover(object):
    """This utility removes memdump duplicate files by hashes.
    """

    def __init__(self, paths):
        self.paths = paths

    def _chunk_reader(self, fobj, chunk_size=1024):
        """Generator that reads a file in chunks of bytes"""
        while True:
            chunk = fobj.read(chunk_size)
            if not chunk:
                return
            yield chunk

    def _get_hash(self, filename, first_chunk_only=False, hash=hashlib.sha1):
        hashobj = hash()
        file_object = open(filename, 'rb')

        if first_chunk_only:
            hashobj.update(file_object.read(1024))
        else:
            for chunk in self._chunk_reader(file_object):
                hashobj.update(chunk)
        hashed = hashobj.digest()

        file_object.close()
        return hashed

    def check_for_duplicates(self, hash=hashlib.sha1):
        hashes_by_size = {}
        hashes_on_1k = {}
        hashes_full = {}

        for full_path in self.paths:
            try:
                # if the target is a symlink (soft one), this will
                # dereference it - change the value to the actual target file
                full_path = os.path.realpath(full_path)
                file_size = os.path.getsize(full_path)
            except (OSError,):
                # not accessible (permissions, etc) - pass on
                continue

            hashes_by_size.setdefault(file_size, []).append(full_path)

        # For all files with the same file size, get their hash on the 1st 1024 bytes
        for __, files in hashes_by_size.items():
            if len(files) < 2:
                continue    # this file size is unique, no need to spend cpy cycles on it

            for filename in files:
                try:
                    small_hash = self._get_hash(filename, first_chunk_only=True)
                except (OSError,):
                    # the file access might've changed till the exec point got here
                    continue

                duplicate = hashes_on_1k.get(small_hash)
                if duplicate:
                    hashes_on_1k[small_hash].append(filename)
                else:
                    hashes_on_1k[small_hash] = []          # create the list for this 1k hash
                    hashes_on_1k[small_hash].append(filename)

        # For all files with the hash on the 1st 1024 bytes, get their hash on the full file - collisions will be duplicates
        for __, files in hashes_on_1k.items():
            if len(files) < 2:
                continue    # this hash of fist 1k file bytes is unique, no need to spend cpy cycles on it

            for filename in files:
                try:
                    full_hash = self._get_hash(filename, first_chunk_only=False)
                except (OSError,):
                    # the file access might've changed till the exec point got here
                    continue

                duplicate = hashes_full.get(full_hash)
                if duplicate:
                    print("Duplicate found: %s and %s" % (filename, duplicate))
                    os.remove(filename)
                else:
                    hashes_full[full_hash] = filename


def main():
    print("asd")
    if sys.argv[1:]:
        MemdumpDuplicatesRemover(sys.argv[1:]).check_for_duplicates()
    else:
        print("Please pass the paths to check as parameters to the script")


if "__main__" == __name__:
    main()
