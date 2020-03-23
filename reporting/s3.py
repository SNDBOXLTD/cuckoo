"""
Module Name:    s3.py
Purpose:        Saves the PCAP and the report to S3
Author:         Itay Huri
Date:           18/09/2017
"""

from cuckoo.common.abstracts import Report
import boto3
import os
import json
import gzip
from zipfile import ZipFile, ZIP_DEFLATED
import logging
import hashlib

log = logging.getLogger(__name__)
s3 = boto3.client("s3")

MEMORY_DUMP_EXT = ".dmp"


class MemdumpDuplicatesRemover(object):
    """This utility removes memdump duplicate files by hashes.
    """

    def __init__(self, paths):
        self.paths = paths
        log.info("Duplicate remover init with %d dumps", len(self.paths))

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
                    log.info("Duplicate found: %s and %s" % (filename, duplicate))
                    os.remove(filename)
                else:
                    hashes_full[full_hash] = filename


class S3(Report):
    """
    Responsible to export the results to S3
    """

    order = 2

    def gzip_report(self, name):
        """
        GZIPs the report, saves it into a temp location
        :param name: desired GZIP file name
        :return: the location of the GZIP file
        """
        report_path = os.path.join(self.reports_path, "report.json")
        if os.path.isfile(report_path):
            gzipped_report_path = os.path.join(self.reports_path, name + ".gz")
            with open(report_path, "r") as report:
                with gzip.open(gzipped_report_path, "wb") as gz:
                    gz.write(report.read())
            return gzipped_report_path
        else:
            log.critical("Report file %s is missing" % report_path)

    def upload_report(self, report_path, name):
        """
        uploads the gzipped report to S3, into a temp directory,
        this is the report expected to be read by the ML processor.
        this is NOT the final report.
        :param report_path: local location of the gzipped report
        :param name: name of the gzip file
        :return: s3 path the file was saved in
        """
        if os.path.isfile(report_path):
            s3_report_path = os.path.join("dynamic_tmp/", name + ".json.gz")
            s3.upload_file(report_path, self.options.bucket, s3_report_path)
            return s3_report_path
        else:
            log.critical("Report GZIP File %s is missing" % report_path)

    def upload_pcap(self, pcap_path, s3_path, name):
        """
        uploads PCAP file to s3
        :param pcap_path: the location of the PCAP file locally
        :param s3_path: the S3 path the PCAP needs to
                be saved in, changes frequently due to Ran's needs
        :param name: the PCAP filename
        :return: s3 path the file was saved in
        """
        if os.path.isfile(pcap_path):
            save_in = s3_path + "/pcaps/" + name + ".pcap"
            s3.upload_file(pcap_path, self.options.bucket, save_in)
            return save_in
        else:
            log.critical("PCAP File %s is missing" % pcap_path)

    def upload_dropped(self, dropped_files, s3_path, s3_key):
        for dropped in dropped_files:
            path = dropped["path"]
            if path.endswith(MEMORY_DUMP_EXT):
                continue
            if not os.path.isfile(path):
                log.warning("dropped file at {} was not found".format(path))
                continue

            save_in = "{base}/dropped_files/{key}/{sha256}".format(base=s3_path, key=s3_key, sha256=dropped["sha256"])
            s3.upload_file(path, self.options.bucket, save_in, ExtraArgs={
                           "Metadata": {"original_name": dropped["name"]}})

    def zip_memdumps(self, memdump_files, name):
        """
        ZIP all memdump files, saves it into a temp location
        :param name: desired GZIP file name
        :return: the location of the GZIP file
        """
        zipped_memdump_path = os.path.join(self.reports_path, "memdump.zip")
        with ZipFile(zipped_memdump_path, 'w', ZIP_DEFLATED) as zipObj:
            for memdump in memdump_files:
                path = memdump["path"]
                if os.path.isfile(path):
                    memdump_filename = os.path.basename(path)
                    zipObj.write(path, memdump_filename)
        return zipped_memdump_path

    def upload_memdump_zip(self, memdump_path,  s3_path, name):
        if os.path.isfile(memdump_path):
            save_in = s3_path + "/memdumps/" + name + ".zip"
            s3.upload_file(memdump_path, self.options.bucket, save_in)
            return save_in
        else:
            log.critical("MEMDUMP File %s is missing" % memdump_path)

    def run(self, results):
        """
        Exports the PCAP and the gzipped version of the report file to s3
        along with its original filename
        :param results: the full report
        """
        sample = json.loads(results["info"]["custom"])["sample"]

        pcap_path = os.path.join(self.analysis_path, "dump.pcap")

        self.upload_pcap(pcap_path, sample["s3_path"], sample["s3_key"])

        if results.get("dropped"):

            dropped_without_memdump = [dropped for dropped in results["dropped"]
                                       if not dropped["path"].endswith(MEMORY_DUMP_EXT)]
            dropped_memdump = [dropped for dropped in results["dropped"] if dropped["path"].endswith(MEMORY_DUMP_EXT)]

            # remove duplicate memdumps
            dropped_memdump_paths = [dropped["path"] for dropped in dropped_memdump]
            MemdumpDuplicatesRemover(dropped_memdump_paths).check_for_duplicates()

            self.upload_dropped(dropped_without_memdump, sample["s3_path"], sample["s3_key"])

            zipped_memdump_path = self.zip_memdumps(dropped_memdump, sample["s3_key"])
            if zipped_memdump_path:
                self.upload_memdump_zip(zipped_memdump_path, sample["s3_path"], sample["s3_key"])

        gzipped_report_path = self.gzip_report(sample["s3_key"])
        if gzipped_report_path:
            s3_report_path = self.upload_report(gzipped_report_path, sample["s3_key"])
            results["s3"] = {
                "s3_bucket": self.options.bucket,
                "s3_key": s3_report_path
            }
