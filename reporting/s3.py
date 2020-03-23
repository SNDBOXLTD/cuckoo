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
from sndbox.memdumpDuplicatesRemover import MemdumpDuplicatesRemover

log = logging.getLogger(__name__)
s3 = boto3.client("s3")

MEMORY_DUMP_EXT = ".dmp"


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
