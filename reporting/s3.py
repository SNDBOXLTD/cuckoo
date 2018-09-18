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
import logging

log = logging.getLogger(__name__)
s3 = boto3.client("s3")


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

    def run(self, results):
        """
        Exports the PCAP and the gzipped version of the report file to s3
        along with its original filename
        :param results: the full report
        """
        sample = json.loads(results["info"]["custom"])["sample"]

        pcap_path = os.path.join(self.analysis_path, "dump.pcap")
        gzipped_report_path = self.gzip_report(sample["s3_key"])

        self.upload_pcap(pcap_path, sample["s3_path"], sample["s3_key"])

        if gzipped_report_path:
            s3_report_path = self.upload_report(gzipped_report_path, sample["s3_key"])
            results["s3"] = {
                "s3_bucket": self.options.bucket,
                "s3_key": s3_report_path
            }

